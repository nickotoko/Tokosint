import json

from bbot.modules.base import BaseInterceptModule
from bbot.core.config.models import BaseModuleConfig, Field

# Статусы находки (IoC) по возрастанию: ложное < историческое < валидное.
FALSE, HISTORICAL, VALID = 0, 1, 2
STATUS_NAMES = {FALSE: "false", HISTORICAL: "historical", VALID: "valid"}
STATUS_BY_NAME = {v: k for k, v in STATUS_NAMES.items()}
# Собственная актуальность «подтверждено проверкой сейчас»: статус valid независимо от родителя.
VERIFIED = 3
OWN_NAMES = {None: "inherit", FALSE: "false", HISTORICAL: "historical", VALID: "current", VERIFIED: "verified"}

# Актуальность данных источника — `meta["freshness"]` каждого модуля, порождающего события:
#   current    — источник отражает состояние на сейчас (живой DNS, неистёкшие серты, текущий скан хоста)
#   historical — архив / passive DNS / индекс: данные могли устареть
#   inherit    — производное из родителя (разбор ответа, файла, URL), своей актуальности нет
FRESHNESS = {"current": VALID, "historical": HISTORICAL, "inherit": None}
# Фиктивные модули ядра: DNS-записи живого резолва и сиды цели — актуальны.
FRESHNESS_BY_DUMMY_TYPE = {"DNS": "current", "SEED": "current"}

# Вердикты проверок второго этапа (по убыванию силы): ложное, «устарело» (не выше historical),
# «подтверждено сейчас» (valid, даже если родитель исторический).
VERDICT_FALSE, VERDICT_HISTORICAL, VERDICT_VERIFIED = "false", "historical", "verified"
# Ложное как связь с целью, но кандидат для анализаторов связей: скрывается (internal), а не отбрасывается.
VERDICT_UNRELATED = "unrelated"

DNS_NAME_TYPES = ("DNS_NAME", "DNS_NAME_UNRESOLVED")
# Живой ответ HTTP (тег status-NNN на URL): ресурс сейчас отвечает — кроме «нет такого ресурса».
HTTP_GONE = (404, 410)
PROMOTE_POLICIES = ("in_scope", "none")

# Зарезервированные для примеров домены (RFC 2606); зоны test/local/invalid/localhost/example
# отсекаются отсутствием публичного суффикса.
RESERVED_DOMAINS = {"example.com", "example.net", "example.org"}
# Локальные части адресов-заглушек из форм и документации (user@…, email@…); проверяются только на чужих доменах.
PLACEHOLDER_LOCALS = {
    "user", "username", "usermail", "name", "email", "mail", "my", "you", "your", "test", "sender", "client",
    "login", "example", "somebody", "someone",
}  # fmt: skip
# Тег модуля-источника: принадлежность найденного профиля/аккаунта цели проверить не удалось → ложное.
OWNER_UNVERIFIED_TAG = "owner-unverified"
# Ресурс третьей стороны, которым пользуется цель (провайдер из её записей DNS): связь valid, но это не актив цели.
THIRD_PARTY_TAG = "third-party"


class validity(BaseInterceptModule):
    """
    Проставляет каждой находке статус: valid / historical / false.

    Этап 1 — правило рекурсии: статус = min(актуальность источника, статус родителя).
    У валидного родителя дети бывают валидными, историческими и ложными;
    у исторического — по умолчанию только историческими (или ложными). Ложные не попадают
    в скан (не рекурсируют и не сохраняются) — пишутся в `validity_false.jsonl` скана.

    Этап 2 — проверки (`self.checks`): синхронные функции `check(event) -> (вердикт, причина) | None`,
    применяются при разметке события, поэтому потомки всегда видят уже проверенного родителя.
      false       — находка ложная;
      historical  — статус не выше historical (например, имя не резолвится);
      verified    — подтверждено сейчас: valid, даже если путь обнаружения исторический
                    («по умолчанию» из правила рекурсии снимается только так).
    Проверки читают то, что уже есть на событии (DNS-записи от dnsresolve, cloud-теги), сами к цели не ходят.

    DNS-проверка (`dns_check`) для DNS_NAME — по результату dnsresolve:
      нет записей (NXDOMAIN/пусто)      → historical, тег dns-check-nxdomain
      ошибка резолва (SERVFAIL/таймаут) → без изменений, dns-check-error
      CNAME без адреса (висячий)        → historical, dns-check-dangling
      wildcard                          → без изменений (резолв по wildcard не доказательство), dns-check-wildcard
      резолвится                        → dns-check-ok; при `promote_resolved: in_scope` имя в скоупе по строке
                                          (поддомен цели) → verified

    Проверка связи (`relation_check`) — DNS-имя вне скоупа валидно только при доказанной связи:
      запись DNS валидного родителя (NS/MX/CNAME… — цель пользуется ресурсом), модуль с `meta["proves_relation"]`
      (related_domains — вердикт verified). Ссылка со страницы, соседство по IP, общий сертификат — не доказательство
      → вердикт unrelated: статус false, но событие не отбрасывается, а скрывается (internal) — в вывод не попадает,
      анализаторы связей (related_domains, сам резолвит кандидатов) его видят и могут продвинуть домен.
      Потомки скрытого имени — обычные ложные (отбрасываются), рекурсии от него нет.

    Тег `third-party`: имя вне скоупа из записи DNS цели (MX/NS/CNAME… на провайдера) и его потомки вне скоупа —
    связь valid («цель пользуется»), но это инфраструктура третьей стороны, а не актив цели.

    Проверка мусора (`junk_check`) — false (кроме имён из записей DNS): имя/адрес без публичного суффикса (`hand@3x.png`, `*.test`, `*.local`),
    зарезервированные домены (example.com), адреса-заглушки на чужих доменах (user@…, email@…), события с тегом
    `owner-unverified` от модуля-источника (профиль найден по совпадению имени, принадлежность не подтвердилась).

    Ложное отбрасывается (`drop_false`), unrelated — скрывается; оба пишутся в `validity_false.jsonl`.

    HTTP-проверка (`http_check`) для URL с тегом status-NNN (живой ответ http): 404/410 → historical
    (ресурса уже нет, путь мог прийти из архива); 5xx/400 — без вывода; иначе (2xx/3xx/401/403/405…) ресурс отвечает →
    verified, если хост в скоупе и `promote_resolved: in_scope`. HTTP_RESPONSE и находки из него наследуют статус URL.

    Теги на событии:
      validity-<status>    — статус наблюдения в рамках скана
      freshness-<level>    — собственная актуальность наблюдения относительно родителя в выводе
                             (current / historical / inherit / verified; omitted-родители свёрнуты);
                             по ним после скана статус сущности пересчитывается по всем путям (web/validity.py)

    Модуль-источник может переопределить актуальность конкретного события тегом
    `freshness-current` / `freshness-historical` (например, по дате last_seen записи).
    """

    watched_events = ["*"]
    produced_events = []
    meta = {
        "description": "Mark every finding as valid, historical or false based on source freshness, its parent and checks",
        "created_date": "2026-11-04",
        "author": "@nickotoko",
    }

    class Config(BaseModuleConfig):
        drop_false: bool = Field(
            True, description="Do not pass false findings to the scan (they are logged to validity_false.jsonl)"
        )
        dns_check: bool = Field(
            True, description="Check DNS names by their resolution: not resolving -> historical, resolving -> verified"
        )
        relation_check: bool = Field(
            True,
            description="Out-of-scope DNS names are false unless the relation is proven (DNS record, related_domains)",
        )
        junk_check: bool = Field(
            True,
            description="False for names/emails without a public suffix, reserved domains, placeholder emails "
            "and events tagged owner-unverified",
        )
        http_check: bool = Field(
            True, description="Check URLs by the live HTTP status: 404/410 -> historical, any other answer -> verified"
        )
        promote_resolved: str = Field(
            "in_scope",
            description="Which resolving names and answering URLs are verified as valid regardless of the discovery "
            "path: in_scope (target hosts by name) or none",
        )

    scope_distance_modifier = None
    # после dnsresolve (1) и cloudcheck (3): проверкам нужны DNS-записи и cloud-теги
    _priority = 4

    async def setup(self):
        self.drop_false = self.config.get("drop_false", True)
        self.promote_resolved = self.config.get("promote_resolved", "in_scope")
        if self.promote_resolved not in PROMOTE_POLICIES:
            return False, f"promote_resolved must be one of {PROMOTE_POLICIES}, got {self.promote_resolved!r}"
        self.checks = []
        if self.config.get("junk_check", True):
            self.checks.append(self.check_junk)
        if self.config.get("relation_check", True):
            self.checks.append(self.check_relation)
        if self.config.get("dns_check", True):
            self.checks.append(self.check_dns)
        if self.config.get("http_check", True):
            self.checks.append(self.check_http)
        # uuid события -> [статус, собственная актуальность, причина вердикта]
        # (у событий __slots__, поэтому состояние хранится в модуле)
        self._state = {}
        self._false_file = None
        self.false_count = 0
        return True

    # --- актуальность источника ---

    def source_freshness(self, event):
        """Собственная актуальность события: VALID / HISTORICAL / None (наследует родителя)."""
        # явное переопределение модулем (по дате записи и т.п.)
        for level in ("current", "historical"):
            if f"freshness-{level}" in event.tags:
                return FRESHNESS[level]
        module = event.module
        level = getattr(module, "meta", {}).get("freshness")
        if level is None:
            level = FRESHNESS_BY_DUMMY_TYPE.get(getattr(module, "_type", ""))
        if level is None:
            # модуль без объявленной актуальности — консервативно считаем архивом
            self.debug(f"Module {module} has no meta freshness, treating {event} as historical")
            level = "historical"
        return FRESHNESS[level]

    # --- проверки этапа 2 ---

    def check_dns(self, event):
        if event.type not in DNS_NAME_TYPES or "seed" in event.tags:
            return None
        tags = event.tags
        errored = any(t.endswith("-error") for t in tags)
        if "unresolved" in tags or event.type == "DNS_NAME_UNRESOLVED":
            if errored:
                event.add_tag("dns-check-error")
                return None
            event.add_tag("dns-check-nxdomain")
            return VERDICT_HISTORICAL, "does not resolve"
        if any("wildcard" in t for t in tags) or event.data.startswith("_wildcard."):
            event.add_tag("dns-check-wildcard")
            return None
        has_address = "a-record" in tags or "aaaa-record" in tags
        if "cname-record" in tags and not has_address and not errored:
            event.add_tag("dns-check-dangling")
            return VERDICT_HISTORICAL, "CNAME without address"
        event.add_tag("dns-check-ok")
        if self.promote_resolved == "in_scope" and self.scan.in_target(event.host):
            return VERDICT_VERIFIED, "in-scope name resolves"
        return None

    def check_junk(self, event):
        if "seed" in event.tags:
            return None
        if OWNER_UNVERIFIED_TAG in event.tags:
            return VERDICT_FALSE, "owner not verified"
        if event.type not in DNS_NAME_TYPES + ("EMAIL_ADDRESS",):
            return None
        if getattr(event.module, "_type", "") == "DNS":
            # имя из настоящей записи DNS (MX на mail.corp.local и т.п.) — запись существует, это не мусор, а находка
            return None
        host = str(event.host or "")
        if not host or self.helpers.is_ip(host):
            return None
        if host.startswith("_wildcard."):
            return None
        if not self.helpers.tldextract(host).suffix:
            return VERDICT_FALSE, f"no public suffix: {host}"
        domain = self.helpers.tldextract(host).top_domain_under_public_suffix
        if domain in RESERVED_DOMAINS:
            return VERDICT_FALSE, f"reserved domain: {domain}"
        if event.type == "EMAIL_ADDRESS" and not self.scan.in_target(host):
            local = str(event.data).split("@", 1)[0].lower()
            if local in PLACEHOLDER_LOCALS or local == domain.split(".", 1)[0]:
                return VERDICT_FALSE, f"placeholder email: {event.data}"
        return None

    def check_relation(self, event):
        if event.type not in DNS_NAME_TYPES or "seed" in event.tags:
            return None
        module = event.module
        if getattr(module, "meta", {}).get("proves_relation"):
            return VERDICT_VERIFIED, f"relation proven by {module}"
        if event.scope_distance <= 0:
            return None
        if getattr(module, "_type", "") == "DNS":
            # запись DNS валидного родителя: цель сейчас пользуется этим ресурсом
            return None
        return VERDICT_UNRELATED, f"out-of-scope name without proven relation ({module})"

    def check_http(self, event):
        if event.type != "URL":
            return None
        status = next((t[len("status-") :] for t in event.tags if t.startswith("status-")), None)
        if status is None or not status.isdigit():
            return None
        status = int(status)
        if status in HTTP_GONE:
            return VERDICT_HISTORICAL, f"HTTP {status}: resource is gone"
        if 500 <= status or status == 400:
            # ошибка сервера / кривой запрос — о существовании ресурса ничего не говорит
            return None
        if self.promote_resolved == "in_scope" and self.scan.in_target(event.host):
            return VERDICT_VERIFIED, f"HTTP {status}: target resource answers now"
        return None

    def run_checks(self, event):
        """Самый сильный вердикт среди проверок: false > unrelated > historical > verified."""
        found = {}
        for check in self.checks:
            result = check(event)
            if result is not None:
                verdict, reason = result
                found.setdefault(verdict, reason)
        for verdict in (VERDICT_FALSE, VERDICT_UNRELATED, VERDICT_HISTORICAL, VERDICT_VERIFIED):
            if verdict in found:
                return verdict, found[verdict]
        return None, ""

    # --- статус ---

    def state_of(self, event):
        """[статус, актуальность, причина, скрыть, третья сторона]; если событие ещё не размечено
        (гонка очередей), размечает по цепочке родителей."""
        if event.type == "SCAN":
            return [VALID, VALID, "", False, False]
        state = self._state.get(event.uuid)
        if state is None:
            state = self.assign(event)
        return state

    def assign(self, event):
        own = self.source_freshness(event)
        parent = event.parent
        has_parent = parent is not None and parent is not event
        parent_state = self.state_of(parent) if has_parent else [VALID, VALID, "", False, False]
        parent_status, parent_own = parent_state[:2]

        verdict, reason = self.run_checks(event)
        if verdict == VERDICT_HISTORICAL:
            own = HISTORICAL if own is None else min(own, HISTORICAL)
        elif verdict == VERDICT_VERIFIED:
            own = VERIFIED

        if verdict in (VERDICT_FALSE, VERDICT_UNRELATED):
            status = FALSE
            own = FALSE
        elif own != VERIFIED and parent_status == FALSE:
            # потомок ложного (например, порт-догадка speculate для скрытого чужого имени)
            status = FALSE
            reason = f"parent is false ({parent.type}: {parent.pretty_string})"
        elif own == VERIFIED:
            status = VALID
        else:
            status = parent_status if own is None else min(own, parent_status)

        # актуальность относительно родителя в выводе: omitted-родители в выводе пропускаются,
        # поэтому их собственная актуальность сворачивается в ребёнка
        rel = own
        if has_parent and parent.type != "SCAN" and parent._omit and parent_own not in (None, VERIFIED):
            if rel is None:
                rel = parent_own
            elif rel not in (VERIFIED, FALSE):
                rel = min(rel, parent_own)

        # инфраструктура третьей стороны: имя вне скоупа из записи DNS цели (почта, DNS, облако, мониторинг —
        # цель этим пользуется, но это не её актив) и его потомки вне скоупа (IP, ASN, геолокация)
        third_party = (
            status != FALSE
            and event.scope_distance > 0
            and ((event.type in DNS_NAME_TYPES and getattr(event.module, "_type", "") == "DNS") or parent_state[4])
        )

        state = [status, rel, reason, verdict == VERDICT_UNRELATED, third_party]
        self._state[event.uuid] = state
        return state

    def tag(self, event, state):
        status, rel = state[:2]
        for name in STATUS_NAMES.values():
            event.remove_tag(f"validity-{name}")
        for level in OWN_NAMES.values():
            event.remove_tag(f"freshness-{level}")
        event.add_tag(f"validity-{STATUS_NAMES[status]}")
        event.add_tag(f"freshness-{OWN_NAMES[rel]}")
        if state[4]:
            event.add_tag(THIRD_PARTY_TAG)

    async def handle_event(self, event, **kwargs):
        if event.type == "SCAN":
            return True
        state = self.state_of(event)
        if state[0] == FALSE:
            hidden = state[3]
            self.log_false(event, state[2], hidden)
            if hidden:
                # кандидат-домен: не в вывод, но анализаторы связей событие видят
                event.internal = True
                # тег affiliate заставляет выводить событие всегда — ложному он не положен
                event.remove_tag("affiliate")
            elif self.drop_false:
                return False, f"false finding: {state[2]}"
        self.tag(event, state)
        return True

    # --- журнал ложных ---

    def log_false(self, event, reason, hidden=False):
        self.false_count += 1
        if self._false_file is None:
            self._false_file = open(self.scan.home / "validity_false.jsonl", "a")
        record = {
            "type": event.type,
            "data": event.pretty_string,
            "module": str(event.module),
            "parent": getattr(event.parent, "id", None),
            "reason": reason,
            "hidden": hidden,
        }
        self._false_file.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._false_file.flush()

    async def report(self):
        if self.false_count:
            self.info(f"{self.false_count:,} false findings dropped or hidden (see validity_false.jsonl)")

    async def cleanup(self):
        if self._false_file is not None:
            self._false_file.close()
