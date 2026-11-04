"""Статус находок скана (valid / historical / false) по всем путям обнаружения.

В скане модуль `validity` размечает каждое НАБЛЮДЕНИЕ (событие от конкретного модуля):
  validity-<status>  — статус по пути, которым пришло это наблюдение;
  freshness-<level>  — собственная актуальность наблюдения относительно родителя в выводе
                       (current / historical / inherit / verified).

Одна сущность может прийти несколькими путями: сначала из архива (historical), потом из
актуального источника. Модули BBoT берут первую копию, поэтому в скане потомки могли
остаться историческими. Здесь статус пересчитывается по графу всех наблюдений:

  status(сущность) = max по наблюдениям o: min(own(o), status(родитель o))

own: current → valid, historical → historical, inherit → не ограничивает (берёт родителя),
verified → valid независимо от родителя (подтверждено проверкой сейчас, например имя цели резолвится).
Корень скана — valid. Значения только растут, поэтому итерация до неподвижной точки конечна.
Ложные находки в вывод не попадают (validity_false.jsonl скана).
"""

FALSE, HISTORICAL, VALID, VERIFIED = 0, 1, 2, 3
NAMES = {FALSE: "false", HISTORICAL: "historical", VALID: "valid"}
# freshness-false: ложное наблюдение (скрытый кандидат-домен, который ядро вернуло в вывод как звено графа)
OWN = {"freshness-current": VALID, "freshness-historical": HISTORICAL, "freshness-inherit": VALID,
       "freshness-verified": VERIFIED, "freshness-false": FALSE}
TAGGED = {"validity-valid": VALID, "validity-historical": HISTORICAL, "validity-false": FALSE}


def compute_status(events):
    """events — словари JSONL скана. Возвращает {id события: "valid"|"historical"|"false"};
    события без разметки (сканы до появления validity) в ответ не попадают."""
    status = {}
    edges = []  # (id, parent_id, own, статус из скана)
    for e in events:
        eid = e.get("id")
        if not eid:
            continue
        if e.get("type") == "SCAN":
            status[eid] = VALID
            continue
        tags = e.get("tags") or []
        own = next((OWN[t] for t in tags if t in OWN), None)
        if own is None:
            continue
        tagged = next((TAGGED[t] for t in tags if t in TAGGED), None)
        edges.append((eid, e.get("parent"), own, tagged))

    ids = {eid for eid, _, _, _ in edges} | set(status)
    for eid, _parent, own, _tagged in edges:
        if own == VERIFIED:
            status[eid] = VALID
    # наблюдение, чей родитель не попал в вывод, берёт статус, посчитанный в скане
    for eid, parent, _own, tagged in edges:
        if parent not in ids and tagged is not None:
            status[eid] = max(status.get(eid, FALSE), tagged)

    changed = True
    while changed:
        changed = False
        for eid, parent, own, _tagged in edges:
            if own == VERIFIED:
                continue
            ps = status.get(parent)
            if ps is None:
                continue
            cand = min(own, ps)
            if cand > status.get(eid, -1):
                status[eid] = cand
                changed = True

    return {eid: NAMES[s] for eid, s in status.items() if not eid.startswith("SCAN:")}
