"""Standard 5-field cron expressions: minute hour day-of-month month day-of-week.

Supports `*`, lists (`1,15`), ranges (`1-5`), steps (`*/15`, `10-50/10`), month and weekday names (`jan`, `mon`),
weekday 0 or 7 = Sunday, and the shortcuts @hourly, @daily, @weekly, @monthly, @yearly.
Like classic cron, when both day-of-month and day-of-week are restricted, a day matches if EITHER matches.
Times are local (naive datetime).
"""

from datetime import datetime, timedelta

SHORTCUTS = {
    "@hourly": "0 * * * *",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@weekly": "0 0 * * 0",
    "@monthly": "0 0 1 * *",
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
}
MONTHS = {m: i for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}
WEEKDAYS = {d: i for i, d in enumerate(["sun", "mon", "tue", "wed", "thu", "fri", "sat"])}
# (name, min, max, aliases)
FIELDS = [("minute", 0, 59, {}), ("hour", 0, 23, {}), ("day of month", 1, 31, {}), ("month", 1, 12, MONTHS),
          ("day of week", 0, 7, WEEKDAYS)]  # fmt: skip
MAX_SEARCH_MINUTES = 366 * 24 * 60 * 5  # five years: enough for any valid expression, e.g. Feb 29


class CronError(ValueError):
    pass


def _value(token, lo, hi, aliases, field):
    token = token.lower()
    if token in aliases:
        return aliases[token]
    if not token.isdigit():
        raise CronError(f"{field}: invalid value {token!r}")
    v = int(token)
    if not lo <= v <= hi:
        raise CronError(f"{field}: {v} is out of range {lo}-{hi}")
    return v


def _parse_field(text, lo, hi, aliases, field):
    values = set()
    for part in text.split(","):
        if not part:
            raise CronError(f"{field}: empty list item")
        step = 1
        if "/" in part:
            part, step_text = part.split("/", 1)
            if not step_text.isdigit() or int(step_text) == 0:
                raise CronError(f"{field}: invalid step {step_text!r}")
            step = int(step_text)
        if part == "*":
            start, end = lo, hi
        elif "-" in part:
            a, b = part.split("-", 1)
            start, end = _value(a, lo, hi, aliases, field), _value(b, lo, hi, aliases, field)
            if start > end:
                raise CronError(f"{field}: range {part} goes backwards")
        else:
            start = _value(part, lo, hi, aliases, field)
            # "5/15" means from 5 to the end in steps of 15
            end = hi if step > 1 else start
        values.update(range(start, end + 1, step))
    return values


class Cron:
    def __init__(self, expr):
        self.expr = str(expr or "").strip()
        text = SHORTCUTS.get(self.expr.lower(), self.expr)
        parts = text.split()
        if len(parts) != 5:
            raise CronError("a cron expression needs 5 fields: minute hour day-of-month month day-of-week")
        sets = [_parse_field(p, lo, hi, al, name) for p, (name, lo, hi, al) in zip(parts, FIELDS, strict=True)]
        self.minutes, self.hours, self.days, self.months, weekdays = sets
        self.weekdays = {0 if d == 7 else d for d in weekdays}
        self.dom_any = parts[2] == "*"
        self.dow_any = parts[4] == "*"

    def _day_matches(self, dt):
        dom = dt.day in self.days
        dow = (dt.isoweekday() % 7) in self.weekdays
        if self.dom_any and self.dow_any:
            return True
        if self.dom_any:
            return dow
        if self.dow_any:
            return dom
        return dom or dow

    def matches(self, dt):
        return (
            dt.minute in self.minutes and dt.hour in self.hours and dt.month in self.months and self._day_matches(dt)
        )

    def next_after(self, dt):
        """The first matching minute strictly after `dt`."""
        t = dt.replace(second=0, microsecond=0) + timedelta(minutes=1)
        for _ in range(MAX_SEARCH_MINUTES):
            if t.month not in self.months:
                # jump to the first day of the next month
                t = (t.replace(day=1, hour=0, minute=0) + timedelta(days=32)).replace(day=1)
                continue
            if not self._day_matches(t):
                t = (t + timedelta(days=1)).replace(hour=0, minute=0)
                continue
            if t.hour not in self.hours:
                t = (t + timedelta(hours=1)).replace(minute=0)
                continue
            if t.minute in self.minutes:
                return t
            t += timedelta(minutes=1)
        raise CronError("the expression never matches")


def next_run(expr, after=None):
    """Next run time (datetime) for a cron expression after `after` (default: now)."""
    return Cron(expr).next_after(after or datetime.now())


def validate(expr):
    """Returns a normalized expression or raises CronError."""
    c = Cron(expr)
    c.next_after(datetime(2000, 1, 1))
    return c.expr
