"""Compile parsed rules into matchers, and decide one node at a time.

This is the ONLY evaluator. The preview, "apply to current graph" and every
scan-time sweep call it on the same projection, which is what makes the counts
a preview shows the counts an apply writes.

Pure Python, no graph access. Globs go through `fnmatch.translate` (Python
3.11's translation cannot backtrack catastrophically) within the pattern caps
model.py enforces; there is no user regex.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from datetime import datetime, timedelta, timezone

from .model import NodeFilterConfig, parse_datetime
from .normalize import field_value, inputs_of


def is_missing(value) -> bool:
    """Absent, null or the empty string. A rule's other operators never match these."""
    return value is None or (isinstance(value, str) and value.strip() == "")


def _text(value) -> str:
    # The whole value. Cutting it short flips the answer of `not_contains`,
    # `ends_with` and end-anchored globs whenever the needle lies past the cut,
    # and buys nothing: every text operator here is linear in the value.
    return str(value).lower()


def _as_list(value):
    if value is None:
        return None
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_text(v) for v in value if v is not None]
    return [_text(value)]


def _as_number(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in ("true", "yes", "1"):
        return True
    if text in ("false", "no", "0"):
        return False
    return None


def _glob(pattern: str):
    """A whole-value glob matcher over already-lowercased text.

    A pattern whose only wildcard is `*` is matched with plain string
    operations: its literal parts must appear in order, the first at the start
    and the last at the end. That is the common case (`*.example.com`,
    `*tmpl-*`) and it is several times cheaper than a regex per node per rule.
    `?` and `[...]` go through `fnmatch.translate`.
    """
    if "?" in pattern or "[" in pattern:
        rx = re.compile(fnmatch.translate(pattern), re.IGNORECASE)
        return lambda s: rx.match(s) is not None
    parts = pattern.split("*")
    if len(parts) == 1:
        return lambda s: s == pattern
    first, last, middle = parts[0], parts[-1], [p for p in parts[1:-1] if p]
    # The shapes almost every rule uses, as single string operations.
    if not middle:
        if not first and not last:
            return lambda s: True
        if not first:
            return lambda s: s.endswith(last)
        if not last:
            return lambda s: s.startswith(first)
    if not first and not last and len(middle) == 1:
        needle = middle[0]
        return lambda s: needle in s
    floor = len(first) + len(last)

    def match(s: str) -> bool:
        if len(s) < floor or not s.startswith(first) or not s.endswith(last):
            return False
        pos, end = len(first), len(s) - len(last)
        for part in middle:
            found = s.find(part, pos, end)
            if found < 0:
                return False
            pos = found + len(part)
        return True
    return match


def prepare(ftype: str, raw, ranks: dict | None = None):
    """A node's value for one field, normalised ONCE per node.

    Every rule that tests the field then compares against this, instead of
    lowercasing or parsing the same value again for each of up to
    forty rules. The shape depends on the type; the first element is always
    whether the value counts as missing.
    """
    if ftype == "list":
        items = _as_list(raw)
        return (raw is None, None if items is None else set(items), raw is None or (
            isinstance(raw, (list, tuple)) and len(raw) == 0))
    missing = is_missing(raw)
    if missing:
        return (True, None, None)
    if ftype == "number":
        return (False, _as_number(raw), None)
    if ftype == "bool":
        return (False, _as_bool(raw), None)
    if ftype == "ip":
        try:
            return (False, ipaddress.ip_address(str(raw).strip()), None)
        except ValueError:
            return (False, None, None)
    if ftype == "date":
        return (False, parse_datetime(raw), None)
    text = _text(raw)
    if ftype == "ordinal":
        text = text.strip()
        return (False, text, (ranks or {}).get(text))
    if ftype == "enum":
        return (False, text.strip(), None)
    return (False, text, None)


def _compile_condition(cond, fdef: dict, now: datetime):
    """One condition as a predicate over the field's PREPARED value (see `prepare`)."""
    op, want, ftype = cond.op, cond.value, fdef["type"]

    if op == "missing":
        return lambda p: p[0]

    if ftype == "list":
        if op == "is_empty":
            return lambda p: p[2]
        if op == "contains_any":
            return lambda p: p[1] is not None and not p[1].isdisjoint(want)
        if op == "contains_all":
            return lambda p: p[1] is not None and want <= p[1]
        return lambda p: p[1] is not None and p[1].isdisjoint(want)  # not_contains_any

    if ftype == "bool":
        target = op == "is_true"
        return lambda p: not p[0] and p[1] is target

    if ftype == "number":
        if op == "between":
            lo, hi = want
            return lambda p: p[1] is not None and lo <= p[1] <= hi
        compare = {"lt": lambda n: n < want, "lte": lambda n: n <= want, "gt": lambda n: n > want,
                   "gte": lambda n: n >= want, "eq": lambda n: n == want}[op]
        return lambda p: p[1] is not None and compare(p[1])

    if ftype == "ordinal":
        if op in ("in", "not_in"):
            inside = op == "in"
            return lambda p: not p[0] and (p[1] in want) is inside
        # A value off the scale ("unknown") is not below or above anything.
        compare = {"lt": lambda r: r < want, "lte": lambda r: r <= want,
                   "gt": lambda r: r > want, "gte": lambda r: r >= want}[op]
        return lambda p: p[2] is not None and compare(p[2])

    if ftype == "enum":
        inside = op == "in"
        # A value a writer stopped writing also stands for what replaced it, so
        # a saved rule keeps matching with no migration (catalog `aliases`).
        aliases = fdef.get("aliases") or {}
        want = frozenset(want).union(*(
            (str(t).lower() for t in aliases[v]) for v in aliases if v.lower() in want))
        return lambda p: not p[0] and (p[1] in want) is inside

    if ftype == "ip":
        inside = op == "in_cidr"
        return lambda p: p[1] is not None and any(
            p[1].version == net.version and p[1] in net for net in want) is inside

    if ftype == "date":
        if op == "before":
            return lambda p: p[1] is not None and p[1] < want
        if op == "after":
            return lambda p: p[1] is not None and p[1] > want
        limit = timedelta(days=want)
        if op == "older_than_days":
            return lambda p: p[1] is not None and now - p[1] > limit
        return lambda p: p[1] is not None and now - p[1] <= limit

    # text, host, url
    if op in ("glob", "not_glob"):
        glob, negate = _glob(want), op == "not_glob"
        return lambda p: not p[0] and glob(p[1]) is not negate
    check = {"eq": lambda s: s == want, "not_eq": lambda s: s != want,
             "contains": lambda s: want in s, "not_contains": lambda s: want not in s,
             "starts_with": lambda s: s.startswith(want),
             "ends_with": lambda s: s.endswith(want)}[op]
    return lambda p: not p[0] and check(p[1])


class _CompiledRule:
    __slots__ = ("id", "name", "match_all", "checks")

    def __init__(self, rule, checks):
        self.id = rule.id
        self.name = rule.name
        self.match_all = rule.match_all
        self.checks = checks  # [(field, predicate over the prepared value)]

    def matches(self, prepared: dict) -> bool:
        if self.match_all:
            return True
        for field, pred in self.checks:
            if not pred(prepared[field]):
                return False
        return True


class FilterSet:
    """Compiled rules for one mode. `decide` is the whole semantics."""

    def __init__(self, config: NodeFilterConfig, catalog, now: datetime | None = None):
        self.config = config
        self.mode = config.mode
        self.catalog = catalog
        now = now or datetime.now(timezone.utc)
        self._rules: dict = {}
        self._fields: dict = {}
        self._prep: dict = {}
        if not config.ok:
            return
        for kind_id, kc in config.kinds.items():
            if not kc.active or kind_id not in catalog.kinds:
                continue
            kind = catalog.kinds[kind_id]
            compiled, used = [], set()
            for rule in kc.rules:
                checks = []
                for cond in rule.conditions:
                    fdef = kind["fields"][cond.field]
                    checks.append((cond.field, _compile_condition(cond, fdef, now)))
                    used.add(cond.field)
                compiled.append(_CompiledRule(rule, checks))
            self._rules[kind_id] = compiled
            self._fields[kind_id] = used
            self._prep[kind_id] = {
                name: (kind["fields"][name]["type"], {
                    s.lower(): i for i, s in enumerate(
                        catalog.ordinals.get(kind["fields"][name].get("scale")) or [])})
                for name in used
            }

    def is_active(self, kind: str) -> bool:
        return bool(self._rules.get(kind))

    def fields_used(self, kind: str) -> set:
        return set(self._fields.get(kind, ()))

    def props_needed(self, kind: str) -> set:
        """The node properties the kind's rules read: its projection."""
        fields = self.catalog.kinds[kind]["fields"]
        props = set()
        for name in self._fields.get(kind, ()):
            props.update(inputs_of(fields[name]))
        return props

    def values(self, kind: str, props: dict) -> dict:
        """The rule fields this kind's rules read, from a node's projected properties."""
        fields = self.catalog.kinds[kind]["fields"]
        return {name: field_value(fields[name], props) for name in self._fields.get(kind, ())}

    def rules(self, kind: str) -> list:
        return list(self._rules.get(kind, ()))

    def decide(self, kind: str, values: dict):
        """(filtered, rule_ids) for one node of an ACTIVE kind.

        Denylist: filtered when any rule matches; `rule_ids` are the matching
        rules in order, and the first is the one the mute is attributed to.
        Allowlist: filtered when NO rule matches; `rule_ids` are the keep rules
        that matched (empty when filtered).
        """
        prepared = {name: prepare(ftype, values.get(name), ranks)
                    for name, (ftype, ranks) in self._prep.get(kind, {}).items()}
        matched = [r.id for r in self._rules.get(kind, ()) if r.matches(prepared)]
        if self.mode == "allowlist":
            return (not matched), matched
        return bool(matched), matched


def compile(config: NodeFilterConfig, catalog, now: datetime | None = None) -> FilterSet:  # noqa: A001
    return FilterSet(config, catalog, now=now)
