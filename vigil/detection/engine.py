"""Rule engine: match normalised events against rules written as JSON.

A rule looks like this (see rules.json for all of them):

    {
      "id": "VIG-002",
      "title": "PowerShell with an encoded command",
      "severity": "high",
      "mitre": {"tactic": "Execution", "technique": "T1059.001", "name": "PowerShell"},
      "category": "process", "action": "start",
      "match": {"all": [
          {"field": "process.name", "op": "in", "value": ["powershell.exe", "pwsh.exe"]},
          {"field": "process.command_line", "op": "regex", "value": "\\s-(e|ec|enc|encodedcommand)\\s"}
      ]},
      "description": "...", "advice": "..."
    }

"match" is a tree of groups:  all = AND,  any = OR,  none = NOT ANY.
Each leaf compares one field with one operator. String comparisons ignore case.
This is the same idea as Sigma rules, cut down to fit in one page of code.
"""
import json
import re
import threading

OPS = {}


def op(name):
    def deco(fn):
        OPS[name] = fn
        return fn
    return deco


def _s(v):
    return "" if v is None else str(v).lower()


@op("equals")
def _eq(v, x): return _s(v) == _s(x)

@op("in")
def _in(v, xs): return _s(v) in {_s(x) for x in xs}

@op("contains")
def _contains(v, x): return _s(x) in _s(v)

@op("contains_any")
def _contains_any(v, xs): return any(_s(x) in _s(v) for x in xs)

@op("contains_all")
def _contains_all(v, xs): return all(_s(x) in _s(v) for x in xs)

@op("startswith")
def _startswith(v, x): return _s(v).startswith(_s(x))

@op("endswith")
def _endswith(v, x): return _s(v).endswith(_s(x))

@op("endswith_any")
def _endswith_any(v, xs): return any(_s(v).endswith(_s(x)) for x in xs)

@op("regex")
def _regex(v, pattern): return re.search(pattern, "" if v is None else str(v), re.IGNORECASE) is not None

@op("gte")
def _gte(v, x):
    try: return float(v) >= float(x)
    except (TypeError, ValueError): return False

@op("is_true")
def _is_true(v, _x=None): return v is True or _s(v) == "true"

@op("exists")
def _exists(v, _x=None): return v not in (None, "")


def matches(node, event):
    if "all" in node:
        return all(matches(n, event) for n in node["all"])
    if "any" in node:
        return any(matches(n, event) for n in node["any"])
    if "none" in node:
        return not any(matches(n, event) for n in node["none"])
    fn = OPS[node["op"]]
    return fn(event.get(node["field"]), node.get("value"))


class RuleEngine:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self.rules = []
        self.hits = {}
        self.load()

    def load(self):
        with open(self.path, encoding="utf-8") as f:
            rules = json.load(f)
        for r in rules:
            r.setdefault("enabled", True)
            for leaf in _leaves(r["match"]):
                if leaf["op"] not in OPS:
                    raise ValueError(f"Rule {r['id']} uses unknown operator {leaf['op']}")
                if leaf["op"] == "regex":
                    re.compile(leaf["value"])
        with self._lock:
            self.rules = rules

    def evaluate(self, event):
        hits = []
        for r in self.rules:
            if not r["enabled"]:
                continue
            if r.get("category") and r["category"] != event.get("category"):
                continue
            actions = r.get("action")
            if actions and event.get("action") not in (actions if isinstance(actions, list) else [actions]):
                continue
            if matches(r["match"], event):
                self.hits[r["id"]] = self.hits.get(r["id"], 0) + 1
                hits.append((r, None))
        return hits

    def toggle(self, rule_id):
        for r in self.rules:
            if r["id"] == rule_id:
                r["enabled"] = not r["enabled"]
                return r["enabled"]
        return None


def _leaves(node):
    for k in ("all", "any", "none"):
        if k in node:
            for n in node[k]:
                yield from _leaves(n)
            return
    yield node
