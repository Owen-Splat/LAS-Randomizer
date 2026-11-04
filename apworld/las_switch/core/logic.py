"""Non-eval parser and placement-independent fixed-point LAS basic logic."""
import re
from collections import Counter
from functools import lru_cache

from .data import NODES, FLAGS, active_locations, content, category_flags

TOKEN = re.compile(r"\s*([A-Za-z0-9_-]+(?:\[[a-z]+\])?(?::[0-9]+)?|[!&|()])")


@lru_cache(maxsize=2048)
def parse(expression):
    if not isinstance(expression, str):
        raise ValueError("Logic expression must be a string")
    position, tokens = 0, []
    while position < len(expression.rstrip()):
        match = TOKEN.match(expression, position)
        if not match:
            raise ValueError(f"Invalid logic at {expression[position:]!r}")
        tokens.append(match.group(1)); position = match.end()
    index = 0

    def expr(min_precedence=0):
        nonlocal index
        if index == len(tokens):
            raise ValueError("Incomplete logic expression")
        token = tokens[index]; index += 1
        if token == "!":
            left = ("not", expr(3))
        elif token == "(":
            left = expr()
            if index == len(tokens) or tokens[index] != ")":
                raise ValueError("Unclosed parenthesis")
            index += 1
        elif token in {"&", "|", ")"}:
            raise ValueError("Unexpected operator")
        else:
            name, _, count = token.partition(":")
            left = ("atom", name, int(count or 1))
        while index < len(tokens) and tokens[index] in {"&", "|"}:
            operator = tokens[index]
            precedence = 2 if operator == "&" else 1
            if precedence < min_precedence:
                break
            index += 1
            left = (operator, left, expr(precedence + 1))
        return left

    result = expr()
    if index != len(tokens):
        raise ValueError("Trailing logic tokens")
    return result


def evaluate(tree, access):
    op = tree[0]
    if op == "atom":
        return access.get(tree[1], 0) >= tree[2]
    if op == "not":
        return not evaluate(tree[1], access)
    if op == "&":
        return evaluate(tree[1], access) and evaluate(tree[2], access)
    return evaluate(tree[1], access) or evaluate(tree[2], access)


class Logic:
    def __init__(self, profile="standard", categories=None, settings=None, entrances=None):
        from .configuration import selected_locations,las_settings
        self.active = frozenset(selected_locations(profile,categories,settings))
        self.flags=(las_settings(categories,settings) if settings is not None else
                    category_flags(categories or ()) if profile=='configured' else FLAGS)
        self.conditions = {(name, key): parse(value) for name, node in NODES.items()
                           for key, value in node.items() if key.startswith("condition-")}
        if entrances:
            for entrance,destination in entrances.items():
                self.conditions[destination,'condition-basic']=parse(NODES[entrance]['condition-basic'])
        if not any(content(name)=='key-D3' for name in self.active):
            # Vanilla Key Cavern's hub branches return their keys; the last
            # basement key is a surplus key, not a prerequisite for reaching it.
            # Keep the original conservative budgets when any D3 keys shuffle.
            self.conditions['D3-3G','condition-basic']=parse('D3-4B & key-D3:1')
            self.conditions['D3-8G','condition-basic']=parse('D3-4C & key-D3:8 & dash-jump & kill-pairodd')
        if not any(content(name)=='key-D4' for name in self.active):
            # The fifth vanilla key is underwater. Four keys reach Cue Ball
            # and the Flippers; requiring that submerged key first is circular.
            self.conditions['D4-north-chest','condition-basic']=parse('D4-4E & (flippers | (key-D4:4 & kill-cueball))')
        if not any(content(name)=='key-D8' for name in self.active):
            # The final vanilla key requires the rod; the rod route uses the
            # six preceding keys and retains Blaino and every equipment gate.
            self.conditions['D8-far-northeast','condition-basic']=parse('D8-8D & key-D8:6 & feather & bombs & hookshot & kill-blaino')
        # Missing upstream rooms. Use complete, conservative vanilla routes,
        # rather than treating the adjacent room alone as access to the reward.
        # 2A is the northwest chess room's staircase to the rapids island.
        self.rooms = {
            'D6-2A': parse('D6-3A & hit-crystal-switch & bracelet:2'),
            # The boss route goes through the eastern wing, its third key door
            # and the hookshot passage. Keep the source's boss/enemy tests too.
            'D6-4D': parse('D6-4H & key-D6:3 & hookshot & bracelet:2'),
        }
        self.reachable = lru_cache(maxsize=256)(self._reachable)

    def _condition(self, name, key, access):
        tree = self.conditions.get((name, key))
        return tree is None or evaluate(tree, access)

    def _reachable(self, inventory):
        access = Counter(dict(inventory))
        access.update({name: 1 for name, enabled in self.flags.items() if enabled is True})
        seen = set()
        while True:
            changed = False
            for name, condition in self.rooms.items():
                if not access[name] and evaluate(condition, access):
                    access[name] = 1
                    changed = True
            for name, node in NODES.items():
                if name in seen:
                    continue
                in_region = node["type"] not in {"item", "follower"} or access[node["region"]] > 0
                if in_region and self._condition(name, "condition-basic", access):
                    seen.add(name); access[name] += 1; changed = True
                    if node["type"] == "follower":
                        access[node["content"]] += 1
                    elif node["type"] == "item" and name not in self.active:
                        # Disabled owl gifts are absent, not free vanilla rupees.
                        if node["subtype"] not in {"overworld-statue", "dungeon-statue"}:
                            access[content(name)] += 1
                    if node["type"] == "enemy":
                        access[name + "[pit]"] = 1
                        access[name + "[heavy]"] = 1
                elif node["type"] == "enemy":
                    for suffix in ("pit", "heavy"):
                        key = f"condition-{suffix}"
                        variant = f"{name}[{suffix}]"
                        if key in node and not access[variant] and self._condition(name, key, access):
                            access[variant] = 1; changed = True
            if not changed:
                return frozenset(name for name, count in access.items() if count > 0)

    def can_reach(self, inventory, name):
        signature = tuple(sorted((name, count) for name, count in inventory.items() if count > 0))
        return name in self.reachable(signature)
