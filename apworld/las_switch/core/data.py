import json
from importlib.resources import files

GAME = "Link's Awakening (Switch)"
VERSION = "0.3.0"
PROTOCOL = 1
CATALOG = json.loads(files(__package__).joinpath("catalog.json").read_text(encoding="utf-8"))
REGISTRY = json.loads(files(__package__).joinpath("ids.json").read_text(encoding="utf-8"))
ITEM_IDS = REGISTRY["items"]
LOCATION_IDS = REGISTRY["locations"]
ITEMS = {k: v["definition"] for k, v in CATALOG["items"].items()}
NODES = CATALOG["logic_nodes"]
# Explicit adapter correction, without altering the supplied source.
CONTENT_ALIASES = {"powders-capacity": "powder-capacity"}
FLAGS = {"free-book": True, "unlocked-bombs": True, "open-kanalet": True,
         "open-bridge": True, "open-mamu": True, "open-mabe": False,
         "shuffle-bombs": False, "shuffle-powder": False, "bad-pets": False,
         "classic-d2": False, "fast-fishing": False, "fast-master-stalfos": False,
         "fast-trendy": False, "free-shop": False, "reduced-farming": False}
ALLOWED_SUBTYPES = {"chest", "boss", "enemy", "drop", "npc", "standing"}
CATEGORIES=json.loads(files(__package__).joinpath('categories.json').read_text(encoding='utf-8'))
CATEGORY_NAMES=frozenset(CATEGORIES.values())
CORE_CATEGORIES=CATEGORY_NAMES-{'owl_gifts','blupsanity'}


def category_flags(categories):
    result=dict(FLAGS)
    result.update({'owl-overworld-gifts':'owl_gifts' in categories,
                   'owl-dungeon-gifts':'owl_gifts' in categories,
                   'blupsanity':'blupsanity' in categories})
    return result


def content(name):
    value = NODES[name]["content"]
    return CONTENT_ALIASES.get(value, value)


def active_locations(profile="standard", categories=None):
    if profile=='configured':
        if categories is None:categories=CORE_CATEGORIES
        if not isinstance(categories,(list,tuple,set,frozenset)) or not set(categories)<=CATEGORY_NAMES:
            raise ValueError('Unknown check category')
        return tuple(sorted(name for name,category in CATEGORIES.items() if category in categories))
    if profile not in {"standard", "chests"}:
        raise ValueError("Unsupported check profile")
    return tuple(sorted(name for name, node in NODES.items()
                        if node["type"] == "item"
                        and node["subtype"] in ({"chest"} if profile == "chests" else ALLOWED_SUBTYPES)
                        and not name.startswith(("trendy-prize-", "D0-rupee-"))))


def pool(profile="standard", categories=None):
    return [content(name) for name in active_locations(profile,categories)]


INDEX_POOLS = {"seashell": list(range(50)), "heart-piece": list(range(32)),
               "heart-container": list(range(9)), "bottle": list(range(3)),
               "golden-leaf": list(range(5)),
               "chamber-stone": [3, 4, 8, 10, 11, 12, 13, 20, 21, 22, 23, 24, 25, 26]}
