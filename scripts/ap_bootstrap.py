"""Development-only loader for the pinned real AP checkout; no framework stubs."""
import os
from pathlib import Path
import sys
import unittest  # Enables AP_TEST_WORLDS scoping in the official loader.

ROOT = Path(__file__).resolve().parents[1]
AP = Path(os.environ.get("LAS_AP_ROOT", str(ROOT.parent / "development_dependencies/Archipelago-0.6.7"))).resolve()


def load_ap():
    if not (AP / "BaseClasses.py").is_file():
        raise RuntimeError("The development AP checkout is absent. See docs/DEVELOPMENT.md")
    os.environ["SKIP_REQUIREMENTS_UPDATE"] = "1"
    os.environ["AP_TEST_WORLDS"] = "las_switch"
    sys.path[:0] = [str(ROOT / ".deps"), str(AP)]
    import settings
    settings.no_gui = True
    settings.skip_autosave = True
    import Utils
    Utils.user_path.cached_path = str(ROOT / "build/ap_user_v2")
    Utils.cache_path.cached_path = str(ROOT / "build/ap_cache")
    Path(Utils.user_path()).mkdir(parents=True, exist_ok=True)
    # Extend the actual world's loader search path before it scans custom worlds.
    # Use the disposable development checkout, never a user's AP install.
    import shutil
    target = AP / "worlds/las_switch"
    shutil.copytree(ROOT / "apworld/las_switch", target, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    import worlds
    if worlds.failed_world_loads:
        raise RuntimeError(worlds.failed_world_loads)
    from worlds.las_switch import LASWorld
    return LASWorld
