from pathlib import Path
import sys
import unittest

from ap_bootstrap import load_ap, ROOT

load_ap()
sys.path.insert(0, str(ROOT))
suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
suite.addTests(unittest.TestLoader().discover(str(ROOT / "tests_ap"), top_level_dir=str(ROOT / "tests_ap")))
result = unittest.TextTestRunner(verbosity=2).run(suite)
sys.exit(not result.wasSuccessful())
