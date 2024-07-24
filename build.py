import os
import re
import shutil
from RandomizerCore.randomizer_data import VERSION

import glob
import sys

base_name = f"LAS Randomizer v{VERSION}"
build_path = os.path.join(".", "build")

freeze_path_search = glob.glob(os.path.join(build_path, f"exe.*-{sys.version_info.major}.{sys.version_info.minor}"))
if len(freeze_path_search) != 1:
    raise Exception('Freeze Path folder could not be identified.')

freeze_path = freeze_path_search.pop()

# Getting platform from folder name
platform_re = re.search(r"exe\.(.*)-.*-.*[0-9]\.[0-9]", freeze_path)
destination_platform = platform_re.group(1)

base_name = f"LAS Randomizer v{VERSION} {destination_platform}"

release_path = os.path.join(build_path, base_name)
os.rename(freeze_path, release_path)
shutil.copyfile("README.md", os.path.join(release_path, "README.txt"))
shutil.copyfile("LICENSE.txt", os.path.join(release_path, "LICENSE.txt"))
shutil.make_archive(release_path, "zip", release_path)
