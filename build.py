import os
import shutil
from RandomizerCore.randomizer_data import VERSION

base_name = f"LAS Randomizer v{VERSION}"
build_path = os.path.join(".", "build")
freeze_path = os.path.join(build_path, "exe.win-amd64-3.8")
release_path = os.path.join(build_path, base_name)
os.rename(freeze_path, release_path)
shutil.copyfile("README.md", os.path.join(release_path, "README.txt"))
shutil.copyfile("LICENSE.txt", os.path.join(release_path, "LICENSE.txt"))
shutil.make_archive(release_path, "zip", release_path)
