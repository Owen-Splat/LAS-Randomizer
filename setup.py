import sys
from cx_Freeze import setup, Executable

build_exe_options = {"packages": ["os"], 
                    "excludes": ["tkinter", "unittest", "sqlite3", "numpy", "matplotlib", "zstandard"],
                    "zip_include_packages": ["encodings", "PySide6"],
                    "include_files": ["Data", "Resources", "version.txt"],
                    "optimize": 2}

base = None
if sys.platform == "win32":
    base = "Win32GUI"

setup(
    name = "Links Awakening Randomizer",
    version = "0.3",
    description = "A randomizer for The Legend of Zelda: Link's Awakening remake!",
    options = {"build_exe": build_exe_options},
    executables = [Executable("randomizer.py", base=base, target_name="Links Awakening Switch Randomizer", icon="Resources/icon.png")]
)