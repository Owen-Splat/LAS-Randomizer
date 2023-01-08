# The MIT License (MIT)

# Copyright (c) 2018 LagoLunatic

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import platform
import shutil

from randomizer_data import VERSION

base_name = "Links Awakening Randomizer"

import struct
if (struct.calcsize("P") * 8) == 64:
	bitness_suffix = "_x64"
else:
	bitness_suffix = "_x32"

exe_ext = ""
if platform.system() == "Windows":
	exe_ext = ".exe"
	platform_name = "win"
if platform.system() == "Darwin":
	exe_ext = ".app"
	platform_name = "mac"
if platform.system() == "Linux":
	platform_name = "linux"

exe_path = os.path.join(".", "dist", base_name + exe_ext)
if not (os.path.isfile(exe_path) or os.path.isdir(exe_path)):
	raise Exception("Executable not found: %s" % exe_path)

release_archive_path = os.path.join(".", "dist", f"release_archive_{VERSION}{bitness_suffix}")

if os.path.exists(release_archive_path) and os.path.isdir(release_archive_path):
	shutil.rmtree(release_archive_path)

os.mkdir(release_archive_path)
shutil.copyfile("README.md", os.path.join(release_archive_path, "README.txt"))

shutil.move(exe_path, os.path.join(release_archive_path, base_name + exe_ext))

if platform.system() == "Darwin":
	shutil.make_archive(release_archive_path, "zip", release_archive_path)
# else:
# 	os.mkdir(os.path.join(release_archive_path, "Models"))
