# -*- mode: python ; coding: utf-8 -*-

with open("./version.txt") as f:
    randomizer_version = f.read().strip()

import os

def createDatas(paths):
    datas = []
    for path in paths:
        if '/' not in path:
            datas.append((path, "."))
            continue
        for entry in os.listdir(path):
            full_path = os.path.join(path, entry)
            if os.path.isdir(full_path):
                datas.extend(createDatas([full_path]))
            else:
                datas.append((full_path, path))
    return datas

from PyInstaller.utils.hooks import collect_data_files

a = Analysis(
    ['randomizer.py'],
    pathex=[],
    binaries=[],
    datas=createDatas([
        "RandomizerCore/Data",
        "RandomizerUI/Resources",
        "version.txt"
    ]) + collect_data_files('lms', include_py_files=True),
    hiddenimports=[
        'lms.titleconfig.presets'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None
)
pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name='LAS Randomizer',
    debug=False,
    strip=False,
    upx=True,
    runtime_tmpdir=None,
    console=False,
    icon="RandomizerUI/Resources/icon.ico"
)

app = BUNDLE(exe,
    name='LAS Randomizer.app',
    icon="RandomizerUI/Resources/icon.icns",
    bundle_identifier=None,
    info_plist={
        "LSBackgroundOnly": False,
        "CFBundleDisplayName": "LAS Randomizer",
        "CFBundleName": "LAS Randomizer",
        "CFBundleShortVersionString": randomizer_version
    })