# -*- mode: python ; coding: utf-8 -*-


block_cipher = None

with open("./version.txt") as f:
    randomizer_version = f.read().strip()

added_files = [
    ( 'Data', 'Data' ),
    ( 'Resources', 'Resources' ),
    ( 'version.txt', '.')
]
a = Analysis(
    ['randomizer.py'],
    pathex=[],
    binaries=[],
    datas = added_files,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Links Awakening Randomizer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='Resources/LASR_Icon.ico',
)

app = BUNDLE(
    exe,
    name='Links Awakening Randomizer.app',
    icon='Resources/LASR_Icon.icns',
    bundle_identifier=None,
    info_plist={
        'LSBackgroundOnly': False,
        'CFBundleDisplayName': 'Links Awakening Randomizer',
        'CFBundleName': 'LAS Randomizer', # 15 character maximum
        'CFBundleShortVersionString': randomizer_version,
    }
)