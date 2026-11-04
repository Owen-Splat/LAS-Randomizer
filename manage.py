"""Build/install/export/patch tools for the real experimental AP world."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT / ".deps"), str(ROOT / "apworld")]


def build(destination):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted((ROOT / "apworld/las_switch").rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                archive.write(path, path.relative_to(ROOT / "apworld").as_posix())
        archive.write(ROOT / "THIRD_PARTY_LAS_LICENSE.txt", "las_switch/THIRD_PARTY_LAS_LICENSE.txt")
        archive.write(ROOT / "LICENSE", "las_switch/LICENSE")
    with zipfile.ZipFile(destination) as archive:
        if archive.testzip():
            raise ValueError("Invalid build archive")
    return destination


def load_manifest(path):
    from las_switch.core.seed import validate_manifest
    return validate_manifest(json.loads(Path(path).read_text(encoding="utf-8")))


def main():
    parser = argparse.ArgumentParser(description="LAS Switch experimental integration tools")
    cmds = parser.add_subparsers(dest="cmd", required=True)
    b = cmds.add_parser("build"); b.add_argument("--out", type=Path, default=ROOT / "dist/las_switch.apworld")
    i = cmds.add_parser("install"); i.add_argument("ap_root", type=Path)
    e = cmds.add_parser("export"); e.add_argument("manifest"); e.add_argument("--out", type=Path, required=True)
    patch = cmds.add_parser("patch")
    patch.add_argument("manifest"); patch.add_argument("--source", type=Path, required=True)
    patch.add_argument("--romfs", type=Path, required=True); patch.add_argument("--out", type=Path, required=True)
    patch.add_argument("--backend", type=Path, required=True); patch.add_argument("--build-id", required=True)
    patch.add_argument("--save-id", required=True); patch.add_argument("--team", type=int, default=0)
    patch.add_argument("--patch-python", default=sys.executable)
    generate = cmds.add_parser("generate", help="Generate from an AP patch using original LAS")
    generate.add_argument("manifest")
    for name in ("source", "romfs", "exefs", "out"):
        generate.add_argument("--" + name, type=Path, required=True)
    generate.add_argument("--mode", choices=("play", "prepare", "test", "native-checks", "native-development", "mod"), default="play")
    generate.add_argument("--backend", type=Path)
    generate.add_argument("--save-id")
    generate.add_argument("--patch-python", default=sys.executable)
    generate.add_argument("--team", type=int, default=0)
    for name in ("client", "mock"):
        cmd = cmds.add_parser(name)
        if name == "client":
            cmd.add_argument("--ap-root", type=Path, required=True)
        cmd.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        if args.cmd == "build":
            print(build(args.out))
        elif args.cmd == "install":
            if not ((args.ap_root / "Launcher.py").is_file() or (args.ap_root / "ArchipelagoLauncher.exe").is_file()):
                raise ValueError("Folder does not look like an AP installation")
            target = args.ap_root / "custom_worlds/las_switch.apworld"
            if target.exists():
                raise ValueError("LAS world already exists; review and move it before replacing")
            build(target); print(f"Installed {target}; restart AP Launcher")
        elif args.cmd == "export":
            from las_switch.core.patcher import generator_contract
            if args.out.exists():
                raise ValueError("Export output must be a new folder")
            contract = generator_contract(load_manifest(args.manifest))
            args.out.mkdir(parents=True)
            (args.out / "generator_input.json").write_text(json.dumps(contract, indent=2, sort_keys=True), encoding="utf-8")
            (args.out / "patch_plan.json").write_text(json.dumps(contract["native_config"], indent=2, sort_keys=True), encoding="utf-8")
            print(f"Exported complete generator contract and native hook plan to {args.out}; not deployable")
        elif args.cmd == "generate":
            from patch_pipeline import generate
            report = generate(args.manifest, args.source, args.romfs, args.exefs, args.out,
                              args.mode, args.backend, args.save_id, args.patch_python, args.team,
                              log=print)
            print(json.dumps(report, indent=2))
        elif args.cmd == "patch":
            from las_switch.core.patcher import generator_contract, check_source, verify_backend, backend_files
            manifest = load_manifest(args.manifest)
            if args.out.exists():
                raise ValueError("Patch output must be a new folder")
            source = check_source(args.source)
            backend_metadata=json.loads((args.backend / 'backend.json').read_text())
            if backend_metadata.get('layout') == 'patched_main_module_v1':
                raise ValueError('Patched-main backends require generate --mode mod with matching --exefs')
            backend = verify_backend(args.backend, manifest, args.build_id)
            if not (args.romfs / "region_common/level/Field/Field_08B.leb").is_file():
                raise ValueError("RomFS chest asset missing; select extracted clean RomFS")
            args.out.parent.mkdir(parents=True, exist_ok=True)
            contract = generator_contract(manifest)
            with tempfile.TemporaryDirectory(prefix="las-build-", dir=args.out.parent) as temporary:
                temp = Path(temporary)
                contract_path = temp / "contract.json"
                contract_path.write_text(json.dumps(contract), encoding="utf-8")
                result = temp / "result"
                subprocess.run([args.patch_python, str(ROOT / "scripts/patch_worker.py"), str(source),
                                str(args.romfs.resolve()), str(result), str(contract_path)], check=True)
                for name in backend_files(backend):
                    shutil.copyfile(backend / name, result / "exefs" / name)
                config = {**contract["native_config"]["runtime_config"], "build_id": args.build_id,
                          "save_id": args.save_id, "team": args.team,
                          "actions": contract["native_config"]["actions"]}
                (result / "romfs/ap_config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
                (result / "seed.lasap").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
                result.rename(args.out)
            print(f"Experimental mod staged at {args.out}; run the documented live validation before use")
        elif args.cmd == "mock":
            from las_switch.mock_game import launch
            launch(args.args[1:] if args.args[:1] == ["--"] else args.args)
        else:
            ap_root = args.ap_root.resolve()
            sys.path.insert(0, str(ap_root))
            import worlds
            worlds.__path__.append(str(ROOT / "apworld"))
            from worlds.las_switch.client import launch
            launch(args.args[1:] if args.args[:1] == ["--"] else args.args)
    except (ValueError, OSError, ImportError, subprocess.CalledProcessError) as exc:
        parser.exit(2, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
