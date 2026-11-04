"""Runs the original Qt generator synchronously in its own Python environment."""
import argparse
import copy
import json
from pathlib import Path
import random
import sys


def main():
    p = argparse.ArgumentParser()
    p.add_argument("source", type=Path)
    p.add_argument("romfs", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("contract", type=Path)
    p.add_argument('--world-visuals',action='store_true')
    args = p.parse_args()
    if args.output.exists():
        raise ValueError("Worker output must not already exist")
    source = args.source.resolve()
    contract = json.loads(args.contract.read_text(encoding="utf-8"))
    # LAS derives its source asset paths from argv[0], so set this before imports.
    sys.path.insert(0, str(source))
    sys.argv[0] = str(source / "randomizer.py")
    from PySide6.QtCore import QCoreApplication
    app = QCoreApplication.instance() or QCoreApplication([])
    from RandomizerCore.mod_generator import ModsProcess
    errors = []
    process = ModsProcess(copy.deepcopy(contract["placements"]), str(args.romfs.resolve()),
                          str(args.output.resolve()), copy.deepcopy(contract["item_defs"]),
                          contract["random_seed"], random.Random(contract["random_seed"]).getstate())
    process.error.connect(errors.append)
    process.run()  # Never invoke the destructive progress-window wrapper.
    app.processEvents()
    if errors:
        raise RuntimeError("Original LAS generator failed: " + "\n".join(errors))
    if not (args.output / "romfs").is_dir() or not (args.output / "exefs").is_dir():
        raise RuntimeError("Generator did not produce expected directories")
    if 'native_check_plan' in contract:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from native_events import stage as stage_native_events
        stage_native_events(args.output,args.romfs)
        if 'native_display_plan' in contract:
            from native_display import stage
            stage(args.output,args.romfs,contract['native_display_plan'])
            from native_underwater import stage as stage_underwater
            stage_underwater(args.output,args.romfs,contract)
            from native_shells import stage as stage_shells
            shell_checks=stage_shells(args.output,args.romfs,contract)
            from native_crane import stage as stage_crane
            stage_crane(args.output,args.romfs,contract)
            from native_shop import stage as stage_shop
            shop=stage_shop(args.output,args.romfs,contract)
            (args.output/'native-shop-plan.json').write_text(json.dumps(shop,indent=2))
            from native_hints import stage as stage_hints
            stage_hints(args.output,args.romfs,contract['native_config']['manifest'])
            if args.world_visuals:
                from native_world_visuals import stage as stage_world_visuals
                visuals=stage_world_visuals(args.output,args.romfs,shell_checks,contract['native_check_plan']['digest'])
                print(f'Experimental shell world visuals: {len(visuals["checks"])} staged, {len(visuals["unsupported"])} stock fallbacks',flush=True)
        from native_plan import audit_markers
        audit = audit_markers(args.output, contract['native_check_plan'],contract.get('native_display_plan'))
        (args.output / 'native-marker-audit.json').write_text(json.dumps(audit, indent=2))
        print(f"Serialized native markers: {audit['serialized_count']}/{audit['managed_count']}", flush=True)


if __name__ == "__main__":
    main()
