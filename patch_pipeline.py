"""Player-facing patch preparation and isolated original-LAS generation."""
import json
import hashlib
from importlib import import_module
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import runpy

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "apworld"))
PACKAGE = "worlds.las_switch" if "worlds.las_switch" in sys.modules else "las_switch"
_patcher = import_module(PACKAGE + ".core.patcher")
check_source = _patcher.check_source
generator_contract = _patcher.generator_contract
verify_backend = _patcher.verify_backend
backend_files = _patcher.backend_files
validate_manifest = import_module(PACKAGE + ".core.seed").validate_manifest
default_save_id = import_module(PACKAGE + ".core.seed").default_save_id


def read_build_id(exefs):
    with (Path(exefs) / "main").open("rb") as stream:
        header = stream.read(0x100)
    if len(header) != 0x100 or header[:4] != b"NSO0":
        raise ValueError("ExeFS/main is not an NSO executable")
    # NSO reserves 32 bytes; LAS pchtxt uses its 20-byte GNU build ID.
    return header[0x40:0x54].hex().upper()


def inputs(manifest_path, source, romfs, exefs):
    manifest = validate_manifest(json.loads(Path(manifest_path).read_text(encoding="utf-8-sig")))
    source = check_source(source)
    romfs = Path(romfs).resolve()
    for name in ("region_common/level/Field/Field_08B.leb", "region_common/event/PlayerStart.bfevfl"):
        if not (romfs / name).is_file():
            raise ValueError(f"Clean RomFS is missing {name}")
    build_id = read_build_id(exefs)
    patcher = (source / "RandomizerCore/mod_generator.py").read_text(encoding="utf-8")
    if build_id not in patcher.upper():
        raise ValueError(f"The original LAS randomizer does not list this executable build: {build_id}")
    return manifest, source, romfs, build_id


def generate(manifest_path, source, romfs, exefs, output, mode="prepare", backend=None,
             save_id=None, patch_python=sys.executable, team=0, log=None, world_visuals=False):
    if mode not in {"prepare", "test", "native-checks", "native-development", "mod", "play"}:
        raise ValueError("Unknown generation mode")
    if world_visuals and mode!='native-development':
        raise ValueError('Experimental shell world models are available only in copied-save native integration tests')
    if mode in {'native-development','play'} and team!=0:
        raise ValueError('The development native bridge currently supports AP team 0')
    output = Path(output).resolve()
    if output.exists():
        raise ValueError("Choose a new output folder; existing folders are never replaced")
    manifest, source, romfs, build_id = inputs(manifest_path, source, romfs, exefs)
    if mode=='play' and not save_id:
        save_id=default_save_id(manifest)
    for protected in (source, romfs, Path(exefs).resolve()):
        if output == protected or protected in output.parents:
            raise ValueError("Output must be outside the reference source and clean game asset folders")
    # Validate the runtime before doing any expensive or partial generation.
    if mode == "mod":
        if not backend or not save_id or not save_id.strip():
            raise ValueError("A reviewed native LAS backend and a save identity are required")
        backend = verify_backend(backend, manifest, build_id,
                                 hashlib.sha256((Path(exefs) / 'main').read_bytes()).hexdigest(), save_id, team)
    contract = generator_contract(manifest)
    patched_backend = mode == 'mod' and 'main' in backend_files(backend)
    if mode in {'native-checks','native-development','play'} or patched_backend:
        if not save_id or not save_id.strip():
            raise ValueError('Native check testing requires an explicit copied-save identity')
        from native_plan import compile_plan
        contract = compile_plan(contract)
        if patched_backend:
            metadata=json.loads((backend/'backend.json').read_text())
            if metadata.get('check_plan_digest') != contract['native_check_plan']['digest']:
                raise ValueError('Native backend physical marker plan mismatch')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="las-ap-", dir=output.parent) as temporary:
        stage = Path(temporary) / "package"
        stage.mkdir()
        contract_path = stage / "generator_input.json"
        contract_path.write_text(json.dumps(contract, indent=2, sort_keys=True), encoding="utf-8")
        (stage / "seed.lasap").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        report = {"mode": mode, "build_id": build_id, "identity": manifest["identity"],
                  "manifest_digest": manifest["manifest_digest"], "native_backend_included": mode == "mod",
                  "live_game_validated": False, "generator_completed": False,
                  "warning": "Native LAS hooks and live testing are required for Archipelago gameplay."}
        report['experimental_shell_world_visuals']=bool(world_visuals)
        if mode != "prepare":
            command = [str(patch_python), "-u", "-X", "faulthandler", str(ROOT / "scripts/patch_worker.py"),
                       str(source), str(romfs), str(stage / "generated"), str(contract_path)]
            if world_visuals:command.append('--world-visuals')
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding="utf-8", errors="replace")
            if log:
                log(result.stdout)
            if result.returncode:
                raise ValueError(f"LAS generator failed (exit {result.returncode}):\n{result.stdout[-8000:]}")
            report["generator_completed"] = True
            (stage / "generator.log").write_text(result.stdout, encoding="utf-8")
            if mode == "mod":
                mod = stage / "generated"
                if patched_backend:
                    audit=json.loads((mod/'native-marker-audit.json').read_text())
                    if not audit['serialized_coverage_complete']:
                        raise ValueError('Incomplete generated native check markers')
                # Deploy only the original patch targeting this exact executable.
                patches = list((mod / "exefs").glob("*.pchtxt"))
                matching = [patch for patch in patches
                            if f"@NSOBID-{build_id}" in patch.read_text(encoding="utf-8").upper()]
                if not matching:
                    raise ValueError("LAS generator did not produce a patch for the selected executable")
                for patch in patches:
                    if patch not in matching:
                        patch.unlink()
                for name in backend_files(backend):
                    shutil.copyfile(backend / name, mod / "exefs" / name)
                config = {**contract["native_config"]["runtime_config"], "build_id": build_id,
                          "save_id": save_id, "team": team, "actions": contract["native_config"]["actions"]}
                (mod / "romfs/ap_config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
                (mod / "seed.lasap").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            elif mode in {'native-checks','native-development','play'}:
                audit = json.loads((stage / 'generated/native-marker-audit.json').read_text())
                if not audit['serialized_coverage_complete']:
                    raise ValueError('The LAS generator did not preserve all managed check markers')
                native_source = ROOT / 'native'
                # Development tree and self-contained delivery use the same builder.
                if not (native_source / 'build.py').is_file():
                    native_source = ROOT.parent / 'las_native'
                plan_path = stage / 'native-check-plan.json'
                plan_path.write_text(json.dumps(contract['native_check_plan'], indent=2))
                native_output = stage / 'native-build'
                command = [str(patch_python), str(native_source / 'build.py'),
                           '--exefs', str(Path(exefs).resolve()), '--out', str(native_output),
                           '--save-probe', '--managed-plan', str(plan_path),
                           '--mod-romfs', str(stage / 'generated/romfs'), '--save-id', save_id]
                if mode in {'native-development','play'}:
                    command+=['--bridge-manifest',str(stage/'seed.lasap'),'--clean-romfs',str(romfs),'--las-source',str(source)]
                if mode=='play':command+=['--validation-candidate']
                if world_visuals:command+=['--world-visuals']
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, encoding='utf-8', errors='replace')
                if log: log(result.stdout)
                if result.returncode:
                    raise ValueError('Native check build failed:\n' + result.stdout[-8000:])
                if world_visuals:
                    commands=[
                        [str(patch_python),str(native_source/'test_native.py'),str(native_output)],
                        [str(patch_python),str(native_source/'test_world_visuals.py'),str(native_output),
                         '--mod',str(stage/'generated'),'--clean-romfs',str(Path(romfs).resolve()),'--plan',str(plan_path)]]
                    for index,check in enumerate(commands):
                        checked=subprocess.run(check,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace')
                        (stage/f'world-visual-tests-{index}.log').write_text(checked.stdout,encoding='utf-8')
                        if log:log(checked.stdout)
                        if checked.returncode:raise ValueError('Experimental shell validation failed; no test mod published:\n'+checked.stdout[-8000:])
                if mode=='play':
                    validation_path=native_output/'protocol-validation.json'
                    command=[str(patch_python),str(native_source/'test_native.py'),str(native_output),'--report-json',str(validation_path)]
                    result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                                          text=True,encoding='utf-8',errors='replace')
                    if log:log(result.stdout)
                    (stage/'native-tests.log').write_text(result.stdout,encoding='utf-8')
                    if result.returncode or not validation_path.is_file():
                        raise ValueError('Native validation failed; no game mod was published:\n'+result.stdout[-8000:])
                    validation=json.loads(validation_path.read_text())
                    proof_rules=runpy.run_path(str(native_source/'validation.py'))
                    proven=proof_rules['verified_capabilities'](validation.get('passed',[]),validation.get('success') is True)
                    required={'atomic_delivery_v1','persistent_checks_v1','reward_suppression_v1','victory_v1',
                              'indexed_rewards_v1','progressive_rewards_v1','dungeon_rewards_v1'}
                    native_report=json.loads((native_output/'probe_report.json').read_text())
                    if not validation.get('success') or not required<=set(proven) or proven!=validation.get('verified_capabilities'):
                        raise ValueError('The native tests did not verify every required protocol capability')
                    extra=[]
                    if native_report.get('death_link_enabled'):extra.append('test_deathlink_command_is_idempotent_and_does_not_advance_item_receipts')
                    if native_report.get('hint_count'):extra.append('test_native_hint_requests_are_bounded_idempotent_and_wait_for_dialog_completion')
                    if native_report.get('shell_checks') or native_report.get('direct_item_checks'):extra.append('test_direct_shop_checks_and_shell_sources_do_not_grant_inventory')
                    if not set(extra)<=set(validation.get('passed',[])):
                        raise ValueError('A selected native feature was not exercised by validation')
                    metadata={'protocol':1,'layout':'patched_main_module_v1','build_id':build_id,
                              'source_digest':manifest['source_digest'],'manifest_digest':manifest['manifest_digest'],
                              'save_id':save_id,'team':team,'capabilities':sorted(required),
                              'original_main_sha256':native_report['original_main_sha256'],
                              'check_plan_digest':contract['native_check_plan']['digest'],
                              'supported_location_ids':[r['location_id'] for r in manifest['placements']],
                              'supported_item_ids':list(native_report['bridge_supported_items'].values()),
                              'files':validation['files'],'validation_level':'automated-beta',
                              'full_playthrough_validated':False}
                    metadata_path=native_output/'mod/exefs/backend.json'
                    metadata_path.write_text(json.dumps(metadata,indent=2))
                    verify_backend(metadata_path.parent,manifest,build_id,
                                   hashlib.sha256((Path(exefs)/'main').read_bytes()).hexdigest(),save_id,team)
                    report.update(protocol_capabilities=sorted(required),validation_level='automated-beta',
                                  native_tests_run=validation['tests_run'],native_tests_passed=len(validation['passed']),
                                  native_tests_skipped=len(validation['skipped']),full_playthrough_validated=False)
                mod = stage / 'generated'
                matching = []
                for patch in (mod / 'exefs').glob('*.pchtxt'):
                    if f'@NSOBID-{build_id}' in patch.read_text(encoding='utf-8').upper():
                        matching.append(patch)
                    else: patch.unlink()
                if not matching: raise ValueError('No matching LAS executable patch was generated')
                for name in ('main', 'subsdk9'):
                    shutil.copyfile(native_output / 'mod/exefs' / name, mod / 'exefs' / name)
                report.update(native_backend_included=True, native_checks_only=mode=='native-checks', native_delivery_development=mode=='native-development',
                              managed_checks=audit['managed_count'], playable_archipelago=mode=='play')
                if mode=='play':report['warning']='Beta: automated protocol checks passed; a complete live playthrough remains unvalidated.'
                (mod / 'seed.lasap').write_text(json.dumps(manifest, indent=2))
                config={**contract['native_config']['runtime_config'],'build_id':build_id,
                        'save_id':save_id,'team':team}
                (mod/'romfs/ap_config.json').write_text(json.dumps(config,indent=2))
                mod.rename(stage / ('ARCHIPELAGO_GAME' if mode=='play' else 'COPIED_SAVE_NATIVE_DEVELOPMENT' if mode=='native-development' else 'COPIED_SAVE_CHECK_TEST_ONLY'))
            else:
                # The baseline contains vanilla rewards. Never present it as an AP mod.
                (stage / "generated").rename(stage / "DIAGNOSTIC_ONLY_NOT_AN_AP_MOD")
        (stage / "build_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        (stage / "READ_ME.txt").write_text(
            "LAS Archipelago patch preparation\n\n" +
            ("Archipelago beta game build. Use a fresh save.\n"
             "All required native protocol tests passed for these exact binaries.\n"
             "A complete live playthrough remains unvalidated.\n" if mode=='play' else
             "Native integration development build. COPIED SAVES ONLY.\n"
             "Native network delivery is included; live validation remains incomplete.\n" if mode=='native-development' else
             "Native checks development build. COPIED SAVES ONLY.\n"
             "Managed rewards are suppressed; AP item delivery is not enabled.\n" if mode == 'native-checks' else
             "Reviewed backend supplied. Live in-game validation is still required.\n" if mode == "mod" else
             "This is NOT a playable Archipelago mod. Do not install the diagnostic baseline in Ryujinx.\n"
             "It uses vanilla rewards as generator input; the native module must suppress these at runtime.\n") +
            "The .lasap placements are authoritative; no second randomization was performed.\n",
            encoding="utf-8")
        stage.rename(output)
    return report
