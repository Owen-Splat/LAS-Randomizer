import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "apworld"))
import patch_pipeline as pipeline
data = pipeline.import_module(pipeline.PACKAGE + ".core.data")
GAME, ITEM_IDS, LOCATION_IDS = data.GAME, data.ITEM_IDS, data.LOCATION_IDS
active_locations, content = data.active_locations, data.content
make_manifest = pipeline.import_module(pipeline.PACKAGE + ".core.seed").make_manifest


class PatchPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.romfs = self.root / "romfs"
        for name in ("region_common/level/Field/Field_08B.leb", "region_common/event/PlayerStart.bfevfl"):
            path = self.romfs / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"test asset")
        self.exefs = self.root / "exefs"
        self.exefs.mkdir()
        header = bytearray(0x100)
        header[:4] = b"NSO0"
        header[0x40:0x54] = bytes.fromhex("AE16F71E002AF8CB059A9A74C4D90F34BA984892")
        (self.exefs / "main").write_bytes(header)
        rows = [dict(location=name, location_id=LOCATION_IDS[name], recipient_slot=1,
                     item_id=ITEM_IDS[content(name)], item_name=content(name), item_game=GAME)
                for name in active_locations()]
        self.manifest = make_manifest(dict(seed="pipeline-test", slot=1, slot_name="Link"), "standard", rows)
        self.path = self.root / "seed.lasap"
        self.path.write_text(json.dumps(self.manifest), encoding="utf-8")
        self.source = ROOT / "source"
        self.output = self.root / "new-output"

    def run_pipeline(self, **kwargs):
        return pipeline.generate(self.path, self.source, self.romfs, self.exefs, self.output, **kwargs)

    def test_preparation_preserves_ap_placements_and_input_files(self):
        before = (self.path.read_bytes(), (self.exefs / "main").read_bytes())
        report = self.run_pipeline()
        saved = json.loads((self.output / "seed.lasap").read_text())
        contract = json.loads((self.output / "generator_input.json").read_text())
        self.assertEqual(saved, self.manifest)
        self.assertEqual(contract["native_config"]["manifest"], self.manifest)
        self.assertFalse(report["generator_completed"])
        self.assertEqual(before, (self.path.read_bytes(), (self.exefs / "main").read_bytes()))

    def test_existing_output_not_overwritten(self):
        self.output.mkdir()
        marker = self.output / "keep.txt"
        marker.write_text("keep")
        with self.assertRaisesRegex(ValueError, "new output"):
            self.run_pipeline()
        self.assertEqual(marker.read_text(), "keep")

    def test_native_module_required_before_generation(self):
        with patch.object(pipeline.subprocess, "run") as runner:
            with self.assertRaisesRegex(ValueError, "native LAS backend"):
                self.run_pipeline(mode="mod", save_id="save")
            runner.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_wrong_executable_rejected(self):
        (self.exefs / "main").write_bytes(b"not an NSO")
        with self.assertRaisesRegex(ValueError, "NSO"):
            self.run_pipeline()
        self.assertFalse(self.output.exists())

    def test_unknown_executable_build_rejected(self):
        header = bytearray((self.exefs / "main").read_bytes())
        header[0x40:0x54] = b"\xff" * 20
        (self.exefs / "main").write_bytes(header)
        with self.assertRaisesRegex(ValueError, "does not list"):
            self.run_pipeline()

    def test_tampered_patch_rejected(self):
        changed = copy.deepcopy(self.manifest)
        changed["identity"]["slot"] = 2
        self.path.write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, "digest"):
            self.run_pipeline()

    def test_failed_generator_does_not_publish_partial_output(self):
        with patch.object(pipeline.subprocess, "run", return_value=type("Result", (),
                          dict(returncode=1, stdout="native crash diagnostic"))()):
            with self.assertRaisesRegex(ValueError, "native crash diagnostic"):
                self.run_pipeline(mode="test")
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob("las-ap-*")))

    def test_clean_asset_folder_cannot_be_output(self):
        self.output = self.romfs / "new-mod"
        with self.assertRaisesRegex(ValueError, "outside"):
            self.run_pipeline()
        self.assertFalse(self.output.exists())

    def test_native_check_build_requires_save_identity_before_generation(self):
        with patch.object(pipeline.subprocess, 'run') as runner:
            for mode in ('native-checks','native-development'):
                with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, 'copied-save identity'):
                    self.run_pipeline(mode=mode)
            runner.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_play_mode_does_not_publish_a_candidate_that_fails_native_validation(self):
        calls=[]
        def runner(command,**kwargs):
            calls.append(command)
            if any(str(value).endswith('patch_worker.py') for value in command):
                generated=Path(command[-2]);(generated/'romfs').mkdir(parents=True)
                (generated/'exefs').mkdir()
                (generated/'native-marker-audit.json').write_text(json.dumps({'serialized_coverage_complete':True,'managed_count':228}))
                return type('Result',(),{'returncode':0,'stdout':'generator passed'})()
            if '--out' in command:
                Path(command[command.index('--out')+1]).mkdir()
                return type('Result',(),{'returncode':0,'stdout':'candidate compiled'})()
            return type('Result',(),{'returncode':1,'stdout':'required native assertion failed'})()
        with patch.object(pipeline.subprocess,'run',side_effect=runner):
            with self.assertRaisesRegex(ValueError,'no game mod was published'):
                self.run_pipeline(mode='play')
        self.assertEqual(len(calls),3)
        self.assertIn('--validation-candidate',calls[1]);self.assertIn('--report-json',calls[2])
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob('las-ap-*')))

    def test_patched_main_backend_is_bound_to_clean_executable_and_hashes(self):
        backend=self.root/'backend';backend.mkdir()
        capabilities=['atomic_delivery_v1','persistent_checks_v1','reward_suppression_v1',
                      'victory_v1','indexed_rewards_v1','progressive_rewards_v1','dungeon_rewards_v1']
        metadata={'protocol':1,'layout':'patched_main_module_v1',
                  'build_id':pipeline.read_build_id(self.exefs),
                  'source_digest':self.manifest['source_digest'],'capabilities':capabilities,
                  'supported_location_ids':[r['location_id'] for r in self.manifest['placements']],
                  'supported_item_ids':list(ITEM_IDS.values()),
                  'original_main_sha256':hashlib.sha256((self.exefs/'main').read_bytes()).hexdigest(),
                  'manifest_digest':self.manifest['manifest_digest'],'save_id':'test-save','team':0,
                  'files':{}}
        for name in ('main','subsdk9'):
            raw=('unit-test-only:'+name).encode();(backend/name).write_bytes(raw)
            metadata['files'][name]=hashlib.sha256(raw).hexdigest()
        (backend/'backend.json').write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValueError,'clean executable'):
            pipeline.verify_backend(backend,self.manifest,metadata['build_id'],'wrong')
        self.assertEqual(pipeline.verify_backend(backend,self.manifest,metadata['build_id'],
                                               metadata['original_main_sha256'],'test-save',0),backend)
        with self.assertRaisesRegex(ValueError,'seed/save/team'):
            pipeline.verify_backend(backend,self.manifest,metadata['build_id'],
                                    metadata['original_main_sha256'],'wrong-save',0)
        (backend/'main').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'hash mismatch'):
            pipeline.verify_backend(backend,self.manifest,metadata['build_id'],metadata['original_main_sha256'],'test-save',0)

    def test_unknown_backend_layout_rejected(self):
        backend=self.root/'backend';backend.mkdir()
        (backend/'backend.json').write_text(json.dumps({'layout':'../arbitrary-file'}))
        with self.assertRaisesRegex(ValueError,'layout'):
            pipeline.backend_files(backend)
