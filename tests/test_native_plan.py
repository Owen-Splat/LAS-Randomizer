import copy
import unittest
import test_patch_pipeline as fixtures
from native_plan import compile_plan, MARKER_BASE


class NativePlanTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.PatchPipelineTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.contract = fixtures.pipeline.generator_contract(fixture.manifest)

    def test_deterministic_markers_preserve_manifest_and_unmanaged_rewards(self):
        before = copy.deepcopy(self.contract)
        result = compile_plan(self.contract)
        self.assertEqual(self.contract, before)
        self.assertEqual(result, compile_plan(self.contract))
        self.assertEqual(result['native_config'], before['native_config'])
        checks = result['native_check_plan']['checks']
        self.assertEqual(len(checks), 228)
        self.assertEqual([r['marker'] for r in checks], list(range(MARKER_BASE, MARKER_BASE + 228)))
        self.assertEqual(len({r['location_id'] for r in checks}), 228)
        names = {r['location'] for r in checks}
        for name, value in before['placements'].items():
            if name not in names and name != 'indexes':
                self.assertEqual(result['placements'][name], value)
        for row in checks:
            self.assertEqual(result['placements'][row['location']], 'AP_Check_'+str(row['location_id']))
            self.assertEqual(result['placements']['indexes'][row['location']], row['marker'])

    def test_rejects_state_capacity_overflow(self):
        self.contract['native_config']['actions']=[copy.deepcopy(self.contract['native_config']['actions'][0]) for _ in range(353)]
        with self.assertRaisesRegex(ValueError, 'capacity'):
            compile_plan(self.contract)
