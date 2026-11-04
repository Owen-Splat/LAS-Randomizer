"""Check that shared pickup code retains each location's original behavior."""
import ast
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]


def load_functions(path, names, namespace):
    tree = ast.parse(path.read_text())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), 'exec'), namespace)


class CleanupRegressions(unittest.TestCase):
    def test_invalid_generated_event_keeps_the_original_error(self):
        import sys
        import tempfile
        from unittest.mock import patch
        sys.path.insert(0, str(ROOT))
        from RandomizerCore.Randomizers.indexed_pickups import StandaloneRewards

        with tempfile.TemporaryDirectory() as temporary:
            generated_event = Path(temporary) / 'Broken.bfevfl'
            generated_event.write_bytes(b'invalid event')
            worker = SimpleNamespace(romfs_dir=temporary, writeFile=Mock())
            rewards = StandaloneRewards.__new__(StandaloneRewards)
            rewards.worker = worker
            rewards.flags = {}
            rewards.sources = [{'item': 58}]
            original_error = ValueError('broken event contents')
            with patch('RandomizerCore.Randomizers.indexed_pickups.event_tools.readFlow', side_effect=original_error):
                with self.assertRaisesRegex(ValueError, 'Invalid generated event flow') as failure:
                    rewards.finish()
            self.assertIs(failure.exception.__cause__, original_error)

    def test_loose_pickups_keep_actor_identity_flags_models_and_reward_paths(self):
        variants = (
            ('changeMushroom', 3, 0x194, 'Woods', 'WOODS_LOOSE_FLAG', False),
            ('changeOcarina', 5, 0x8E, 'DreamShrine', 'DREAM_SHRINE_FLAG', False),
            ('changeBirdKey', 0, 0x194, 'TalTal', 'ROOSTER_CAVE_FLAG', False),
            ('changeLens', 7, 0x194, 'MermaidCave', 'MERMAID_CAVE_FLAG', True),
        )
        for source_folder in ('',):
            for function, actor_index, actor_type, entry_point, flag, resets_rotation in variants:
                for item in ('Rupee20', 'Seashell', 'HookShot'):
                    for custom_model in (False, True):
                        with self.subTest(folder=source_folder, pickup=function, item=item, custom_model=custom_model):
                            events = Mock()
                            events.createActionEvent.return_value = 'plain_reward'
                            item_get = Mock()
                            item_get.insertItemGetAnimation.return_value = 'animated_reward'
                            namespace = {'event_tools': events, 'item_get': item_get,
                                         'MODEL_SIZES': {'Custom': 1.5}, 'MODEL_ROTATIONS': {'Custom': 90}}
                            namespace.update({variant[4]: variant[4] for variant in variants})
                            load_functions(ROOT/source_folder/'RandomizerCore/Randomizers/miscellaneous.py',
                                           {variant[0] for variant in variants} | {'_change_loose_pickup'}, namespace)
                            actors = [SimpleNamespace(type=0, rotY=45, scaleX=1, scaleY=1, scaleZ=1,
                                                      parameters=[b'unchanged']*5) for _ in range(8)]
                            room = SimpleNamespace(actors=actors)
                            flowchart = object()
                            model = 'Custom' if custom_model else 'Ordinary'
                            namespace[function](flowchart, item, 7, 'Item.bfres', model, room)
                            actor = actors[actor_index]
                            self.assertEqual(actor.type, actor_type)
                            self.assertEqual(actor.parameters, [b'Item.bfres', model.encode(), entry_point.encode(),
                                                               flag.encode(), b'true' if item == 'Seashell' else b'false'])
                            self.assertEqual(actor.rotY, 90 if custom_model else 0 if resets_rotation else 45)
                            self.assertEqual((actor.scaleX, actor.scaleY, actor.scaleZ), (1.5,)*3 if custom_model else (1,)*3)
                            self.assertTrue(all(other.type == 0 for index, other in enumerate(actors) if index != actor_index))
                            events.addEntryPoint.assert_called_once_with(flowchart, entry_point)
                            reward = 'plain_reward' if item.startswith('Rup') else 'animated_reward'
                            events.createActionChain.assert_called_once_with(flowchart, entry_point, [
                                ('SinkingSword', 'Destroy', {}),
                                ('EventFlags', 'SetFlag', {'symbol': flag, 'value': True})], reward)
                            if item.startswith('Rup'):
                                events.createActionEvent.assert_called_once_with(flowchart, 'Inventory', 'AddItemByKey',
                                    {'itemKey': item, 'count': 1, 'index': 7, 'autoEquip': False})
                                item_get.insertItemGetAnimation.assert_not_called()
                            else:
                                item_get.insertItemGetAnimation.assert_called_once_with(flowchart, item, 7)

    def test_invalid_saved_widget_value_is_reported_and_other_settings_load(self):
        import logging
        for source_folder in ('',):
            namespace = {'logging': logging, '__name__': 'settings_cleanup_test', 'SETTINGS': {},
                         'BASE_OPTIONS': {'brokenCheck': False, 'validCheck': False}, 'EXTRA_OPTIONS': [],
                         'PLATFORMS': ['console'], 'TOTAL_CHECKS': set(), 'STARTING_ITEMS': []}
            load_functions(ROOT/source_folder/'RandomizerUI/settings_manager.py', {'loadSettings'}, namespace)
            broken = Mock()
            broken.setChecked.side_effect = TypeError('invalid saved value')
            valid = Mock()
            window = SimpleNamespace(ui=SimpleNamespace(brokenCheck=broken, validCheck=valid, platformComboBox=Mock()))
            with self.assertLogs('settings_cleanup_test', level='WARNING') as warnings:
                namespace['loadSettings'](window, {'brokenCheck': True, 'validCheck': True,
                                                   'excluded_locations': [], 'starting_gear': []})
            self.assertIn('brokenCheck', warnings.output[0])
            valid.setChecked.assert_called_once_with(True)


if __name__ == '__main__':
    unittest.main()
