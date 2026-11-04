import copy
from collections import Counter
import json
from pathlib import Path
import tempfile
import unittest

from Fill import distribute_items_restrictive
from test.general import setup_multiworld
from worlds.las_switch import LASWorld
from worlds.las_switch.core.configuration import defaults,validate,las_settings
from worlds.las_switch.core.data import ITEMS,NODES,content
from worlds.las_switch.core.patcher import generator_contract
from worlds.las_switch.core.seed import sha,canonical_manifest,validate_manifest

class ExpandedOptions(unittest.TestCase):
    def world(self,options=None,seed=555):
        return setup_multiworld(LASWorld,options=options or {},seed=seed)

    def manifest(self,mw):
        mw.seed_name='options-test';distribute_items_restrictive(mw)
        self.assertTrue(mw.can_beat_game())
        with tempfile.TemporaryDirectory() as temp:
            mw.worlds[1].generate_output(temp)
            return validate_manifest(json.loads(next(Path(temp).glob('*.lasap')).read_text()))

    def test_mansion_tiers_change_actual_check_set(self):
        for tier,count in ((0,278),(5,279),(15,280),(30,281),(40,282),(50,283)):
            mw=self.world({'check_profile':'configured','seashell_mansion':tier})
            self.assertEqual(len(mw.get_locations()),count)
            self.assertTrue(all(int(l.name.split('-')[0])<=tier for l in mw.get_locations() if l.name.endswith('-seashell-reward')))

    def test_owl_choices_choose_actual_regions_and_logic_flags(self):
        for choice,expected in (('none',283),('overworld',292),('dungeons',307),('all',316)):
            mw=self.world({'check_profile':'configured','owl_gifts':choice})
            self.assertEqual(len(mw.get_locations()),expected)
            flags=mw.worlds[1].logic.flags
            self.assertEqual(flags['owl-overworld-gifts'],choice in ('overworld','all'))
            self.assertEqual(flags['owl-dungeon-gifts'],choice in ('dungeons','all'))

    def test_qol_and_world_options_reach_original_las_generator(self):
        options={'fast_fishing':True,'fast_stalfos':True,'blur_removal':True,'fast_stealing':True,
                 'fast_boss_cutscenes':True,'fast_song_cutscenes':True,'fast_chest_animations':True,
                 'fast_key_animations':True,'randomize_enemies':True,'randomize_enemy_sizes':True,
                 'nice_magic_rod':True,'sword_beam_with_lv1':True,'one_hit_ko':True,
                 'chest_appearance':'texture_and_size','stealing':'never','open_kanalet':False}
        mw=self.world(options);manifest=self.manifest(mw)
        settings=generator_contract(manifest)['placements']['settings']
        for name in ('fast-fishing','fast-stalfos','blur-removal','fast-stealing','boss-cutscenes','fast-songs',
                     'fast-chests','fast-keys','randomize-enemies','randomize-enemy-sizes','nice-rod','lv1-beam','OHKO'):
            self.assertTrue(settings[name],name)
        self.assertEqual(settings['chest-aspect'],'camc');self.assertEqual(settings['stealing'],'never')
        self.assertFalse(settings['open-kanalet'])
        self.assertTrue(mw.worlds[1].logic.flags['fast-master-stalfos'])

    def test_starting_quantities_remove_pool_entries_and_use_ap_precollection(self):
        starts={'sword':1,'bracelet':2,'shield':1}
        mw=self.world({'starting_items':starts})
        world=mw.worlds[1];pool=Counter(i.name for i in mw.itempool)
        original=Counter(content(name) for name in world.active)
        self.assertEqual(Counter(i.name for i in mw.precollected_items[1]),Counter(starts))
        self.assertEqual(len(mw.itempool),len(world.active))
        for name,count in starts.items():self.assertEqual(pool[name],original[name]-count)
        manifest=self.manifest(mw)
        self.assertEqual(manifest['starting_items'],starts)
        self.assertEqual(generator_contract(manifest)['placements']['settings']['starting-items'],[])

    def test_whitelist_locks_unlisted_items_at_vanilla_checks(self):
        whitelist={'sword','shield','bracelet'}
        mw=self.world({'randomized_items':whitelist})
        world=mw.worlds[1]
        self.assertEqual(len(mw.get_locations()),6)
        self.assertTrue(all(content(loc.name) in whitelist for loc in mw.get_locations()))
        self.assertNotIn('D1-west-hallway',world.active)
        self.assertTrue(world.logic.can_reach({'sword':1,'shield':1,'bracelet':1},'D1-west-hallway'))
        self.manifest(mw)

    def test_invalid_starting_items_and_quantities_are_rejected(self):
        for starts in ({'sword':3},{'sword':0},{'sword':True},{'not-an-item':1}):
            with self.subTest(starts=starts),self.assertRaises(ValueError):self.world({'starting_items':starts})
        with self.assertRaises(ValueError):self.world({'starting_items':{'sword':1},'randomized_items':{'shield'}})

    def test_trap_levels_mutate_ap_pool_not_original_las_shuffle(self):
        for level,count in (('none',0),('few',3),('several',9),('many',17)):
            mw=self.world({'traps':level})
            animated=[i for i in mw.itempool if i.name.endswith('-trap') and i.name!='zol-trap']
            self.assertEqual(len(animated),count)
            manifest=self.manifest(mw)
            self.assertEqual(manifest['player_settings']['traps'],level)
            self.assertEqual(generator_contract(manifest)['placements']['settings']['traps'],'none')

    def test_shuffled_entrances_share_the_exact_logic_and_generator_permutation(self):
        for seed in (101,202,303):
            mw=self.world({'shuffled_dungeons':True},seed)
            world=mw.worlds[1]
            self.assertTrue(any(k!=v for k,v in world.entrances.items()))
            from worlds.las_switch.core.logic import parse
            for entrance,destination in world.entrances.items():
                self.assertEqual(world.logic.conditions[destination,'condition-basic'],parse(NODES[entrance]['condition-basic']))
            manifest=self.manifest(mw);contract=generator_contract(manifest)
            self.assertEqual(contract['placements']['dungeon-entrances'],world.entrances)
            self.assertTrue(contract['placements']['settings']['shuffle-dungeons'])

    def test_manifest_rejects_settings_that_do_not_match_generator_flags(self):
        manifest=self.manifest(self.world({'fast_fishing':True}))
        changed=copy.deepcopy(manifest);changed['player_settings']['fast_fishing']=False
        changed['manifest_digest']=sha(canonical_manifest(changed))
        with self.assertRaises(ValueError):validate_manifest(changed)

    def test_shuffled_bombs_and_powder_are_progression(self):
        mw=self.world({'shuffled_bombs':True,'shuffled_powder':True})
        self.assertTrue(mw.worlds[1].create_item('bomb').advancement)
        self.assertTrue(mw.worlds[1].create_item('powder').advancement)
