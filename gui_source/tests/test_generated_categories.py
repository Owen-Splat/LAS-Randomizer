"""Inspect generated standalone game assets without distributing them.

Set LAS_TEST_MOD to a fresh standalone generated mod folder.
"""
import json
import os
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from RandomizerCore.Tools import oead_tools as o,event_tools as e
from RandomizerCore.Tools.msbt import Msbt

BUILD=os.environ.get('LAS_TEST_MOD')

@unittest.skipUnless(BUILD,'Set LAS_TEST_MOD to inspect private generated game assets')
class GeneratedCategories(unittest.TestCase):
    def setUp(self):self.root=Path(BUILD);self.romfs=self.root/'romfs'
    def sheet(self,name):return o.readSheet(self.romfs/'region_common/datasheets'/name)

    def test_prize_rows_keep_native_indexes_and_nonempty_layouts(self):
        rows=self.sheet('CranePrize.gsheet')['values']
        self.assertEqual(len(rows),27)
        self.assertTrue(all(len(r['layouts']) for r in rows))
        for row in rows[-6:]:
            self.assertTrue((self.romfs/'region_common/actor'/('Prize'+row['symbol']+'.bfres')).is_file())
            self.assertFalse(row['options']['isAutoSave'])
            self.assertTrue(row['layouts'][0]['itemIndex']&0xFFFF0000==0x53430000)
        for row in rows:
            if row['symbol'] in ('YoshiDoll','HeartPiece','SecretSeashell','PanelDungeonPiece'):
                for layout in row['layouts']:
                    self.assertIn('LAS_CraneOriginalOff',[c['parameter'] for c in layout['conditions']])

    def test_all_source_and_pending_flags_are_distinct_and_present(self):
        flags=self.sheet('GlobalFlags.gsheet')['values']
        symbols=[r['symbol'] for r in flags];indexes=[r['index'] for r in flags]
        self.assertEqual(len(symbols),len(set(symbols)))
        self.assertEqual(len(indexes),len(set(indexes)))
        custom=[r for r in flags if r['symbol'].startswith(('LASPickup_','LASShop','LAS_Crane'))]
        self.assertEqual(len(custom),65)
        self.assertTrue(all(1248<=r['index']<2048 for r in custom))
        sources=json.loads((self.root/'native-build/sources.json').read_text())
        self.assertEqual(len(sources),48)
        self.assertTrue(all(r['flag'] in indexes for r in sources))

    def test_shop_shelves_prices_and_pending_theft_flows_exist(self):
        sheet=self.sheet('ShopItem.gsheet')
        goods=[g for slot in sheet['values'] for g in slot['mGoods'] if g['mItem'].startswith('LASShopGoods_')]
        self.assertEqual(len(goods),10)
        items=self.sheet('Items.gsheet')['values']
        dummies=[r for r in items if r['symbol'].startswith('LASShopGoods_')]
        self.assertEqual({r['itemID'] for r in dummies},set(range(230,240)))
        self.assertFalse(any(r['symbol'].startswith('AP_') for r in items))
        files=list(self.romfs.rglob('System.msbt'));self.assertTrue(files)
        for path in files:
            messages=Msbt(path.read_bytes())
            for i in range(10):
                self.assertIn('LASShopGoods_'+str(i)+'_Price',messages.texts)
                self.assertIn('LASShopGoods_'+str(i)+'_Buy',messages.texts)
        flow=e.readFlow(self.romfs/'region_common/event/PlayerStart.bfevfl')
        parameters=[event.data.params.data for event in flow.flowchart.events if getattr(event.data,'params',None) is not None]
        for i in range(10):self.assertTrue(any(p.get('symbol')=='LASShopPending_'+str(i) for p in parameters))

    def test_real_indexed_event_grants_are_tagged_and_no_ap_markers_are_present(self):
        grants=0
        for path in self.romfs.rglob('*.bfevfl'):
            flow=e.readFlow(path)
            for event in flow.flowchart.events:
                data=event.data
                if getattr(data,'params',None) is None:continue
                p=data.params.data
                index=p.get('index')
                if not isinstance(index,int):continue
                self.assertFalse(0x4C410000<=index<0x4C430000)
                if hasattr(data,'actor_action') and data.actor_action.v.v=='AddItemByKey' and p.get('itemKey') in ('Seashell','HeartPiece') and index>=0:
                    self.assertEqual(index&0xFFFF0000,0x53470000)
                    grants+=1
        self.assertGreater(grants,0)

if __name__=='__main__':unittest.main()
