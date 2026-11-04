import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock

from Fill import distribute_items_restrictive
from NetUtils import NetworkItem
from test.general import setup_multiworld
from worlds.las_switch import LASWorld
from worlds.las_switch.client import LASContext
from worlds.las_switch.client_model import snapshot
from worlds.las_switch.core.data import ITEM_IDS
from worlds.las_switch.core.seed import sha
from worlds.las_switch.core.runtime import history_rows

class ClientFeatures(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        mw=setup_multiworld(LASWorld,options={'death_link':True},seed=7788)
        mw.seed_name='client-features';distribute_items_restrictive(mw)
        with tempfile.TemporaryDirectory() as temp:
            mw.worlds[1].generate_output(temp)
            cls.manifest=json.loads(next(Path(temp).glob('*.lasap')).read_text())

    async def asyncSetUp(self):
        self.ctx=LASContext(copy.deepcopy(self.manifest),build_id='MOCK',save_id='client-test',allow_mock=True)
        self.ctx.ap_validated=self.ctx.history_ready=True
        self.ctx.slot=1;self.ctx.team=0
        self.ctx.player_names={0:'Starting items',1:'LinkPlayer',2:'Friend'}
        self.ctx.tags={'AP','DeathLink'}
        self.ctx.bridge.hello={'team':0,'supports_deathlink':True}
        self.ctx.bridge.state={'t':'state','cursor':0,'history_hash':sha([]),'checks':[],'ready':True,
                               'victory':False,'alive':True,'deathlink_ack':0,'deathlink_busy':False}
        self.ctx.bridge.send=AsyncMock(return_value=True)
        self.ctx.send_death=AsyncMock()

    async def asyncTearDown(self):await self.ctx.shutdown()

    async def test_status_history_and_tracker_use_delivered_not_queued_inventory(self):
        ctx=self.ctx
        ctx.items_received=[NetworkItem(ITEM_IDS['sword'],self.manifest['placements'][0]['location_id'],2)]
        before=snapshot(ctx)
        self.assertEqual(before['pending'],1)
        self.assertEqual(before['history'][0]['sender'],'Friend')
        self.assertFalse(before['history'][0]['delivered'])
        ctx.bridge.state.update(cursor=1,history_hash=sha(history_rows(ctx.items_received)))
        after=snapshot(ctx)
        self.assertEqual(after['pending'],0);self.assertTrue(after['history'][0]['delivered'])
        self.assertEqual(len(after['tracker']),len(self.manifest['placements']))
        ctx.bridge.state['history_hash']='bad'
        blocked=snapshot(ctx)
        self.assertFalse(blocked['history_validated']);self.assertIsNone(blocked['pending'])
        self.assertFalse(any(r['reachable'] for r in blocked['tracker']))

    async def test_deathlink_sends_once_per_local_death_transition(self):
        await self.ctx.deathlink_state({'alive':True})
        await self.ctx.deathlink_state({'alive':False})
        await self.ctx.deathlink_state({'alive':False})
        self.ctx.send_death.assert_awaited_once()
        await self.ctx.deathlink_state({'alive':None})
        await self.ctx.deathlink_state({'alive':False})
        self.ctx.send_death.assert_awaited_once()

    async def test_received_death_queues_until_ready_and_does_not_echo(self):
        ctx=self.ctx;ctx.last_alive=True
        ctx.on_deathlink({'time':12345.0,'source':'Friend','cause':'A test death'})
        nonce=ctx.remote_death['nonce']
        ctx.bridge.state['ready']=False
        self.assertTrue(await ctx.pump_deathlink());ctx.bridge.send.assert_not_awaited()
        ctx.bridge.state['ready']=True
        await ctx.pump_deathlink()
        ctx.bridge.send.assert_awaited_once_with({'t':'deathlink','nonce':nonce})
        ctx.bridge.state.update(deathlink_ack=nonce,alive=False,ready=False)
        await ctx.deathlink_state(ctx.bridge.state)
        self.assertIsNone(ctx.remote_death);ctx.send_death.assert_not_awaited()

    async def test_delayed_remote_death_stays_latched_after_ack(self):
        ctx=self.ctx;ctx.last_alive=True
        ctx.on_deathlink({'time':12346.0,'source':'Friend'})
        nonce=ctx.remote_death['nonce']
        ctx.bridge.state.update(deathlink_ack=nonce,deathlink_busy=True)
        await ctx.deathlink_state(ctx.bridge.state);await ctx.pump_deathlink()
        self.assertTrue(ctx.remote_death_latched)
        ctx.last_remote_death_at=0
        ctx.bridge.state.update(alive=False,deathlink_busy=False)
        await ctx.deathlink_state(ctx.bridge.state)
        ctx.send_death.assert_not_awaited()

    async def test_unvalidated_game_history_cannot_send_deathlink(self):
        ctx=self.ctx;ctx.last_alive=True
        bad=dict(ctx.bridge.state,history_hash='bad',alive=False)
        with self.assertRaises(ValueError):await ctx.game_state(bad)
        ctx.send_death.assert_not_awaited()

    async def test_disabled_deathlink_does_not_join_or_act(self):
        ctx=self.ctx;ctx.death_link_enabled=False
        ctx.on_deathlink({'time':12345.0,'source':'Friend'})
        self.assertIsNone(ctx.remote_death)
        await ctx.pump_deathlink();self.assertNotIn('DeathLink',ctx.tags)
        ctx.bridge.send.assert_not_awaited()

    async def test_outgoing_item_history_records_recipient(self):
        ctx=self.ctx
        ctx.on_print_json({'type':'ItemSend','data':[], 'item':NetworkItem(ITEM_IDS['sword'],1,1),'receiving':2})
        self.assertEqual(len(ctx.outgoing_history),1)
        self.assertIn('Friend',ctx.outgoing_history[0]['text'])

    async def test_in_game_hints_require_an_actual_server_hint_and_wait_for_ack(self):
        ctx=self.ctx;ctx.bridge.hello['supports_hints']=True
        route=ctx.manifest['hint_routes'][0]
        self.assertFalse(ctx.request_game_hint(route['index']))
        ctx.stored_data['_read_hints_0_1']=[{'finding_player':route['finding_player'],'location':route['location_id'],
                                          'receiving_player':route['recipient_slot'],'item':route['item_id'],'found':False}]
        self.assertEqual([r['index'] for r in ctx.available_game_hints()],[route['index']])
        self.assertTrue(ctx.request_game_hint(route['index']))
        nonce=ctx.pending_hint['nonce']
        ctx.bridge.state['ready']=False
        self.assertTrue(await ctx.pump_hint());ctx.bridge.send.assert_not_awaited()
        ctx.bridge.state['ready']=True
        await ctx.pump_hint()
        ctx.bridge.send.assert_awaited_once_with({'t':'hint','index':route['index'],'nonce':nonce})
        ctx.bridge.state['hint_ack']=nonce
        self.assertFalse(await ctx.pump_hint());self.assertIsNone(ctx.pending_hint)

    async def test_mismatched_hint_item_or_recipient_cannot_reveal_a_route(self):
        ctx=self.ctx;ctx.bridge.hello['supports_hints']=True
        route=ctx.manifest['hint_routes'][0]
        ctx.stored_data['_read_hints_0_1']=[{'finding_player':route['finding_player'],'location':route['location_id'],
                                          'receiving_player':999,'item':route['item_id'],'found':False}]
        self.assertEqual(ctx.available_game_hints(),[])
        self.assertFalse(ctx.request_game_hint(route['index']))
        self.assertIsNone(ctx.pending_hint)
