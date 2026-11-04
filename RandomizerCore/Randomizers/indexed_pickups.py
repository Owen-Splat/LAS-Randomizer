"""Standalone original-actor shell and dive pickups (LAS 1.0.0)."""
from pathlib import Path
from RandomizerCore.Tools import event_tools
from RandomizerCore.Randomizers import item_get
SUNKEN_HEARTS = frozenset(('bay-passage-sunken', 'river-crossing-cave', 'kanalet-moat-south', 'south-bay-sunken', 'taltal-east-drop'))
GRANT_TAG = 0x53470000

def locations(logic):
    return sorted((location_name for location_name, location_details in logic.items() if location_details.get('type') == 'item' and (location_details.get('subtype') in ('dig', 'hidden', 'bomb-hole') or location_name in SUNKEN_HEARTS or (location_details.get('subtype') == 'underwater' and location_details.get('content') == 'seashell'))))

def redirect(flowchart, original_event, new, original_events):
    # Update every existing link that points to the replaced event.
    event_indexes = event_tools.invertList(flowchart.events)
    event_references = [entry_point.main_event for entry_point in flowchart.entry_points]
    for event in original_events:
        event_data = event.data
        if hasattr(event_data, 'nxt'):
            event_references.append(event_data.nxt)
        if hasattr(event_data, 'forks'):
            event_references.extend(event_data.forks)
        if hasattr(event_data, 'cases'):
            event_references.extend(event_data.cases.values())
    for event_reference in event_references:
        if event_reference.v is original_event:
            event_reference.v = new
            event_reference.set_index(event_indexes)

class StandaloneRewards:

    def __init__(self, worker):
        self.worker = worker
        self.flags = worker.readFile('GlobalFlags.gsheet')
        self.used = {int(source_row['index']) for source_row in self.flags['values']}
        self.sources = []

    def flag(self, symbol):
        from RandomizerCore.Tools import oead_tools as sheet_tools
        matching_flags = [int(source_row['index']) for source_row in self.flags['values'] if source_row['symbol'] == symbol]
        if matching_flags:
            return matching_flags[0]
        # Allocate a save flag that is not already used by the game.
        item_index = next((flag_index for flag_index in range(1248, 2048) if flag_index not in self.used), None)
        if item_index is None:
            raise ValueError('No free persistent source flags')
        self.used.add(item_index)
        self.flags['values'].append(sheet_tools.dictToStruct({'symbol': symbol, 'index': item_index}))
        return item_index

    def give(self, flowchart, location, next_event=None):
        item_key, item_index = self.worker.getItemInfo(location)
        return item_get.insertItemGetAnimation(flowchart, item_key, item_index, after=next_event)

    def shells(self, logic):
        worker = self.worker
        flow = worker.readFile('ItemCommon.bfevfl')
        flowchart = flow.flowchart
        original_event = event_tools.findEvent(flowchart, 'Event0')
        original_events = list(flowchart.events)
        next_event = event_tools.findEvent(flowchart, 'Event1').data.nxt.v.name
        reward_chains = {'seashell': original_event.name, 'heart-piece': original_event.name}
        for location in reversed(locations(logic)):
            location_details = logic[location]
            pickup_kind = location_details['content']
            item_index = location_details['index']
            if pickup_kind not in reward_chains:
                raise ValueError('Unsupported indexed pickup: ' + location)
            collection_flag = 'LASPickup_' + location
            flag_index = self.flag(collection_flag)
            # Collection belongs to the location, not the received item.
            self.sources.append({'item': 22 if pickup_kind == 'seashell' else 58, 'index': item_index, 'flag': flag_index, 'pending': -1, 'location': location})
            completion_event = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag', {'symbol': collection_flag, 'value': True}, next_event)
            reward_event = self.give(flowchart, location, completion_event)
            reward_chains[pickup_kind] = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareInt', {'value1': 'itemIndex', 'value2': item_index}, {0: reward_event, 1: reward_chains[pickup_kind]})
        reward_chain = original_event.name
        for pickup_kind, item_key in (('seashell', 'Seashell'), ('heart-piece', 'HeartPiece')):
            reward_chain = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': 'itemKey', 'value2': item_key}, {0: reward_chains[pickup_kind], 1: reward_chain})
        redirect(flowchart, original_event, event_tools.findEvent(flowchart, reward_chain), original_events)
        worker.writeFile('ItemCommon.bfevfl', flow)

    def finish(self):
        worker = self.worker
        if any((source['item'] == 22 for source in self.sources)):
            from RandomizerCore.Randomizers.world_pickup_visuals import stage
            stage(worker, self.sources)
        worker.writeFile('GlobalFlags.gsheet', self.flags)
        if not self.sources:
            return
        # Tag actual rewards so native hooks can distinguish them from pickups.
        for path in Path(worker.romfs_dir).rglob('*.bfevfl'):
            try:
                flow = event_tools.readFlow(path)
            except Exception as exc:
                raise ValueError('Invalid generated event flow: ' + str(path)) from error
            changed = False
            for event in flow.flowchart.events:
                event_data = event.data
                if getattr(event_data, 'params', None) is None:
                    continue
                if not hasattr(event_data, 'actor_action') or event_data.actor_action.v.v != 'AddItemByKey':
                    continue
                event_parameters = event_data.params.data
                if event_parameters.get('itemKey') not in ('Seashell', 'HeartPiece'):
                    continue
                item_index = event_parameters.get('index')
                if isinstance(item_index, int) and 0 <= item_index < (50 if event_parameters['itemKey'] == 'Seashell' else 32):
                    event_parameters['index'] = GRANT_TAG | item_index
                    changed = True
            if changed:
                event_tools.writeFlow(path, flow)
        from RandomizerCore.Native.builder import build, validate_input
        exefs_folder = Path(worker.romfs_dir).parent / 'exefs'
        build(validate_input(worker.rom_path), exefs_folder, self.sources, Path(worker.romfs_dir).parent / 'native-build')
