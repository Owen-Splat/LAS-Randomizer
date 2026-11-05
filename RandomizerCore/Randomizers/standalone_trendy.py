# Adapter details derived in part from LASRecomp (MIT); see RandomizerCore/Tools/LASRecomp-LICENSE.txt.
"""Randomized featured prizes, keeping their vanilla slots and instrument gates."""
from copy import deepcopy
from pathlib import Path

def stage(rewards):
    worker = rewards.worker
    mod_folder = Path(worker.romfs_dir).parent
    clean_romfs = Path(worker.rom_path)
    selected_prizes = {}
    item_definitions = {}
    for prize_number in range(1, 7):
        location_name = 'trendy-prize-' + str(prize_number)
        item_key, item_index = worker.getItemInfo(location_name)
        selected_prizes[location_name] = {'location': location_name, 'key': item_key, 'marker': 0x53430000 + prize_number}
        item_definitions[item_key] = worker.item_defs[worker.placements[location_name]]
    from RandomizerCore.Tools import oead_tools as sheet_tools, event_tools as event_tools
    if 'trendy-prize-1' not in selected_prizes:
        return []
    output_romfs = Path(mod_folder) / 'romfs'
    clean_romfs_folder = Path(clean_romfs)

    def read_path(relative_path):
        return output_romfs / relative_path if (output_romfs / relative_path).is_file() else clean_romfs_folder / relative_path

    def write_path(relative_path):
        path = output_romfs / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    prize_sheet = sheet_tools.readSheet(read_path('region_common/datasheets/CranePrize.gsheet'))
    prize_rows = [sheet_tools.parseStruct(source_row) for source_row in prize_sheet['values']]
    original_prizes = {source_row['symbol']: source_row for source_row in prize_rows}
    # Keep each featured prize in its original slot and progression order.
    vanilla_prize_slots = [('YoshiDoll', 0), ('HeartPiece', 0), ('SecretSeashell', 0), ('PanelDungeonPiece', 0), ('HeartPiece', 1), ('SecretSeashell', 1)]
    disabled_layout_flag = 'LAS_CraneOriginalOff'
    rewards.flag(disabled_layout_flag)
    randomized_prizes = []
    flags_by_position = {}
    for prize_number, (prize_symbol, prize_layout) in enumerate(vanilla_prize_slots, 1):
        location_name = 'trendy-prize-' + str(prize_number)
        prize_details = selected_prizes[location_name]
        collection_flag = 'LAS_CranePrize' + str(prize_number)
        rewards.flag(collection_flag)
        row = deepcopy(original_prizes[prize_symbol])
        row['layouts'] = [deepcopy(row['layouts'][prize_layout])]
        prize_position = tuple((row['layouts'][0]['place'][field_name] for field_name in ('type', 'index')))
        availability_conditions = row['layouts'][0]['conditions']
        # Track this prize independently of the item it awards.
        availability_conditions = [condition for condition in availability_conditions if condition.get('parameter') != '!TradeYoshiDollGet']
        availability_conditions.append({'category': 1, 'parameter': '!' + collection_flag})
        if prize_position in flags_by_position:
            availability_conditions.append({'category': 1, 'parameter': flags_by_position[prize_position][-1]})
        flags_by_position.setdefault(prize_position, []).append(collection_flag)
        row['layouts'][0].update(itemIndex=prize_details['marker'], conditions=availability_conditions)
        item_definition = item_definitions[prize_details['key']]
        model_name = item_definition['model-name']
        model_number = str(prize_number).zfill(len(model_name) - 2)
        if len(model_name) < 3 or len(model_number) != len(model_name) - 2:
            raise ValueError('Unsupported crane model name')
        unique_model_name = 'A' + model_number + model_name[-1]
        model_bytes = read_path('region_common/actor/' + item_definition['model-path']).read_bytes()
        # Give each prize model a unique name without changing its byte length.
        model_name_bytes = len(model_name).to_bytes(2, 'little') + model_name.encode() + b'\x00'
        if model_bytes.count(model_name_bytes) != 1:
            raise ValueError('Ambiguous crane model rename: ' + model_name)
        model_bytes = model_bytes.replace(model_name_bytes, len(unique_model_name).to_bytes(2, 'little') + unique_model_name.encode() + b'\x00')
        write_path('region_common/actor/Prize' + unique_model_name + '.bfres').write_bytes(model_bytes)
        row.update(symbol=unique_model_name, getCount=1)
        row['getEvent']['messageEntry'] = prize_details['key']
        row['options']['isFeatured'] = False
        row['options']['isAutoSave'] = False
        randomized_prizes.append(row)
    # Keep old rows and their layouts; disable them with a flag instead.
    old_symbols = {prize_slot[0] for prize_slot in vanilla_prize_slots}
    for row in prize_rows:
        if row['symbol'] in old_symbols:
            for prize_layout in row['layouts']:
                prize_layout['conditions'].append({'category': 1, 'parameter': disabled_layout_flag})
        elif not row['options']['isFeatured']:
            for prize_layout in row['layouts']:
                prize_position = tuple((prize_layout['place'][field_name] for field_name in ('type', 'index')))
                if prize_position in flags_by_position:
                    prize_layout['conditions'] = [condition for condition in prize_layout['conditions'] if condition.get('parameter') != 'TradeYoshiDollGet']
                    prize_layout['conditions'].append({'category': 1, 'parameter': flags_by_position[prize_position][-1]})
    # The game expects the original prize rows to keep their indexes.
    prize_sheet['values'] = sheet_tools.listToSheetArray('values', prize_rows + randomized_prizes)
    sheet_tools.writeSheet(write_path('region_common/datasheets/CranePrize.gsheet'), prize_sheet)
    flow = event_tools.readFlow(read_path('region_common/event/PrizeCommon.bfevfl'))
    flowchart = flow.flowchart
    original_event = event_tools.findEvent(flowchart, 'Event0')
    original_events = list(flowchart.events)
    reward_chain = original_event.name
    next_event = event_tools.findEvent(flowchart, 'Event1').data.nxt.v.name
    for prize_number in range(6, 0, -1):
        prize_details = selected_prizes['trendy-prize-' + str(prize_number)]
        completion_event = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag', {'symbol': 'LAS_CranePrize' + str(prize_number), 'value': True}, next_event)
        reward_event = rewards.give(flowchart, 'trendy-prize-' + str(prize_number), completion_event)
        reward_chain = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareInt', {'value1': 'itemIndex', 'value2': prize_details['marker']}, {0: reward_event, 1: reward_chain})
    _redirect(flowchart, original_event, event_tools.findEvent(flowchart, reward_chain), original_events)
    event_tools.writeFlow(write_path('region_common/event/PrizeCommon.bfevfl'), flow)
    verified_prize_sheet = sheet_tools.readSheet(read_path('region_common/datasheets/CranePrize.gsheet'))
    if len(verified_prize_sheet['values']) != 27 or any((not len(source_row['layouts']) for source_row in verified_prize_sheet['values'])):
        raise ValueError('Crane prize rows must retain nonempty layouts')
    return ['trendy-prize-' + str(prize_number) for prize_number in range(1, 7)]


def _redirect(flowchart, original_event, replacement, original_events):
    """Redirect existing links without changing newly created reward branches."""
    from RandomizerCore.Tools import event_tools
    indexes = event_tools.invertList(flowchart.events)
    references = [entry.main_event for entry in flowchart.entry_points]
    for event in original_events:
        data = event.data
        if hasattr(data, 'nxt'):
            references.append(data.nxt)
        if hasattr(data, 'forks'):
            references.extend(data.forks)
        if hasattr(data, 'cases'):
            references.extend(data.cases.values())
    for reference in references:
        if reference.v is original_event:
            reference.v = replacement
            reference.set_index(indexes)


class DevTrendyRewards:
    """Use dev's managers for prize flags, item lookup and real reward events."""
    def __init__(self, generator):
        from copy import deepcopy
        self.generator = generator
        self.worker = self
        self.rom_path = generator.rom_path
        self.romfs_dir = generator.romfs_dir
        self.placements = generator.placements
        self.item_defs = deepcopy(generator.item_defs)
        for definition in self.item_defs.values():
            if definition['item-key'].endswith('Trap'):
                definition['model-path'] = 'ItemRupeeGreen.bfres'
                definition['model-name'] = 'RupeeGreen'

    def getItemInfo(self, location):
        return self.generator.item_info_manager.getItemInfo(location)

    def flag(self, symbol):
        self.generator.flag_manager.addFlag(symbol)
        index = self.generator.flag_manager.flags[symbol]
        if not 0 <= index < 2048:
            raise ValueError('Trendy prize flags exceed the supported save flag range')
        return index

    def give(self, flowchart, location, after=None):
        return self.generator.item_get_manager.get(flowchart, location, after=after, force_anim=True)

    def save_flags(self):
        from RandomizerCore.Tools import oead_tools
        sheet = self.generator.file_manager.readFile('GlobalFlags.gsheet')
        existing = {row['symbol'] for row in sheet['values']}
        for symbol, index in self.generator.flag_manager.flags.items():
            if symbol not in existing:
                sheet['values'].append(oead_tools.dictToStruct({'symbol': symbol, 'index': index}))
        self.generator.file_manager.writeFile('GlobalFlags.gsheet', sheet)
