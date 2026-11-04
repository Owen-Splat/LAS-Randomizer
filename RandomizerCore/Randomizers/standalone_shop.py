# Adapter details derived in part from LASRecomp (MIT); see RandomizerCore/Tools/LASRecomp-LICENSE.txt.
"""One-time standalone goods in the vanilla shop's shovel/bow, stone and heart slots.

Vanilla consumable goods remain available. Purchased and stolen goods share the
persistent source flag, independently of receiving their original vanilla equipment.
"""
from copy import deepcopy
from pathlib import Path
import re
import struct

def stage(rewards):
    worker = rewards.worker
    mod_folder = Path(worker.romfs_dir).parent
    clean_romfs = Path(worker.rom_path)
    shop_locations = ['shop-slot3-1st', 'shop-slot3-2nd'] + [f'shop-slot5-{purchase_number}' for purchase_number in ('1st', '2nd', '3rd', '4th', '5th', '6th', '7th')] + ['shop-slot6']
    item_displays = {}
    item_definitions = {}
    for location_name in shop_locations:
        item_key, item_index = worker.getItemInfo(location_name)
        item_displays[location_name] = {'location': location_name, 'key': item_key, 'marker': item_index, 'message': worker.placements[location_name].replace('-', ' ').title()}
        item_definitions[item_key] = worker.item_defs[worker.placements[location_name]]
    from RandomizerCore.Tools import event_tools as event_tools, oead_tools as sheet_tools
    from RandomizerCore.Tools.msbt import Msbt
    if not item_displays:
        return []
    output_romfs = Path(mod_folder) / 'romfs'
    clean_romfs_folder = Path(clean_romfs)

    def read_path(relative_path):
        path = output_romfs / relative_path
        return path if path.is_file() else clean_romfs_folder / relative_path

    def write_path(relative_path):
        path = output_romfs / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    shop_locations = ['shop-slot3-1st', 'shop-slot3-2nd'] + [f'shop-slot5-{purchase_number}' for purchase_number in ('1st', '2nd', '3rd', '4th', '5th', '6th', '7th')] + ['shop-slot6']
    shop_rewards = []
    for shop_index, location_name in enumerate(shop_locations):
        if location_name not in item_displays:
            continue
        item_display = item_displays[location_name]
        shop_rewards.append(dict(item_display, flag='LASShop_' + location_name, dummy='LASShopGoods_' + str(shop_index), pending='LASShopPending_' + str(shop_index), native_id=230 + shop_index, slot=2 if shop_index < 2 else 4 if shop_index < 9 else 5, price=200 if shop_index in (0, 9) else 980 if shop_index == 1 else 999, ordinal=shop_index))
    # Give each one-time good separate collected and pending save flags.
    for shop_reward in shop_rewards:
        collection_flag_index = rewards.flag(shop_reward['flag'])
        pending_flag_index = rewards.flag(shop_reward['pending'])
        rewards.sources.append({'item': shop_reward['native_id'], 'index': -1, 'flag': collection_flag_index, 'pending': pending_flag_index})
    item_sheet = sheet_tools.readSheet(read_path('region_common/datasheets/Items.gsheet'))
    item_template = next((sheet_tools.parseStruct(shop_reward) for shop_reward in item_sheet['values'] if shop_reward['symbol'] == 'HookShot'))
    for shop_reward in shop_rewards:
        row = deepcopy(item_template)
        row.update(symbol=shop_reward['dummy'], itemID=shop_reward['native_id'], gettingFlag='')
        item_sheet['values'].append(sheet_tools.dictToStruct(row))
    sheet_tools.writeSheet(write_path('region_common/datasheets/Items.gsheet'), item_sheet)
    availability_conditions = sheet_tools.readSheet(read_path('region_common/datasheets/Conditions.gsheet'))
    previous_slot_flags = {}
    for shop_reward in shop_rewards:
        availability_checks = [(1, '!' + shop_reward['flag'])]
        if shop_reward['slot'] in previous_slot_flags:
            availability_checks.append((1, previous_slot_flags[shop_reward['slot']]))
        previous_slot_flags[shop_reward['slot']] = shop_reward['flag']
        availability_conditions['values'].append(sheet_tools.createCondition(shop_reward['dummy'], availability_checks))
    sheet_tools.writeSheet(write_path('region_common/datasheets/Conditions.gsheet'), availability_conditions)
    shop_sheet = sheet_tools.readSheet(read_path('region_common/datasheets/ShopItem.gsheet'))
    for slot in shop_sheet['values']:
        slot_rewards = [shop_reward for shop_reward in shop_rewards if shop_reward['slot'] == slot['mIndex']]
        if not slot_rewards:
            continue
        slot_goods = []
        for shop_reward in slot_rewards:
            item_definition = item_definitions[shop_reward['key']]
            slot_goods.append({'mItem': shop_reward['dummy'], 'mIndex': shop_reward['marker'], 'mCount': 1, 'mModelPath': 'actor/' + item_definition['model-path'], 'mModelName': item_definition['model-name'], 'mLabel': 'System:' + shop_reward['dummy'] + '_Price', 'mCondition': shop_reward['dummy'], 'mEntryPoint': shop_reward['dummy']})
        # Keep arrows available after the one-time equipment is sold.
        if slot['mIndex'] == 2:
            arrow = next((sheet_tools.parseStruct(goods_entry) for goods_entry in slot['mGoods'] if goods_entry['mItem'] == 'Arrow'))
            arrow['mCondition'] = 'LASShopArrowRestock'
            slot_goods.append(arrow)
            availability_conditions['values'].append(sheet_tools.createCondition('LASShopArrowRestock', [(1, slot_rewards[-1]['flag'])]))
        slot['mGoods'] = sheet_tools.listToSheetArray('mGoods', slot_goods)
    sheet_tools.writeSheet(write_path('region_common/datasheets/ShopItem.gsheet'), shop_sheet)
    sheet_tools.writeSheet(write_path('region_common/datasheets/Conditions.gsheet'), availability_conditions)
    flow = event_tools.readFlow(read_path('region_common/event/ToolShopkeeper.bfevfl'))
    flowchart = flow.flowchart
    talk_parameters = dict(event_tools.findEvent(flowchart, 'Event138').data.params.data)
    for shop_reward in shop_rewards:
        completion_event = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag', {'symbol': shop_reward['flag'], 'value': True})
        reward_event = rewards.give(flowchart, shop_reward['location'], completion_event)
        purchase_event = event_tools.createActionChain(flowchart, None, [('Link', 'AddRupee', {'amount': -shop_reward['price']}), ('ToolShopkeeper', 'RemoveGoods', {}), ('ToolShopkeeper', 'Talk', {'message': 'Npc:BuyToolShop'})], reward_event)
        restore_goods_event = event_tools.createActionEvent(flowchart, 'ToolShopkeeper', 'RestoreGoods', {})
        insufficient_rupees_event = event_tools.createActionEvent(flowchart, 'ToolShopkeeper', 'Talk', {'message': 'Npc:NoneMoneyToolShop'}, restore_goods_event)
        check_rupees_event = event_tools.createSwitchEvent(flowchart, 'Link', 'CheckRupee', {'amount': shop_reward['price']}, {0: insufficient_rupees_event, 1: purchase_event})
        answer_event = event_tools.createSwitchEvent(flowchart, 'Dialog', 'GetLastResult', {}, {0: check_rupees_event, 1: restore_goods_event})
        offer_event = event_tools.createActionEvent(flowchart, 'ToolShopkeeper', 'Talk', {'message': 'System:' + shop_reward['dummy'] + '_Buy'})
        face_player_event = event_tools.createActionEvent(flowchart, 'ToolShopkeeper', 'GenericTalkSequence', talk_parameters)
        offer_sequence = event_tools.createForkEvent(flowchart, None, [face_player_event, offer_event], answer_event)[0]
        event_tools.addEntryPoint(flowchart, shop_reward['dummy'])
        event_tools.insertEventAfter(flowchart, shop_reward['dummy'], event_tools.createActionEvent(flowchart, 'Hud', 'ShowRupee', {'visible': True}, offer_sequence))
    event_tools.writeFlow(write_path('region_common/event/ToolShopkeeper.bfevfl'), flow)
    price_color_command = b'\x0e\x00\x00\x03\x00\x04\x00\xd9Em\xff'
    for original_message_path in sorted(clean_romfs_folder.rglob('System.msbt')):
        path = write_path(original_message_path.relative_to(clean_romfs_folder))
        messages = Msbt((path if path.is_file() else original_message_path).read_bytes())
        price_message_template = messages.texts['PriceTagScoop']
        buy_message_template = messages.texts['BuyHeartPeace']
        for shop_reward in shop_rewards:
            item_label = shop_reward['message'].split('\nFor ')[0].replace('\n', ' ').encode()
            for suffix, message_template in (('_Price', price_message_template), ('_Buy', buy_message_template)):
                message_bytes = item_label + b'\n' + message_template[message_template.index(price_color_command):]
                price_start = message_bytes.index(price_color_command) + len(price_color_command)
                # Change the price while preserving the locale's dialog commands.
                price_match = re.match(b'(?:[0-9,]|\\xef\\xbc[\\x90-\\x99]|\\xef\\xbc\\x8c)+', message_bytes[price_start:])
                if not price_match:
                    raise ValueError('Unrecognized localized shop price')
                message_bytes = message_bytes[:price_start] + str(shop_reward['price']).encode() + message_bytes[price_start + len(price_match[0]):]
                messages.set(shop_reward['dummy'] + suffix, message_bytes)
                if messages.atr is not None:
                    _, attribute_size = struct.unpack_from('<II', messages.atr)
                    template_label = 'PriceTagScoop' if suffix == '_Price' else 'BuyHeartPeace'
                    source_offset = 8 + messages.labels[template_label] * attribute_size
                    target_offset = 8 + messages.labels[shop_reward['dummy'] + suffix] * attribute_size
                    messages.atr = messages.atr[:target_offset] + messages.atr[source_offset:source_offset + attribute_size] + messages.atr[target_offset + attribute_size:]
        path.write_bytes(messages.pack())
    # Deliver stolen goods on PlayerStart and clear their pending flags.
    flow = worker.readFile('PlayerStart.bfevfl')
    flowchart = flow.flowchart
    start_event = 'Event57'
    next_event = event_tools.findEvent(flowchart, start_event).data.nxt.v.name
    reward_chain = next_event
    for shop_reward in reversed(shop_rewards):
        completion_event = event_tools.createActionChain(flowchart, None, [('EventFlags', 'SetFlag', {'symbol': shop_reward['flag'], 'value': True}), ('EventFlags', 'SetFlag', {'symbol': shop_reward['pending'], 'value': False})], reward_chain)
        reward_event = rewards.give(flowchart, shop_reward['location'], completion_event)
        # A stale pending flag must not grant an already collected reward.
        clear_pending_event = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag', {'symbol': shop_reward['pending'], 'value': False}, reward_chain)
        already_collected_event = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag', {'symbol': shop_reward['flag']}, {0: reward_event, 1: clear_pending_event})
        reward_chain = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag', {'symbol': shop_reward['pending']}, {0: reward_chain, 1: already_collected_event})
    event_tools.insertEventAfter(flowchart, start_event, reward_chain)
    worker.writeFile('PlayerStart.bfevfl', flow)
    return [shop_reward['location'] for shop_reward in shop_rewards]
