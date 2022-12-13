from Randomizers import data, item_get
import Tools.event_tools as event_tools
import Tools.oead_tools as oead_tools
import shutil
import copy
import oead


prizes_dict = {}



def makeDatasheetChanges(sheet, placements, item_defs):
    """Edits conditions in the Trendy prizes datasheet. Trendy is still a WIP"""
    
    # sheet['root_fields'][5].fields.append(oead_tools.createField(
    #     name='gettingFlag',
    #     type_name='GlobalFlags',
    #     type=oead.gsheet.Field.Type.String,
    #     # flags=oead.gsheet.Field.Flag.IsKey,
    #     offset=20
    # ))
    
    symbols = []
    for prize in sheet['values']:

        symbols.append(prize['symbol'])

        # Bombs should not be obtainable until you have bombs, or automatically if unlocked-bombs is on
        if prize['symbol'] == 'Bomb':
            prize['layouts'][0]['conditions'][0] = {'category': 1, 'parameter': data.BOMBS_FOUND_FLAG}
            continue

        # Shield should not be obtainable until you find your first shield
        if prize['symbol'] == 'Shield':
            prize['layouts'][0]['conditions'].append({'category': 1, 'parameter': data.SHIELD_FOUND_FLAG})
            continue

        # SmallBowWow (Ciao Ciao): Remove the condition of HintYosshi. It's unnecessary and can lead to a softlock
        if prize['symbol'] == 'SmallBowWow':
            prize['layouts'][0]['conditions'].pop(0)
            continue

        # BowWow: Remove the ShadowClear condition. This was stupid in vanilla and it's even worse for rando.
        if prize['symbol'] == 'BowWow':
            prize['layouts'][0]['conditions'].pop(0)
            continue
    
    # return

    ### ADD RANDOMIZED PRIZES
    total_syms = len(symbols)

    if item_defs[placements['trendy-prize-1']]['model-name'] not in symbols:
        prize1 = copy.deepcopy(oead_tools.parseStruct(sheet['values'][7]))
        prize1['symbol'] = item_defs[placements['trendy-prize-1']]['model-name']
        prize1['layouts'][0]['itemIndex'] = placements['indexes']['trendy-prize-1'] if 'trendy-prize-1' in placements['indexes'] else -1
        # prize1['layouts'][0]['conditions'].append({'category': 1, 'parameter': '!PrizeGet1'})
        # prize1['layouts'][0]['gettingFlag'] = 'PrizeGet1'
        sheet['values'].append(oead_tools.dictToStruct(prize1))
        prizes_dict['prize1'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize1['symbol'], 'index': prize1['layouts'][0]['itemIndex']}
        symbols.append(prize1['symbol'])
        total_syms += 1
    else:
        for prize in sheet['values']:
            if prize['symbol'] == item_defs[placements['trendy-prize-1']]['model-name']:
                prize['layouts'].append(oead_tools.dictToStruct({
                    'itemIndex': placements['indexes']['trendy-prize-1'] if 'trendy-prize-1' in placements['indexes'] else -1,
                    'conditions': [],
                    # 'conditions': [{'category': 1, 'parameter': '!PrizeGet1'}],
                    'place': {'type': 1, 'index': 0},
                    # 'gettingFlag': 'PrizeGet1'
                }))
                layoutNum = len(prize['layouts']) - 1
                break
        prizes_dict['prize1'] = {
            'cranePrizeId': symbols.index(item_defs[placements['trendy-prize-1']]['model-name']),
            'layoutIndex': layoutNum,
            'symbol': prize['symbol'],
            'index': prize['layouts'][layoutNum]['itemIndex']}


    if item_defs[placements['trendy-prize-2']]['model-name'] not in symbols:
        prize2 = copy.deepcopy(oead_tools.parseStruct(sheet['values'][7]))
        prize2['symbol'] = item_defs[placements['trendy-prize-2']]['model-name']
        prize2['layouts'][0]['itemIndex'] = placements['indexes']['trendy-prize-2'] if 'trendy-prize-2' in placements['indexes'] else -1
        prize2['layouts'][0]['place'] = {'type': 1, 'index': 1}
        # prize2['layouts'][0]['conditions'].append({'category': 1, 'parameter': '!PrizeGet2'})
        # prize2['layouts'][0]['gettingFlag'] = 'PrizeGet2'
        sheet['values'].append(oead_tools.dictToStruct(prize2))
        prizes_dict['prize2'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize2['symbol'], 'index': prize2['layouts'][0]['itemIndex']}
        symbols.append(item_defs[placements['trendy-prize-1']]['model-name'])
        total_syms += 1
    else:
        for prize in sheet['values']:
            if prize['symbol'] == item_defs[placements['trendy-prize-2']]['model-name']:
                prize['layouts'].append(oead_tools.dictToStruct({
                    'itemIndex': placements['indexes']['trendy-prize-2'] if 'trendy-prize-2' in placements['indexes'] else -1,
                    'conditions': [],
                    # 'conditions': [{'category': 1, 'parameter': '!PrizeGet2'}],
                    'place': {'type': 1, 'index': 1},
                    # 'gettingFlag': 'PrizeGet2'
                }))
                layoutNum = len(prize['layouts']) - 1
                break
        prizes_dict['prize2'] = {
            'cranePrizeId': symbols.index(item_defs[placements['trendy-prize-2']]['model-name']),
            'layoutIndex': layoutNum,
            'symbol': prize['symbol'],
            'index': prize['layouts'][layoutNum]['itemIndex']}
    

    if item_defs[placements['trendy-prize-3']]['model-name'] not in symbols:
        prize3 = copy.deepcopy(oead_tools.parseStruct(sheet['values'][7]))
        prize3['symbol'] = item_defs[placements['trendy-prize-3']]['model-name']
        prize3['layouts'][0]['itemIndex'] = placements['indexes']['trendy-prize-3'] if 'trendy-prize-3' in placements['indexes'] else -1
        prize3['layouts'][0]['place'] = {'type': 1, 'index': 1}
        # prize3['layouts'][0]['conditions'].append({'category': 1, 'parameter': 'PrizeGet2'})
        # prize3['layouts'][0]['conditions'].append({'category': 1, 'parameter': '!PrizeGet3'})
        # prize3['layouts'][0]['gettingFlag'] = 'PrizeGet3'
        sheet['values'].append(oead_tools.dictToStruct(prize3))
        prizes_dict['prize3'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize3['symbol'], 'index': prize3['layouts'][0]['itemIndex']}
        symbols.append(item_defs[placements['trendy-prize-1']]['model-name'])
        total_syms += 1
    else:
        for prize in sheet['values']:
            if prize['symbol'] == item_defs[placements['trendy-prize-3']]['model-name']:
                prize['layouts'].append(oead_tools.dictToStruct({
                    'itemIndex': placements['indexes']['trendy-prize-3'] if 'trendy-prize-3' in placements['indexes'] else -1,
                    'conditions': [
                        # {'category': 1, 'parameter': 'PrizeGet2'},
                        # {'category': 1, 'parameter': '!PrizeGet3'}
                    ],
                    'place': {'type': 1, 'index': 1},
                    # 'gettingFlag': 'PrizeGet3'
                }))
                layoutNum = len(prize['layouts']) - 1
                break
        prizes_dict['prize3'] = {
            'cranePrizeId': symbols.index(item_defs[placements['trendy-prize-3']]['model-name']),
            'layoutIndex': layoutNum,
            'symbol': prize['symbol'],
            'index': prize['layouts'][layoutNum]['itemIndex']}


    if item_defs[placements['trendy-prize-4']]['model-name'] not in symbols:
        prize4 = copy.deepcopy(oead_tools.parseStruct(sheet['values'][7]))
        prize4['symbol'] = item_defs[placements['trendy-prize-4']]['model-name']
        prize4['layouts'][0]['itemIndex'] = placements['indexes']['trendy-prize-4'] if 'trendy-prize-4' in placements['indexes'] else -1
        prize4['layouts'][0]['place'] = {'type': 2, 'index': 0}
        # prize4['layouts'][0]['conditions'].append({'category': 1, 'parameter': 'PrizeGet3'})
        # prize4['layouts'][0]['conditions'].append({'category': 1, 'parameter': '!PrizeGet4'})
        if not placements['settings']['fast-trendy']:
            prize4['layouts'][0]['conditions'].append({'category': 2, 'parameter': 'ConchHorn'})
        # prize4['layouts'][0]['gettingFlag'] = 'PrizeGet4'
        sheet['values'].append(oead_tools.dictToStruct(prize4))
        prizes_dict['prize4'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize4['symbol'], 'index': prize4['layouts'][0]['itemIndex']}
        symbols.append(item_defs[placements['trendy-prize-1']]['model-name'])
        total_syms += 1
    else:
        for prize in sheet['values']:
            if prize['symbol'] == item_defs[placements['trendy-prize-4']]['model-name']:
                prize['layouts'].append(oead_tools.dictToStruct({
                    'itemIndex': placements['indexes']['trendy-prize-4'] if 'trendy-prize-4' in placements['indexes'] else -1,
                    'conditions': [
                        # {'category': 1, 'parameter': 'PrizeGet3'},
                        # {'category': 1, 'parameter': '!PrizeGet4'}
                    ],
                    'place': {'type': 2, 'index': 0},
                    # 'gettingFlag': 'PrizeGet4'
                }))
                layoutNum = len(prize['layouts']) - 1
                if not placements['settings']['fast-trendy']:
                    prize['layouts'][layoutNum]['conditions'].append({'category': 2, 'parameter': 'ConchHorn'})
                break
        prizes_dict['prize4'] = {
            'cranePrizeId': symbols.index(item_defs[placements['trendy-prize-4']]['model-name']),
            'layoutIndex': layoutNum,
            'symbol': prize['symbol'],
            'index': prize['layouts'][layoutNum]['itemIndex']}


    if item_defs[placements['trendy-prize-5']]['model-name'] not in symbols:
        prize5 = copy.deepcopy(oead_tools.parseStruct(sheet['values'][7]))
        prize5['symbol'] = item_defs[placements['trendy-prize-5']]['model-name']
        prize5['layouts'][0]['itemIndex'] = placements['indexes']['trendy-prize-5'] if 'trendy-prize-5' in placements['indexes'] else -1
        prize5['layouts'][0]['place'] = {'type': 2, 'index': 1}
        # prize5['layouts'][0]['conditions'].append({'category': 1, 'parameter': 'PrizeGet4'})
        # prize5['layouts'][0]['conditions'].append({'category': 1, 'parameter': '!PrizeGet5'})
        if not placements['settings']['fast-trendy']:
            prize5['layouts'][0]['conditions'].append({'category': 2, 'parameter': 'SeaLilysBell'})
        # prize5['layouts'][0]['gettingFlag'] = 'PrizeGet5'
        sheet['values'].append(oead_tools.dictToStruct(prize5))
        prizes_dict['prize5'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize5['symbol'], 'index': prize5['layouts'][0]['itemIndex']}
        symbols.append(item_defs[placements['trendy-prize-1']]['model-name'])
        total_syms += 1
    else:
        for prize in sheet['values']:
            if prize['symbol'] == item_defs[placements['trendy-prize-5']]['model-name']:
                prize['layouts'].append(oead_tools.dictToStruct({
                    'itemIndex': placements['indexes']['trendy-prize-5'] if 'trendy-prize-5' in placements['indexes'] else -1,
                    'conditions': [
                        # {'category': 1, 'parameter': 'PrizeGet4'},
                        # {'category': 1, 'parameter': '!PrizeGet5'}
                    ],
                    'place': {'type': 2, 'index': 1},
                    # 'gettingFlag': 'PrizeGet5'
                }))
                layoutNum = len(prize['layouts']) - 1
                if not placements['settings']['fast-trendy']:
                    prize['layouts'][layoutNum]['conditions'].append({'category': 2, 'parameter': 'SeaLilysBell'})
                break
        prizes_dict['prize5'] = {
            'cranePrizeId': symbols.index(item_defs[placements['trendy-prize-5']]['model-name']),
            'layoutIndex': layoutNum,
            'symbol': prize['symbol'],
            'index': prize['layouts'][layoutNum]['itemIndex']}


    if item_defs[placements['trendy-prize-6']]['model-name'] not in symbols:
        prize6 = copy.deepcopy(oead_tools.parseStruct(sheet['values'][7]))
        prize6['symbol'] = item_defs[placements['trendy-prize-6']]['model-name']
        prize6['layouts'][0]['itemIndex'] = placements['indexes']['trendy-prize-6'] if 'trendy-prize-6' in placements['indexes'] else -1
        prize6['layouts'][0]['place'] = {'type': 2, 'index': 0}
        # prize6['layouts'][0]['conditions'].append({'category': 1, 'parameter': 'PrizeGet5'})
        # prize6['layouts'][0]['conditions'].append({'category': 1, 'parameter': '!PrizeGet6'})
        if not placements['settings']['fast-trendy']:
            prize6['layouts'][0]['conditions'].append({'category': 2, 'parameter': 'SurfHarp'})
        # prize6['layouts'][0]['gettingFlag'] = 'PrizeGet6'
        sheet['values'].append(oead_tools.dictToStruct(prize6))
        prizes_dict['prize6'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize6['symbol'], 'index': prize6['layouts'][0]['itemIndex']}
        symbols.append(item_defs[placements['trendy-prize-1']]['model-name'])
        total_syms += 1
    else:
        for prize in sheet['values']:
            if prize['symbol'] == item_defs[placements['trendy-prize-6']]['model-name']:
                prize['layouts'].append(oead_tools.dictToStruct({
                    'itemIndex': placements['indexes']['trendy-prize-6'] if 'trendy-prize-6' in placements['indexes'] else -1,
                    'conditions': [
                        # {'category': 1, 'parameter': 'PrizeGet5'},
                        # {'category': 1, 'parameter': '!PrizeGet6'}
                    ],
                    'place': {'type': 2, 'index': 0},
                    # 'gettingFlag': 'PrizeGet6'
                }))
                layoutNum = len(prize['layouts']) - 1
                if not placements['settings']['fast-trendy']:
                    prize['layouts'][layoutNum]['conditions'].append({'category': 2, 'parameter': 'SurfHarp'})
                break
        prizes_dict['prize6'] = {
            'cranePrizeId': symbols.index(item_defs[placements['trendy-prize-6']]['model-name']),
            'layoutIndex': layoutNum,
            'symbol': prize['symbol'],
            'index': prize['layouts'][layoutNum]['itemIndex']}



def changePrizeGroups(sheet1, sheet2):
    # print(prizes_dict)
    
    sheet1['values'][0]['cranePrizeId'] = prizes_dict['prize1']['cranePrizeId']
    sheet1['values'][0]['layoutIndex'] = prizes_dict['prize1']['layoutIndex']
    
    sheet2['values'][0]['cranePrizeId'] = prizes_dict['prize2']['cranePrizeId']
    sheet2['values'][0]['layoutIndex'] = prizes_dict['prize2']['layoutIndex']

    sheet2['values'][1]['cranePrizeId'] = prizes_dict['prize3']['cranePrizeId']
    sheet2['values'][1]['layoutIndex'] = prizes_dict['prize3']['layoutIndex']

    sheet2['values'][2]['cranePrizeId'] = prizes_dict['prize4']['cranePrizeId']
    sheet2['values'][2]['layoutIndex'] = prizes_dict['prize4']['layoutIndex']

    sheet2['values'][3]['cranePrizeId'] = prizes_dict['prize5']['cranePrizeId']
    sheet2['values'][3]['layoutIndex'] = prizes_dict['prize5']['layoutIndex']

    sheet2['values'][4]['cranePrizeId'] = prizes_dict['prize6']['cranePrizeId']
    sheet2['values'][4]['layoutIndex'] = prizes_dict['prize6']['layoutIndex']



def makeEventChanges(flowchart, placements):
    try:
        event_tools.findActor(flowchart, 'FlowControl').find_query('CompareInt')
    except ValueError:
        event_tools.addActorQuery(event_tools.findActor(flowchart, 'FlowControl'), 'CompareInt')

    if placements['settings']['fast-trendy']:
        event_tools.findEvent(flowchart, 'Event5').data.params.data['prizeType'] = 10
    
    # after rewarding the item, set certain flags as well as remove trade quest items from inventory
    sword2_give = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItem',
        {'itemType': 1, 'count': 1}, None)
    sword1_give = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
        {'symbol': data.SWORD_FOUND_FLAG, 'value': True}, None)
    sword_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.SWORD_FOUND_FLAG}, {0: sword1_give, 1: sword2_give})
    sword_content_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'SwordLv1'},
        {0: sword_flag_check, 1: None})
    
    shield2_give = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItem',
        {'itemType': 3, 'count': 1}, None)
    shield1_give = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
        {'symbol': data.SHIELD_FOUND_FLAG, 'value': True}, None)
    shield_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.SHIELD_FOUND_FLAG}, {0: shield1_give, 1: shield2_give})
    shield_content_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Shield'},
        {0: shield_flag_check, 1: sword_content_check})

    bracelet2_give = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItem',
        {'itemType': 15, 'count': 1}, None)
    bracelet1_give = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
        {'symbol': data.BRACELET_FOUND_FLAG, 'value': True}, None)
    bracelet_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.BRACELET_FOUND_FLAG}, {0: bracelet1_give, 1: bracelet2_give})
    bracelet_content_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'PowerBraceletLv1'},
        {0: bracelet_flag_check, 1: shield_content_check})
    
    bomb_give = event_tools.createActionChain(flowchart, None, [
        ('EventFlags', 'SetFlag', {'symbol': data.BOMBS_FOUND_FLAG, 'value': True}),
        ('Inventory', 'AddItem', {'itemType': 4, 'count': 20})
    ], None)
    bomb_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Bomb'},
        {0: bomb_give, 1: bracelet_content_check})
    
    harp_flags = event_tools.createActionChain(flowchart, None, [
        ('EventFlags', 'SetFlag', {'symbol': 'GhostClear1', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'Ghost2_Clear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'Ghost3_Clear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'Ghost4_Clear', 'value': True})
    ], None)
    harp_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'SurfHarp'},
        {0: harp_flags, 1: bomb_check})
    
    lens_give = event_tools.createActionChain(flowchart, None, [
        ('EventFlags', 'SetFlag', {'symbol': data.LENS_FOUND_FLAG, 'value': True}),
        ('Inventory', 'AddItem', {'itemType': 44, 'count': 1})
    ], None)
    lens_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.LENS_FOUND_FLAG}, {0: None, 1: lens_give})
    lens_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'MagnifyingLens'},
        {0: lens_give, 1: harp_check})

    scale_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'RemoveItem', {'itemType': 43}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeMermaidsScaleGet', 'value': True})
    ], lens_flag_check)
    scale_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'MermaidsScale'},
        {0: scale_give, 1: lens_check})

    necklace_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'RemoveItem', {'itemType': 41}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeNecklaceGet', 'value': True})
    ], lens_flag_check)
    necklace_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'PinkBra'},
        {0: necklace_give, 1: scale_check})

    hook_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'RemoveItem', {'itemType': 40}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeFishingHookGet', 'value': True})
    ], lens_flag_check)
    hook_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'FishingHook'},
        {0: hook_give, 1: necklace_check})

    broom_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'RemoveItem', {'itemType': 39}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeBroomGet', 'value': True})
    ], lens_flag_check)
    broom_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Broom'},
        {0: broom_give, 1: hook_check})

    letter_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'RemoveItem', {'itemType': 38}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeLetterGet', 'value': True})
    ], lens_flag_check)
    letter_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Letter'},
        {0: letter_give, 1: broom_check})

    hibiscus_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'RemoveItem', {'itemType': 37}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeHibiscusGet', 'value': True})
    ], lens_flag_check)
    hibiscus_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Hibiscus'},
        {0: hibiscus_give, 1: letter_check})

    pineapple_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'RemoveItem', {'itemType': 36}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradePineappleGet', 'value': True})
    ], lens_flag_check)
    pineapple_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Pineapple'},
        {0: pineapple_give, 1: hibiscus_check})

    honeycomb_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'RemoveItem', {'itemType': 35}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeHoneycombGet', 'value': True})
    ], lens_flag_check)
    honeycomb_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Honeycomb'},
        {0: honeycomb_give, 1: pineapple_check})

    stick_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'RemoveItem', {'itemType': 34}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeStickGet', 'value': True})
    ], lens_flag_check)
    stick_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Stick'},
        {0: stick_give, 1: honeycomb_check})

    bananas_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'RemoveItem', {'itemType': 33}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeBananasGet', 'value': True})
    ], lens_flag_check)
    bananas_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Bananas'},
        {0: bananas_give, 1: stick_check})

    dogfood_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'RemoveItem', {'itemType': 32}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeDogFoodGet', 'value': True})
    ], lens_flag_check)
    dogfood_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'DogFood'},
        {0: dogfood_give, 1: bananas_check})

    ribbon_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'RemoveItem', {'itemType': 31}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeRibbonGet', 'value': True})
    ], lens_flag_check)
    ribbon_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Ribbon'},
        {0: ribbon_give, 1: dogfood_check})

    yoshi_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'RemoveItem', {'itemType': 30}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeYoshiDollGet', 'value': True})
    ], lens_flag_check)
    yoshi_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'YoshiDoll'},
        {0: yoshi_give, 1: ribbon_check})

    ### CONNECT CHAIN TO EVENTS
    event_tools.insertEventAfter(flowchart, 'Event3', yoshi_check)
    event_tools.insertEventAfter(flowchart, 'Event7', yoshi_check)
    event_tools.insertEventAfter(flowchart, 'Event9', yoshi_check)



def makePrizeModels(romPath, outDir, placements, itemDefs):
    """Since prizes have their own, separate models, we copy the needed item models over and rename them to Prize{model}.bfres"""

    prizes = [key for key in placements.keys() if key.startswith('trendy-prize')]
    prizes.remove('trendy-prize-final')
    
    for prize in prizes:
        path = itemDefs[placements[prize]]['model-path']
        model = itemDefs[placements[prize]]['model-name']
        try:
            shutil.copy(f'{romPath}/region_common/actor/{path}', f'{outDir}/Romfs/region_common/actor/Prize{model}.bfres')
        except FileNotFoundError:
            shutil.copy(f'{outDir}/Romfs/region_common/actor/{path}', f'{outDir}/Romfs/region_common/actor/Prize{model}.bfres')
