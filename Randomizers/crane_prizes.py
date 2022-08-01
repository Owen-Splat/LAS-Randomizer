from Randomizers import data, item_get
import Tools.event_tools as event_tools
import Tools.oead_tools as oead_tools
import shutil
import copy
import oead


prizesDict = {}



def makeDatasheetChanges(sheet, placements, item_defs):
    """Edits conditions in the Trendy prizes datasheet. Trendy is not randomized yet"""
    
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

        # cranePrize['layouts'][0]['gettingFlag'] = ''
        # try:
        #     cranePrize['layouts'][1]['gettingFlag'] = ''
        # except IndexError:
        #     pass
        
        # Bombs should not be obtainable until you have bombs
        if prize['symbol'] == 'Bomb' and placements['settings']['shuffle-bombs']:
            prize['layouts'][0]['conditions'][0] = {'category': 1, 'parameter': data.BOMBS_FOUND_FLAG}
        # Shield should not be obtainable until you find your first shield
        if prize['symbol'] == 'Shield':
            prize['layouts'][0]['conditions'].append({'category': 1, 'parameter': data.SHIELD_FOUND_FLAG})

        # SmallBowWow (Ciao Ciao): Remove the condition of HintYosshi. It's unnecessary and can lead to a softlock
        if prize['symbol'] == 'SmallBowWow':
            prize['layouts'][0]['conditions'].pop(0)

        # BowWow: Remove the ShadowClear condition. This was stupid in vanilla and it's even worse for rando.
        if prize['symbol'] == 'BowWow':
            prize['layouts'][0]['conditions'].pop(0)
    
    return
    ### ADD RANDOMIZED PRIZES

    total_syms = len(symbols)

    if item_defs[placements['trendy-prize-1']]['model-name'] not in symbols:
        prize1 = copy.deepcopy(oead_tools.parseStruct(sheet['values'][7]))
        prize1['symbol'] = item_defs[placements['trendy-prize-1']]['model-name']
        prize1['layouts'][0]['itemIndex'] = placements['indexes']['trendy-prize-1'] if 'trendy-prize-1' in placements['indexes'] else -1
        # prize1['layouts'][0]['conditions'].append({'category': 1, 'parameter': '!PrizeGet1'})
        # prize1['layouts'][0]['gettingFlag'] = 'PrizeGet1'
        sheet['values'].append(oead_tools.dictToStruct(prize1))
        prizesDict['prize1'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize1['symbol'], 'index': prize1['layouts'][0]['itemIndex']}
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
        prizesDict['prize1'] = {
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
        prizesDict['prize2'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize2['symbol'], 'index': prize2['layouts'][0]['itemIndex']}
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
        prizesDict['prize2'] = {
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
        prizesDict['prize3'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize3['symbol'], 'index': prize3['layouts'][0]['itemIndex']}
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
        prizesDict['prize3'] = {
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
        prizesDict['prize4'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize4['symbol'], 'index': prize4['layouts'][0]['itemIndex']}
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
        prizesDict['prize4'] = {
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
        prizesDict['prize5'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize5['symbol'], 'index': prize5['layouts'][0]['itemIndex']}
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
        prizesDict['prize5'] = {
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
        prizesDict['prize6'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize6['symbol'], 'index': prize6['layouts'][0]['itemIndex']}
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
        prizesDict['prize6'] = {
            'cranePrizeId': symbols.index(item_defs[placements['trendy-prize-6']]['model-name']),
            'layoutIndex': layoutNum,
            'symbol': prize['symbol'],
            'index': prize['layouts'][layoutNum]['itemIndex']}



def changePrizeGroups(sheet1, sheet2):
    # print(prizesDict)

    sheet1['values'][0]['cranePrizeId'] = prizesDict['prize1']['cranePrizeId']
    sheet1['values'][0]['layoutIndex'] = prizesDict['prize1']['layoutIndex']

    sheet2['values'][0]['cranePrizeId'] = prizesDict['prize2']['cranePrizeId']
    sheet2['values'][0]['layoutIndex'] = prizesDict['prize2']['layoutIndex']

    sheet2['values'][1]['cranePrizeId'] = prizesDict['prize3']['cranePrizeId']
    sheet2['values'][1]['layoutIndex'] = prizesDict['prize3']['layoutIndex']

    sheet2['values'][2]['cranePrizeId'] = prizesDict['prize4']['cranePrizeId']
    sheet2['values'][2]['layoutIndex'] = prizesDict['prize4']['layoutIndex']

    sheet2['values'][3]['cranePrizeId'] = prizesDict['prize5']['cranePrizeId']
    sheet2['values'][3]['layoutIndex'] = prizesDict['prize5']['layoutIndex']

    sheet2['values'][4]['cranePrizeId'] = prizesDict['prize6']['cranePrizeId']
    sheet2['values'][4]['layoutIndex'] = prizesDict['prize6']['layoutIndex']



def makeEventChanges(flowchart, placements):
    try:
        event_tools.findActor(flowchart, 'FlowControl').find_query('CompareInt')
    except ValueError:
        event_tools.addActorQuery(event_tools.findActor(flowchart, 'FlowControl'), 'CompareInt')

    if placements['settings']['fast-trendy']:
        event_tools.findEvent(flowchart, 'Event5').data.params.data['prizeType'] = 10
    

    # basicGet = event_tools.createActionChain(flowchart, None, [
    #     ('Inventory', 'AddItemByKey', {
    #         'itemKey': event_tools.findEvent(flowchart, 'Event1').data.params.data['prizeKey'],
    #         'count': event_tools.findEvent(flowchart, 'Event1').data.params.data['count'],
    #         'index': event_tools.findEvent(flowchart, 'Event1').data.params.data['index'],
    #         'autoEquip': False
    #     }),
    #     ('Link', 'GenericItemGetSequenceByKey', {
    #         'itemKey': event_tools.findEvent(flowchart, 'Event1').data.params.data['prizeKey'],
    #         'keepCarry': False,
    #         'messageEntry': ''
    #     })
    # ], 'Event5')

    swordGet = item_get.insertSetItemFlag(flowchart, 'SwordLv1', None, None)
    swordContentCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'SwordLv1'}, {0: swordGet, 1: None})
    
    shieldGet = item_get.insertSetItemFlag(flowchart, 'Shield', None, None)
    shieldContentCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Shield'}, {0: shieldGet, 1: swordContentCheck})

    braceletGet = item_get.insertSetItemFlag(flowchart, 'PowerBraceletLv1', None, None)
    braceletContentCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'PowerBraceletLv1'}, {0: braceletGet, 1: shieldContentCheck})

    # powderCapacityGet = item_get.insertSetItemFlag(flowchart, 'MagicPowder_MaxUp', None, None)
    # powderCapacityCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'MagicPowder_MaxUp'}, {0: powderCapacityGet, 1: braceletContentCheck})

    # bombCapacityGet = item_get.insertSetItemFlag(flowchart, 'Bomb_MaxUp', None, None)
    # bombCapacityCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Bomb_MaxUp'}, {0: bombCapacityGet, 1: powderCapacityCheck})

    # arrowCapacityGet = item_get.insertSetItemFlag(flowchart, 'Arrow_MaxUp', None, None)
    # arrowCapacityCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Arrow_MaxUp'}, {0: arrowCapacityGet, 1: bombCapacityCheck})

    # redTunicGet = item_get.insertSetItemFlag(flowchart, 'ClothesRed', None, None)
    # redTunicCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'ClothesRed'}, {0: redTunicGet, 1: arrowCapacityCheck})

    # blueTunicGet = item_get.insertSetItemFlag(flowchart, 'ClothesBlue', None, None)
    # blueTunicCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'ClothesBlue'}, {0: blueTunicGet, 1: redTunicCheck})

    harpGet = item_get.insertSetItemFlag(flowchart, 'SurfHarp', None, None)
    harpCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'SurfHarp'}, {0: harpGet, 1: braceletContentCheck})

    yoshiGet = item_get.insertSetItemFlag(flowchart, 'YoshiDoll', None, None)
    yoshiCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'YoshiDoll'}, {0: yoshiGet, 1: harpCheck})

    ribbonGet = item_get.insertSetItemFlag(flowchart, 'Ribbon', None, None)
    ribbonCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Ribbon'}, {0: ribbonGet, 1: yoshiCheck})

    dogFoodGet = item_get.insertSetItemFlag(flowchart, 'DogFood', None, None)
    dogFoodCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'DogFood'}, {0: dogFoodGet, 1: ribbonCheck})

    bananasGet = item_get.insertSetItemFlag(flowchart, 'Bananas', None, None)
    bananasCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Bananas'}, {0: bananasGet, 1: dogFoodCheck})

    stickGet = item_get.insertSetItemFlag(flowchart, 'Stick', None, None)
    stickCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Stick'}, {0: stickGet, 1: bananasCheck})

    honeycombGet = item_get.insertSetItemFlag(flowchart, 'Honeycomb', None, None)
    honeycombCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Honeycomb'}, {0: honeycombGet, 1: stickCheck})

    pineappleGet = item_get.insertSetItemFlag(flowchart, 'Pineapple', None, None)
    pineappleCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Pineapple'}, {0: pineappleGet, 1: honeycombCheck})

    hibiscusGet = item_get.insertSetItemFlag(flowchart, 'Hibiscus', None, None)
    hibiscusCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Hibiscus'}, {0: hibiscusGet, 1: pineappleCheck})

    letterGet = item_get.insertSetItemFlag(flowchart, 'Letter', None, None)
    letterCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Letter'}, {0: letterGet, 1: hibiscusCheck})

    broomGet = item_get.insertSetItemFlag(flowchart, 'Broom', None, None)
    broomCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Broom'}, {0: broomGet, 1: letterCheck})

    hookGet = item_get.insertSetItemFlag(flowchart, 'FishingHook', None, None)
    hookCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'FishingHook'}, {0: hookGet, 1: broomCheck})

    necklaceGet = item_get.insertSetItemFlag(flowchart, 'PinkBra', None, None)
    necklaceCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'PinkBra'}, {0: necklaceGet, 1: hookCheck})

    scaleGet = item_get.insertSetItemFlag(flowchart, 'MermaidsScale', None, None)
    scaleCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'MermaidsScale'}, {0: scaleGet, 1: necklaceCheck})

    # zapGet = item_get.insertSetItemFlag(flowchart, 'ZapTrap', None, None)
    # zapCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'ZapTrap'}, {0: zapGet, 1: scaleCheck})
    
    bombGet = item_get.insertSetItemFlag(flowchart, 'Bomb', None, None)
    bombCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['prizeKey'], 'value2': 'Bomb'}, {0: bombGet, 1: scaleCheck})

    # ### PRIZE PARAMS CHECK
    # prize6Get = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
    #     {'symbol': 'PrizeGet6'}, bombCheck)
    # prize6IndexCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareInt', {'value1': event_tools.findEvent(flowchart, 'Event1').data.params.data['index'], 'value2': prizesDict['prize6']['index']}, {0: prize6Get, 1: bombCheck})
    # prize6SymbolCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event1').data.params.data['prizeKey'], 'value2': prizesDict['prize6']['symbol']}, {0: prize6IndexCheck, 1: bombCheck})

    # prize5Get = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
    #     {'symbol': 'PrizeGet5'}, bombCheck)
    # prize5IndexCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareInt', {'value1': event_tools.findEvent(flowchart, 'Event1').data.params.data['index'], 'value2': prizesDict['prize5']['index']}, {0: prize5Get, 1: prize6SymbolCheck})
    # prize5SymbolCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event1').data.params.data['prizeKey'], 'value2': prizesDict['prize5']['symbol']}, {0: prize5IndexCheck, 1: prize6SymbolCheck})

    # prize4Get = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
    #     {'symbol': 'PrizeGet4'}, bombCheck)
    # prize4IndexCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareInt', {'value1': event_tools.findEvent(flowchart, 'Event1').data.params.data['index'], 'value2': prizesDict['prize4']['index']}, {0: prize4Get, 1: prize5SymbolCheck})
    # prize4SymbolCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event1').data.params.data['prizeKey'], 'value2': prizesDict['prize4']['symbol']}, {0: prize4IndexCheck, 1: prize5SymbolCheck})

    # prize3Get = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
    #     {'symbol': 'PrizeGet3'}, bombCheck)
    # prize3IndexCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareInt', {'value1': event_tools.findEvent(flowchart, 'Event1').data.params.data['index'], 'value2': prizesDict['prize3']['index']}, {0: prize3Get, 1: prize4SymbolCheck})
    # prize3SymbolCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event1').data.params.data['prizeKey'], 'value2': prizesDict['prize3']['symbol']}, {0: prize3IndexCheck, 1: prize4SymbolCheck})

    # prize2Get = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
    #     {'symbol': 'PrizeGet2'}, bombCheck)
    # prize2IndexCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareInt', {'value1': event_tools.findEvent(flowchart, 'Event1').data.params.data['index'], 'value2': prizesDict['prize2']['index']}, {0: prize2Get, 1: prize3SymbolCheck})
    # prize2SymbolCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event1').data.params.data['prizeKey'], 'value2': prizesDict['prize2']['symbol']}, {0: prize2IndexCheck, 1: prize3SymbolCheck})

    # prize1Get = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
    #     {'symbol': 'PrizeGet1'}, bombCheck)
    # prize1IndexCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareInt', {'value1': event_tools.findEvent(flowchart, 'Event1').data.params.data['index'], 'value2': prizesDict['prize1']['index']}, {0: prize1Get, 1: prize2SymbolCheck})
    # prize1SymbolCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event1').data.params.data['prizeKey'], 'value2': prizesDict['prize1']['symbol']}, {0: prize1IndexCheck, 1: prize2SymbolCheck})

    ### CONNECT CHAIN TO EVENTS
    event_tools.insertEventAfter(flowchart, 'Event3', bombCheck)
    event_tools.insertEventAfter(flowchart, 'Event7', bombCheck)
    event_tools.insertEventAfter(flowchart, 'Event9', bombCheck)



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
