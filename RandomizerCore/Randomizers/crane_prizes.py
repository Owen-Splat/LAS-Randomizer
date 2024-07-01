from RandomizerCore.Randomizers import data
import RandomizerCore.Tools.event_tools as event_tools
import RandomizerCore.Tools.oead_tools as oead_tools
import shutil
import copy


prizes_dict = {}



def makeDatasheetChanges(sheet, settings):
    """Edits conditions in the Trendy prizes datasheet. Trendy is still a WIP"""
    
    # PRIZE PLACEMENTS
    # type 1 is the lower level, index 0 on the left and index 2 on the right
    # type 2 is upper level, index 0 on the left and index 1 on the right

    # symbols = []
    # sheet['values'].pop(7) # remove yoshi doll
    for prize in sheet['values']:

        # symbols.append(prize['symbol'])

        # Bombs should not be obtainable until you have bombs if shuffled bombs is on
        if prize['symbol'] == 'Bomb' and settings['shuffle-bombs']:
            prize['layouts'][0]['conditions'][0] = {'category': 1, 'parameter': data.BOMBS_FOUND_FLAG}
            continue

        # Shield should not be obtainable until you find your first shield
        if prize['symbol'] == 'Shield':
            prize['layouts'][0]['conditions'].append({'category': 1, 'parameter': data.SHIELD_FOUND_FLAG})
            continue

        if prize['symbol'] == 'RupeeRed':
            # Now because the 2 non featured prizes in this slot have conditions, nothing will be in this slot
            # Lets fix this by adding RupeeRed prizes to the slot that will be met automatically
            prize['layouts'].append(oead_tools.dictToStruct({
                'itemIndex': -1,
                'conditions': [],
                'place': {'type': 2, 'index': 1}
            }))

            if settings['shuffle-bombs']:
                prize['layouts'][2]['conditions'].append({'category': 1, 'parameter': f'!{data.BOMBS_FOUND_FLAG}'})
            else:
                prize['layouts'][2]['conditions'].append({'category': 2, 'parameter': '!SurfHarp'})
            
            prize['layouts'][2]['conditions'].append({'category': 1, 'parameter': f'!{data.SHIELD_FOUND_FLAG}'})

            # We are removing Yoshi from being considered as a featured prize
            # So we want to make the red rupee that would otherwise replace it require the yoshi gotten flag
            prize['layouts'][0]['conditions'].append({'category': 1, 'parameter': 'TradeYoshiDollGet'})
            continue
        
        # Make the YoshiDoll prize go away once you get it since we don't actually keep the item
        if prize['symbol'] == 'YoshiDoll':
            prize['layouts'][0]['conditions'].append({'category': 1, 'parameter': '!TradeYoshiDollGet'})
            prize['options']['isFeatured'] = False
            continue
        
        # # get rid of the instrument requirements if fast-trendy is on
        # if prize['symbol'] == 'HeartPiece' and placements['settings']['fast-trendy']:
        #     prize['layouts'][1]['conditions'].pop(0)
        #     continue
        
        # if prize['symbol'] == 'SecretSeashell' and placements['settings']['fast-trendy']:
        #     prize['layouts'][1]['conditions'].pop(0)
        #     continue
        
        # if prize['symbol'] == 'PanelDungeonPiece' and placements['settings']['fast-trendy']:
        #     prize['layouts'][0]['conditions'].pop(0)
        #     continue

        # SmallBowWow (Ciao Ciao): Remove the condition of HintYosshi. It's unnecessary and can lead to a softlock
        if prize['symbol'] == 'SmallBowWow':
            prize['layouts'][0]['conditions'].pop(0)
            continue

        # BowWow: Remove the ShadowClear condition. This was stupid in vanilla and it's even worse for rando.
        if prize['symbol'] == 'BowWow':
            prize['layouts'][0]['conditions'].pop(0)
            continue
    
    # return

    # ### ADD RANDOMIZED PRIZES
    # total_syms = len(symbols)

    # if item_defs[placements['trendy-prize-1']]['model-name'] not in symbols:
    #     prize1 = copy.deepcopy(oead_tools.parseStruct(sheet['values'][7]))
    #     prize1['symbol'] = item_defs[placements['trendy-prize-1']]['model-name']
    #     prize1['layouts'][0]['itemIndex'] = placements['indexes']['trendy-prize-1'] if 'trendy-prize-1' in placements['indexes'] else -1
    #     prize1['layouts'][0]['conditions'].append({'category': 1, 'parameter': '!PrizeGet1'})
    #     sheet['values'].append(oead_tools.dictToStruct(prize1))
    #     prizes_dict['prize1'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize1['symbol'], 'index': prize1['layouts'][0]['itemIndex']}
    #     symbols.append(prize1['symbol'])
    #     total_syms += 1
    # else:
    #     for prize in sheet['values']:
    #         if prize['symbol'] == item_defs[placements['trendy-prize-1']]['model-name']:
    #             prize['layouts'].append(oead_tools.dictToStruct({
    #                 'itemIndex': placements['indexes']['trendy-prize-1'] if 'trendy-prize-1' in placements['indexes'] else -1,
    #                 'conditions': [],
    #                 'conditions': [{'category': 1, 'parameter': '!PrizeGet1'}],
    #                 'place': {'type': 1, 'index': 0},
    #             }))
    #             layoutNum = len(prize['layouts']) - 1
    #             break
    #     prizes_dict['prize1'] = {
    #         'cranePrizeId': symbols.index(item_defs[placements['trendy-prize-1']]['model-name']),
    #         'layoutIndex': layoutNum,
    #         'symbol': prize['symbol'],
    #         'index': prize['layouts'][layoutNum]['itemIndex']}


    # if item_defs[placements['trendy-prize-2']]['model-name'] not in symbols:
    #     prize2 = copy.deepcopy(oead_tools.parseStruct(sheet['values'][7]))
    #     prize2['symbol'] = item_defs[placements['trendy-prize-2']]['model-name']
    #     prize2['layouts'][0]['itemIndex'] = placements['indexes']['trendy-prize-2'] if 'trendy-prize-2' in placements['indexes'] else -1
    #     prize2['layouts'][0]['place'] = {'type': 1, 'index': 1}
    #     # prize2['layouts'][0]['conditions'].append({'category': 1, 'parameter': '!PrizeGet2'})
    #     # prize2['layouts'][0]['gettingFlag'] = 'PrizeGet2'
    #     sheet['values'].append(oead_tools.dictToStruct(prize2))
    #     prizes_dict['prize2'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize2['symbol'], 'index': prize2['layouts'][0]['itemIndex']}
    #     symbols.append(item_defs[placements['trendy-prize-1']]['model-name'])
    #     total_syms += 1
    # else:
    #     for prize in sheet['values']:
    #         if prize['symbol'] == item_defs[placements['trendy-prize-2']]['model-name']:
    #             prize['layouts'].append(oead_tools.dictToStruct({
    #                 'itemIndex': placements['indexes']['trendy-prize-2'] if 'trendy-prize-2' in placements['indexes'] else -1,
    #                 'conditions': [],
    #                 # 'conditions': [{'category': 1, 'parameter': '!PrizeGet2'}],
    #                 'place': {'type': 1, 'index': 1},
    #                 # 'gettingFlag': 'PrizeGet2'
    #             }))
    #             layoutNum = len(prize['layouts']) - 1
    #             break
    #     prizes_dict['prize2'] = {
    #         'cranePrizeId': symbols.index(item_defs[placements['trendy-prize-2']]['model-name']),
    #         'layoutIndex': layoutNum,
    #         'symbol': prize['symbol'],
    #         'index': prize['layouts'][layoutNum]['itemIndex']}
    

    # if item_defs[placements['trendy-prize-3']]['model-name'] not in symbols:
    #     prize3 = copy.deepcopy(oead_tools.parseStruct(sheet['values'][7]))
    #     prize3['symbol'] = item_defs[placements['trendy-prize-3']]['model-name']
    #     prize3['layouts'][0]['itemIndex'] = placements['indexes']['trendy-prize-3'] if 'trendy-prize-3' in placements['indexes'] else -1
    #     prize3['layouts'][0]['place'] = {'type': 1, 'index': 1}
    #     # prize3['layouts'][0]['conditions'].append({'category': 1, 'parameter': 'PrizeGet2'})
    #     # prize3['layouts'][0]['conditions'].append({'category': 1, 'parameter': '!PrizeGet3'})
    #     # prize3['layouts'][0]['gettingFlag'] = 'PrizeGet3'
    #     sheet['values'].append(oead_tools.dictToStruct(prize3))
    #     prizes_dict['prize3'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize3['symbol'], 'index': prize3['layouts'][0]['itemIndex']}
    #     symbols.append(item_defs[placements['trendy-prize-1']]['model-name'])
    #     total_syms += 1
    # else:
    #     for prize in sheet['values']:
    #         if prize['symbol'] == item_defs[placements['trendy-prize-3']]['model-name']:
    #             prize['layouts'].append(oead_tools.dictToStruct({
    #                 'itemIndex': placements['indexes']['trendy-prize-3'] if 'trendy-prize-3' in placements['indexes'] else -1,
    #                 'conditions': [
    #                     # {'category': 1, 'parameter': 'PrizeGet2'},
    #                     # {'category': 1, 'parameter': '!PrizeGet3'}
    #                 ],
    #                 'place': {'type': 1, 'index': 1},
    #                 # 'gettingFlag': 'PrizeGet3'
    #             }))
    #             layoutNum = len(prize['layouts']) - 1
    #             break
    #     prizes_dict['prize3'] = {
    #         'cranePrizeId': symbols.index(item_defs[placements['trendy-prize-3']]['model-name']),
    #         'layoutIndex': layoutNum,
    #         'symbol': prize['symbol'],
    #         'index': prize['layouts'][layoutNum]['itemIndex']}


    # if item_defs[placements['trendy-prize-4']]['model-name'] not in symbols:
    #     prize4 = copy.deepcopy(oead_tools.parseStruct(sheet['values'][7]))
    #     prize4['symbol'] = item_defs[placements['trendy-prize-4']]['model-name']
    #     prize4['layouts'][0]['itemIndex'] = placements['indexes']['trendy-prize-4'] if 'trendy-prize-4' in placements['indexes'] else -1
    #     prize4['layouts'][0]['place'] = {'type': 2, 'index': 0}
    #     # prize4['layouts'][0]['conditions'].append({'category': 1, 'parameter': 'PrizeGet3'})
    #     # prize4['layouts'][0]['conditions'].append({'category': 1, 'parameter': '!PrizeGet4'})
    #     if not placements['settings']['fast-trendy']:
    #         prize4['layouts'][0]['conditions'].append({'category': 2, 'parameter': 'ConchHorn'})
    #     # prize4['layouts'][0]['gettingFlag'] = 'PrizeGet4'
    #     sheet['values'].append(oead_tools.dictToStruct(prize4))
    #     prizes_dict['prize4'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize4['symbol'], 'index': prize4['layouts'][0]['itemIndex']}
    #     symbols.append(item_defs[placements['trendy-prize-1']]['model-name'])
    #     total_syms += 1
    # else:
    #     for prize in sheet['values']:
    #         if prize['symbol'] == item_defs[placements['trendy-prize-4']]['model-name']:
    #             prize['layouts'].append(oead_tools.dictToStruct({
    #                 'itemIndex': placements['indexes']['trendy-prize-4'] if 'trendy-prize-4' in placements['indexes'] else -1,
    #                 'conditions': [
    #                     # {'category': 1, 'parameter': 'PrizeGet3'},
    #                     # {'category': 1, 'parameter': '!PrizeGet4'}
    #                 ],
    #                 'place': {'type': 2, 'index': 0},
    #                 # 'gettingFlag': 'PrizeGet4'
    #             }))
    #             layoutNum = len(prize['layouts']) - 1
    #             if not placements['settings']['fast-trendy']:
    #                 prize['layouts'][layoutNum]['conditions'].append({'category': 2, 'parameter': 'ConchHorn'})
    #             break
    #     prizes_dict['prize4'] = {
    #         'cranePrizeId': symbols.index(item_defs[placements['trendy-prize-4']]['model-name']),
    #         'layoutIndex': layoutNum,
    #         'symbol': prize['symbol'],
    #         'index': prize['layouts'][layoutNum]['itemIndex']}


    # if item_defs[placements['trendy-prize-5']]['model-name'] not in symbols:
    #     prize5 = copy.deepcopy(oead_tools.parseStruct(sheet['values'][7]))
    #     prize5['symbol'] = item_defs[placements['trendy-prize-5']]['model-name']
    #     prize5['layouts'][0]['itemIndex'] = placements['indexes']['trendy-prize-5'] if 'trendy-prize-5' in placements['indexes'] else -1
    #     prize5['layouts'][0]['place'] = {'type': 2, 'index': 1}
    #     # prize5['layouts'][0]['conditions'].append({'category': 1, 'parameter': 'PrizeGet4'})
    #     # prize5['layouts'][0]['conditions'].append({'category': 1, 'parameter': '!PrizeGet5'})
    #     if not placements['settings']['fast-trendy']:
    #         prize5['layouts'][0]['conditions'].append({'category': 2, 'parameter': 'SeaLilysBell'})
    #     # prize5['layouts'][0]['gettingFlag'] = 'PrizeGet5'
    #     sheet['values'].append(oead_tools.dictToStruct(prize5))
    #     prizes_dict['prize5'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize5['symbol'], 'index': prize5['layouts'][0]['itemIndex']}
    #     symbols.append(item_defs[placements['trendy-prize-1']]['model-name'])
    #     total_syms += 1
    # else:
    #     for prize in sheet['values']:
    #         if prize['symbol'] == item_defs[placements['trendy-prize-5']]['model-name']:
    #             prize['layouts'].append(oead_tools.dictToStruct({
    #                 'itemIndex': placements['indexes']['trendy-prize-5'] if 'trendy-prize-5' in placements['indexes'] else -1,
    #                 'conditions': [
    #                     # {'category': 1, 'parameter': 'PrizeGet4'},
    #                     # {'category': 1, 'parameter': '!PrizeGet5'}
    #                 ],
    #                 'place': {'type': 2, 'index': 1},
    #                 # 'gettingFlag': 'PrizeGet5'
    #             }))
    #             layoutNum = len(prize['layouts']) - 1
    #             if not placements['settings']['fast-trendy']:
    #                 prize['layouts'][layoutNum]['conditions'].append({'category': 2, 'parameter': 'SeaLilysBell'})
    #             break
    #     prizes_dict['prize5'] = {
    #         'cranePrizeId': symbols.index(item_defs[placements['trendy-prize-5']]['model-name']),
    #         'layoutIndex': layoutNum,
    #         'symbol': prize['symbol'],
    #         'index': prize['layouts'][layoutNum]['itemIndex']}


    # if item_defs[placements['trendy-prize-6']]['model-name'] not in symbols:
    #     prize6 = copy.deepcopy(oead_tools.parseStruct(sheet['values'][7]))
    #     prize6['symbol'] = item_defs[placements['trendy-prize-6']]['model-name']
    #     prize6['layouts'][0]['itemIndex'] = placements['indexes']['trendy-prize-6'] if 'trendy-prize-6' in placements['indexes'] else -1
    #     prize6['layouts'][0]['place'] = {'type': 2, 'index': 0}
    #     # prize6['layouts'][0]['conditions'].append({'category': 1, 'parameter': 'PrizeGet5'})
    #     # prize6['layouts'][0]['conditions'].append({'category': 1, 'parameter': '!PrizeGet6'})
    #     if not placements['settings']['fast-trendy']:
    #         prize6['layouts'][0]['conditions'].append({'category': 2, 'parameter': 'SurfHarp'})
    #     # prize6['layouts'][0]['gettingFlag'] = 'PrizeGet6'
    #     sheet['values'].append(oead_tools.dictToStruct(prize6))
    #     prizes_dict['prize6'] = {'cranePrizeId': total_syms, 'layoutIndex': 0, 'symbol': prize6['symbol'], 'index': prize6['layouts'][0]['itemIndex']}
    #     symbols.append(item_defs[placements['trendy-prize-1']]['model-name'])
    #     total_syms += 1
    # else:
    #     for prize in sheet['values']:
    #         if prize['symbol'] == item_defs[placements['trendy-prize-6']]['model-name']:
    #             prize['layouts'].append(oead_tools.dictToStruct({
    #                 'itemIndex': placements['indexes']['trendy-prize-6'] if 'trendy-prize-6' in placements['indexes'] else -1,
    #                 'conditions': [
    #                     # {'category': 1, 'parameter': 'PrizeGet5'},
    #                     # {'category': 1, 'parameter': '!PrizeGet6'}
    #                 ],
    #                 'place': {'type': 2, 'index': 0},
    #                 # 'gettingFlag': 'PrizeGet6'
    #             }))
    #             layoutNum = len(prize['layouts']) - 1
    #             if not placements['settings']['fast-trendy']:
    #                 prize['layouts'][layoutNum]['conditions'].append({'category': 2, 'parameter': 'SurfHarp'})
    #             break
    #     prizes_dict['prize6'] = {
    #         'cranePrizeId': symbols.index(item_defs[placements['trendy-prize-6']]['model-name']),
    #         'layoutIndex': layoutNum,
    #         'symbol': prize['symbol'],
    #         'index': prize['layouts'][layoutNum]['itemIndex']}



def changePrizeGroups(sheet1):
    # print(prizes_dict)
    
    sheet1['values'].pop(0) # remove yoshi doll
    
    # sheet1['values'][0]['cranePrizeId'] = prizes_dict['prize1']['cranePrizeId']
    # sheet1['values'][0]['layoutIndex'] = prizes_dict['prize1']['layoutIndex']
    
    # sheet2['values'][0]['cranePrizeId'] = prizes_dict['prize2']['cranePrizeId']
    # sheet2['values'][0]['layoutIndex'] = prizes_dict['prize2']['layoutIndex']

    # sheet2['values'][1]['cranePrizeId'] = prizes_dict['prize3']['cranePrizeId']
    # sheet2['values'][1]['layoutIndex'] = prizes_dict['prize3']['layoutIndex']

    # sheet2['values'][2]['cranePrizeId'] = prizes_dict['prize4']['cranePrizeId']
    # sheet2['values'][2]['layoutIndex'] = prizes_dict['prize4']['layoutIndex']

    # sheet2['values'][3]['cranePrizeId'] = prizes_dict['prize5']['cranePrizeId']
    # sheet2['values'][3]['layoutIndex'] = prizes_dict['prize5']['layoutIndex']

    # sheet2['values'][4]['cranePrizeId'] = prizes_dict['prize6']['cranePrizeId']
    # sheet2['values'][4]['layoutIndex'] = prizes_dict['prize6']['layoutIndex']



def makeEventChanges(flowchart, settings):

    # if settings['fast-trendy']:
    #     event_tools.findEvent(flowchart, 'Event5').data.params.data['prizeType'] = 10
    
    yoshi_lens_get = event_tools.createActionChain(flowchart, None, [
        ('EventFlags', 'SetFlag', {'symbol': 'TradeYoshiDollGet', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': data.LENS_FOUND_FLAG, 'value': True}),
        ('Inventory', 'SetWarashibeItem', {'itemType': 15})
    ], None)
    yoshi_get = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'SetWarashibeItem', {'itemType': 0}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeYoshiDollGet', 'value': True})
    ], None)
    lens_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.LENS_FOUND_FLAG}, {0: yoshi_get, 1: yoshi_lens_get})
    yoshi_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 30, 'count': 1}, {0: None, 1: lens_flag_check})

    ### CONNECT LENS CHECK TO EVENTS
    event_tools.insertEventAfter(flowchart, 'Event3', yoshi_check)
    event_tools.insertEventAfter(flowchart, 'Event7', yoshi_check)
    event_tools.insertEventAfter(flowchart, 'Event9', yoshi_check)



# def makePrizeModels(romPath, outDir, placements, itemDefs):
#     """Since prizes have their own, separate models, we copy the needed item models over and rename them to Prize{model}.bfres"""

#     prizes = [key for key in placements.keys() if key.startswith('trendy-prize')]
#     prizes.remove('trendy-prize-final')
    
#     for prize in prizes:
#         path = itemDefs[placements[prize]]['model-path']
#         model = itemDefs[placements[prize]]['model-name']
#         try:
#             shutil.copy(f'{romPath}/region_common/actor/{path}', f'{outDir}/Romfs/region_common/actor/Prize{model}.bfres')
#         except FileNotFoundError:
#             shutil.copy(f'{outDir}/Romfs/region_common/actor/{path}', f'{outDir}/Romfs/region_common/actor/Prize{model}.bfres')
