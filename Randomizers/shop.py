import Tools.event_tools as event_tools
from Randomizers import item_get



def makeDatasheetChanges(sheet, placements, item_defs):
    """Edit the ShopItem datasheet to for the new items. Incomplete, was only testing"""

    for slot in sheet['values']:
        if slot['mIndex'] == 2:
            item = placements['shop-slot3-1st'] # shovel
            slot['mGoods'][0]['mItem'] = 'ShopShovel'
            slot['mGoods'][0]['mModelPath'] = f"actor/{item_defs[item]['model-path']}"
            slot['mGoods'][0]['mModelName'] = item_defs[item]['model-name']
            slot['mGoods'][0]['mIndex'] = -1

            item = placements['shop-slot3-2nd'] # bow
            slot['mGoods'][1]['mItem'] = 'ShopBow'
            slot['mGoods'][1]['mModelPath'] = f"actor/{item_defs[item]['model-path']}"
            slot['mGoods'][1]['mModelName'] = item_defs[item]['model-name']
            slot['mGoods'][1]['mIndex'] = -1
        
        if slot['mIndex'] == 5:
            item = placements['shop-slot6'] # heart piece
            slot['mGoods'][0]['mItem'] = 'ShopHeart'
            slot['mGoods'][0]['mModelPath'] = f"actor/{item_defs[item]['model-path']}"
            slot['mGoods'][0]['mModelName'] = item_defs[item]['model-name']
            slot['mGoods'][0]['mIndex'] = -1



def makeBuyingEventChanges(flowchart, placements, item_defs):
    """edit the ToolShopKeeper event flow for the new items. Incomplete, was only testing"""

    # shovel
    item = placements['shop-slot3-1st']
    item_key = item_defs[item]['item-key']
    item_index = placements['indexes']['shop-slot3-1st'] if 'shop-slot3-1st' in placements['indexes'] else -1
    event_tools.setSwitchEventCase(flowchart, 'Event50', 1, 'Event52')
    event_tools.insertEventAfter(flowchart, 'Event52', 'Event61')
    item_get.insertItemGetAnimation(flowchart, item_key, item_index, 'Event53', 'Event43')
    # event_tools.findEvent(flowchart, 'Event43').data.params.data['symbol'] = 'ShopShovelGet'

    # bow
    item = placements['shop-slot3-2nd']
    item_key = item_defs[item]['item-key']
    item_index = placements['indexes']['shop-slot3-2nd'] if 'shop-slot3-2nd' in placements['indexes'] else -1
    event_tools.setSwitchEventCase(flowchart, 'Event12', 1, 'Event14')
    event_tools.insertEventAfter(flowchart, 'Event14', 'Event65')
    item_get.insertItemGetAnimation(flowchart, item_key, item_index, 'Event17', 'Event151')
    # event_tools.findEvent(flowchart, 'Event151').data.params.data['symbol'] = 'ShopBowGet'

    # heart piece
    item = placements['shop-slot6']
    item_key = item_defs[item]['item-key']
    item_index = placements['indexes']['shop-slot6'] if 'shop-slot6' in placements['indexes'] else -1
    set_flag = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
        {'symbol': 'ShopHeartGet', 'value': True})
    item_get.insertItemGetAnimation(flowchart, item_key, item_index, 'Event122', set_flag)



def makeStealingEventChanges(flowchart, placements, item_defs):
    # if placements['settings']['fast-stealing']:
    #     end_event = 'AutoEvent22'
    # else:
    #     end_event = 'Event774'
    
    remove_heart = event_tools.createActionChain(flowchart, None, [
        ('EventFlags', 'SetFlag', {'symbol': 'ShopHeartGet', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'ShopHeartSteal', 'value': False}),
    ], None)
    give_heart = item_get.insertItemGetAnimation(flowchart,
        item_defs[placements['shop-slot6']]['item-key'],
        placements['indexes']['shop-slot6'] if 'shop-slot6' in placements['indexes'] else -1,
        before=None, after=remove_heart
    )
    check_heart = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': 'ShopHeartSteal'}, {0: None, 1: give_heart})

    remove_bow = event_tools.createActionChain(flowchart, None, [
        ('EventFlags', 'SetFlag', {'symbol': 'ShopBowGet', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'BowGet', 'value': False}),
    ], check_heart)
    give_bow = item_get.insertItemGetAnimation(flowchart,
        item_defs[placements['shop-slot3-2nd']]['item-key'],
        placements['indexes']['shop-slot3-2nd'] if 'shop-slot3-2nd' in placements['indexes'] else -1,
        before=None, after=remove_bow
    )
    check_bow = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': 'BowGet'}, {0: check_heart, 1: give_bow})
    
    remove_shovel = event_tools.createActionChain(flowchart, None, [
        ('EventFlags', 'SetFlag', {'symbol': 'ShopShovelGet', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'ScoopGet', 'value': False}),
    ], check_bow)
    give_shovel = item_get.insertItemGetAnimation(flowchart,
        item_defs[placements['shop-slot3-1st']]['item-key'],
        placements['indexes']['shop-slot3-1st'] if 'shop-slot3-1st' in placements['indexes'] else -1,
        before=None, after=remove_shovel
    )
    check_shovel = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': 'ScoopGet'}, {0: check_bow, 1: give_shovel})
    
    event_tools.insertEventAfter(flowchart, 'Event57', check_shovel)
