import Tools.event_tools as event_tools
from Randomizers import item_get, data



def makeDatasheetChanges(sheet, reward_num, item_key, item_index, entry_point):
    """Edits the Dampe rewards datasheets to be new items. Progressive items and any items that set flags will not work however"""
    
    sheet['values'][reward_num]['mRewardItem'] = item_key
    sheet['values'][reward_num]['mRewardItemIndex'] = item_index
    sheet['values'][reward_num]['mRewardItemEventEntry'] = entry_point



def makeEventChanges(flowchart):
    """Make Dampe perform inventory and flag checks before and after the reward event"""

    # 0 for HasItem means you do not have the item, 1 means you do

    sword_remove = event_tools.createActionEvent(flowchart, 'Inventory', 'RemoveItem',
        {'itemType': 0}, 'Event39')
    sword2_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 1, 'count': 1}, {0: sword_remove, 1: 'Event39'})
    sword_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.SWORD_FOUND_FLAG}, {0: 'Event39', 1: sword2_check})
    
    shield_remove = event_tools.createActionEvent(flowchart, 'Inventory', 'RemoveItem',
        {'itemType': 2}, sword_flag_check)
    shield2_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 3, 'count': 1}, {0: shield_remove, 1: sword_flag_check})
    shield_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.SHIELD_FOUND_FLAG}, {0: sword_flag_check, 1: shield2_check})

    bracelet_remove = event_tools.createActionEvent(flowchart, 'Inventory', 'RemoveItem',
        {'itemType': 14}, shield_flag_check)
    bracelet2_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 15, 'count': 1}, {0: bracelet_remove, 1: shield_flag_check})
    bracelet_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.BRACELET_FOUND_FLAG}, {0: shield_flag_check, 1: bracelet2_check})
    
    event_tools.insertEventAfter(flowchart, 'Event43', bracelet_flag_check)
    afterRewardEvents(flowchart, bracelet_flag_check)



def afterRewardEvents(flowchart, loop_event):
    """Handling the after reward inventory and flag checks separately to make this easier to read"""

    # 0 for HasItem means you do not have the item, 1 means you do

    sword2_give = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItem',
        {'itemType': 1, 'count': 1, 'autoEquip': False}, 'Event42')
    sword1_give = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItem',
        {'itemType': 0, 'count': 1, 'autoEquip': False}, 'Event42')
    sword1_flag = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
        {'symbol': data.SWORD_FOUND_FLAG, 'value': True}, 'Event42')
    first_sword_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 0, 'count': 1}, {0: 'Event42', 1: sword1_flag})
    sword_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 0, 'count': 1}, {0: sword1_give, 1: sword2_give})
    sword_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.SWORD_FOUND_FLAG}, {0: first_sword_check, 1: sword_check})
    
    shield2_give = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItem',
        {'itemType': 3, 'count': 1, 'autoEquip': False}, sword_flag_check)
    shield1_give = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItem',
        {'itemType': 2, 'count': 1, 'autoEquip': False}, sword_flag_check)
    shield1_flag = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
        {'symbol': data.SHIELD_FOUND_FLAG, 'value': True}, sword_flag_check)
    first_shield_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 2, 'count': 1}, {0: sword_flag_check, 1: shield1_flag})
    shield_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 2, 'count': 1}, {0: shield1_give, 1: shield2_give})
    shield_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.SHIELD_FOUND_FLAG}, {0: first_shield_check, 1: shield_check})
    
    bracelet2_give = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItem',
        {'itemType': 15, 'count': 1, 'autoEquip': False}, shield_flag_check)
    bracelet1_give = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItem',
        {'itemType': 14, 'count': 1, 'autoEquip': False}, shield_flag_check)
    bracelet1_flag = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
        {'symbol': data.BRACELET_FOUND_FLAG, 'value': True}, shield_flag_check)
    first_bracelet_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 14, 'count': 1}, {0: shield_flag_check, 1: bracelet1_flag})
    bracelet_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 14, 'count': 1}, {0: bracelet1_give, 1: bracelet2_give})
    bracelet_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.BRACELET_FOUND_FLAG}, {0: first_bracelet_check, 1: bracelet_check})
    
    bomb_flag = event_tools.createActionChain(flowchart, None, [
        ('EventFlags', 'SetFlag', {'symbol': data.BOMBS_FOUND_FLAG, 'value': True}),
        ('Inventory', 'AddItem', {'itemType': 4, 'count': 20, 'autoEquip': False})
    ], bracelet_flag_check)
    bomb_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 4, 'count': 1}, {0: bracelet_flag_check, 1: bomb_flag})
    
    cello_flags = event_tools.createActionChain(flowchart, None, [
        ('EventFlags', 'SetFlag', {'symbol': 'BowWowEvent', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'DoorOpen_Btl_MoriblinCave_2A', 'value': False}),
        ('EventFlags', 'SetFlag', {'symbol': 'DoorOpen_Btl_MoriblinCave_1A', 'value': False})
    ], bomb_check)
    cello_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': 'BowWowEvent'}, {0: cello_flags, 1: bomb_check})
    cello_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 45, 'count': 1}, {0: bomb_check, 1: cello_flag_check})

    harp_flags = event_tools.createActionChain(flowchart, None, [
        ('EventFlags', 'SetFlag', {'symbol': 'GhostClear1', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'Ghost2_Clear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'Ghost3_Clear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'Ghost4_Clear', 'value': True})
    ], cello_check)
    harp_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 48, 'count': 1}, {0: cello_check, 1: harp_flags})
    
    lens_flag_set = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
        {'symbol': data.LENS_FOUND_FLAG, 'value': True}, harp_check)
    lens_give = event_tools.createActionEvent(flowchart, 'Inventory', 'SetWarashibeItem',
        {'itemType': 15}, harp_check)
    lens_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.LENS_FOUND_FLAG}, {0: harp_check, 1: lens_give})
    lens_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 44, 'count': 1}, {0: lens_flag_check, 1: lens_flag_set})
    
    scale_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'SetWarashibeItem', {'itemType': 0}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeMermaidsScaleGet', 'value': True})
    ], lens_check)
    scale_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 43, 'count': 1}, {0: lens_check, 1: scale_give})
    
    necklace_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'SetWarashibeItem', {'itemType': 0}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeNecklaceGet', 'value': True})
    ], scale_check)
    necklace_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 41, 'count': 1}, {0: scale_check, 1: necklace_give})
    
    hook_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'SetWarashibeItem', {'itemType': 0}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeFishingHookGet', 'value': True})
    ], necklace_check)
    hook_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 40, 'count': 1}, {0: necklace_check, 1: hook_give})
    
    broom_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'SetWarashibeItem', {'itemType': 0}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeBroomGet', 'value': True})
    ], hook_check)
    broom_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 39, 'count': 1}, {0: hook_check, 1: broom_give})
    
    letter_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'SetWarashibeItem', {'itemType': 0}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeLetterGet', 'value': True})
    ], broom_check)
    letter_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 38, 'count': 1}, {0: broom_check, 1: letter_give})

    hibiscus_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'SetWarashibeItem', {'itemType': 0}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeHibiscusGet', 'value': True})
    ], letter_check)
    hibiscus_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 37, 'count': 1}, {0: letter_check, 1: hibiscus_give})

    pineapple_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'SetWarashibeItem', {'itemType': 0}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradePineappleGet', 'value': True})
    ], hibiscus_check)
    pineapple_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 36, 'count': 1}, {0: hibiscus_check, 1: pineapple_give})

    honeycomb_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'SetWarashibeItem', {'itemType': 0}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeHoneycombGet', 'value': True})
    ], pineapple_check)
    honeycomb_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 35, 'count': 1}, {0: pineapple_check, 1: honeycomb_give})

    stick_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'SetWarashibeItem', {'itemType': 0}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeStickGet', 'value': True})
    ], honeycomb_check)
    stick_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 34, 'count': 1}, {0: honeycomb_check, 1: stick_give})

    bananas_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'SetWarashibeItem', {'itemType': 0}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeBananasGet', 'value': True})
    ], stick_check)
    bananas_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 33, 'count': 1}, {0: stick_check, 1: bananas_give})

    dogfood_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'SetWarashibeItem', {'itemType': 0}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeDogFoodGet', 'value': True})
    ], bananas_check)
    dogfood_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 32, 'count': 1}, {0: bananas_check, 1: dogfood_give})

    ribbon_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'SetWarashibeItem', {'itemType': 0}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeRibbonGet', 'value': True})
    ], dogfood_check)
    ribbon_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 31, 'count': 1}, {0: dogfood_check, 1: ribbon_give})

    yoshi_give = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'SetWarashibeItem', {'itemType': 0}),
        ('EventFlags', 'SetFlag', {'symbol': 'TradeYoshiDollGet', 'value': True})
    ], ribbon_check)
    yoshi_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 30, 'count': 1}, {0: ribbon_check, 1: yoshi_give})

    event_tools.insertEventAfter(flowchart, 'Event39', yoshi_check)
    event_tools.setSwitchEventCase(flowchart, 'Event42', 1, loop_event)
