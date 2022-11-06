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
    sword_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.SWORD2_FOUND_FLAG}, {0: sword_remove, 1: 'Event39'})
    sword_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 0, 'count': 1}, {0: 'Event39', 1: sword_flag_check})
    
    shield_remove = event_tools.createActionEvent(flowchart, 'Inventory', 'RemoveItem',
        {'itemType': 2}, sword_check)
    shield_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.SHIELD2_FOUND_FLAG}, {0: shield_remove, 1: sword_check})
    shield_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 2, 'count': 1}, {0: sword_check, 1: shield_flag_check})
    
    bracelet_remove = event_tools.createActionEvent(flowchart, 'Inventory', 'RemoveItem',
        {'itemType': 14}, shield_check)
    bracelet_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.SWORD2_FOUND_FLAG}, {0: bracelet_remove, 1: shield_check})
    bracelet_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 14, 'count': 1}, {0: shield_check, 1: bracelet_flag_check})
    
    lens_flag_set = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
        {'symbol': 'DampeLens', 'value': True}, bracelet_check)
    lens_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
        {'itemType': 44, 'count': 1}, {0: bracelet_check, 1: lens_flag_set})
    
    event_tools.insertEventAfter(flowchart, 'Event43', lens_check)
