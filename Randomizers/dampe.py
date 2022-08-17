import Tools.event_tools as event_tools
from Randomizers import item_get



def makeDatasheetChanges(sheet, reward_num, item_key, item_index, entry_point):
    """Edits the Dampe rewards datasheets to be new items. Progressive items and any items that set flags will not work however"""
    
    sheet['values'][reward_num]['mRewardItem'] = item_key
    sheet['values'][reward_num]['mRewardItemIndex'] = item_index
    sheet['values'][reward_num]['mRewardItemEventEntry'] = entry_point



def makeEventChanges(flowchart, placements, item_defs):
    """Adds custom entries to the Item flowchart that normally controls what dialog to display. 
    The messageEntry parameter in the GenericItemGetSequenceByKey event uses this"""

    event_tools.addEntryPoint(flowchart, 'DampePage1')
    item_key = item_defs[placements['dampe-page-1']]['item-key']
    item_index = placements['indexes']['dampe-page-1'] if 'dampe-page-1' in placements['indexes'] else -1
    dialog = event_tools.createSubFlowEvent(flowchart, '', item_key, {}, None)
    item_get.insertInventoryEvent(flowchart, item_key, item_index, 'DampePage1', dialog)
    
    event_tools.addEntryPoint(flowchart, 'DampePage2')
    item_key = item_defs[placements['dampe-page-2']]['item-key']
    item_index = placements['indexes']['dampe-page-2'] if 'dampe-page-2' in placements['indexes'] else -1
    dialog = event_tools.createSubFlowEvent(flowchart, '', item_key, {}, None)
    item_get.insertInventoryEvent(flowchart, item_key, item_index, 'DampePage2', dialog)
    
    event_tools.addEntryPoint(flowchart, 'DampeFinal')
    item_key = item_defs[placements['dampe-final']]['item-key']
    item_index = placements['indexes']['dampe-final'] if 'dampe-final' in placements['indexes'] else -1
    dialog = event_tools.createSubFlowEvent(flowchart, '', item_key, {}, None)
    item_get.insertInventoryEvent(flowchart, item_key, item_index, 'DampeFinal', dialog)
    
    event_tools.addEntryPoint(flowchart, 'DampeHeart')
    item_key = item_defs[placements['dampe-heart-challenge']]['item-key']
    item_index = placements['indexes']['dampe-heart-challenge'] if 'dampe-heart-challenge' in placements['indexes'] else -1
    dialog = event_tools.createSubFlowEvent(flowchart, '', item_key, {}, None)
    item_get.insertInventoryEvent(flowchart, item_key, item_index, 'DampeHeart', dialog)
    
    event_tools.addEntryPoint(flowchart, 'DampeBottle')
    item_key = item_defs[placements['dampe-bottle-challenge']]['item-key']
    item_index = placements['indexes']['dampe-bottle-challenge'] if 'dampe-bottle-challenge' in placements['indexes'] else -1
    dialog = event_tools.createSubFlowEvent(flowchart, '', item_key, {}, None)
    item_get.insertInventoryEvent(flowchart, item_key, item_index, 'DampeBottle', dialog)
