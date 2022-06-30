import Tools.event_tools as event_tools
import Tools.oead_tools as oead_tools
from Randomizers import item_get, data



def makeDatasheetChanges(sheet, placements, item_defs):
    for slot in sheet['values']:
        if slot['mIndex'] == 2: # shovel/bow/arrows
            item = placements['shop-slot3-1st']
            itemIndex = placements['indexes']['shop-slot3-1st'] if 'shop-slot3-1st' in placements['indexes'] else -1
            slot['mGoods'][0]['mItem'] = item_defs[item]['item-key']
            slot['mGoods'][0]['mModelPath'] = f"actor/{item_defs[item]['model-path']}"
            slot['mGoods'][0]['mModelName'] = item_defs[item]['model-name']
            slot['mGoods'][0]['mIndex'] = itemIndex

            slot['mGoods'][1]['mCondition'] = 'ShopShovelGet'

            slot['mGoods'][2]['mCondition'] = 'ShopBowGet'



def makeEventChanges(flowchart, placements, item_defs):
    
    # shovel
    item = placements['shop-slot3-1st']
    itemKey = item_defs[item]['item-key']
    itemIndex = placements['indexes']['shop-slot3-1st'] if 'shop-slot3-1st' in placements['indexes'] else -1

    event_tools.setSwitchEventCase(flowchart, 'Event50', 1, 'Event52')
    event_tools.insertEventAfter(flowchart, 'Event52', 'Event61')
    item_get.insertItemGetAnimation(flowchart, itemKey, itemIndex, 'Event53', 'Event43')
    gotFlag = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag', {'symbol': 'ShopShovelGet', 'value': True})
    event_tools.insertEventAfter(flowchart, 'Event43', gotFlag)
