import Tools.event_tools as event_tools
import Tools.oead_tools as oead_tools
from Randomizers import item_get, data



def makeDatasheetChanges(sheet, placements, item_defs):
    """Edit the ShopItem datasheet to for the new items. Incomplete, was only testing"""

    for slot in sheet['values']:
        if slot['mIndex'] == 2: # shovel/bow/arrows
            item = placements['shop-slot3-1st'] # shovel
            itemIndex = placements['indexes']['shop-slot3-1st'] if 'shop-slot3-1st' in placements['indexes'] else -1
            slot['mGoods'][0]['mItem'] = item_defs[item]['item-key']
            slot['mGoods'][0]['mModelPath'] = f"actor/{item_defs[item]['model-path']}"
            slot['mGoods'][0]['mModelName'] = item_defs[item]['model-name']
            slot['mGoods'][0]['mIndex'] = itemIndex

            item = placements['shop-slot3-2nd'] # bow
            itemIndex = placements['indexes']['shop-slot3-2nd'] if 'shop-slot3-2nd' in placements['indexes'] else -1
            slot['mGoods'][1]['mItem'] = item_defs[item]['item-key']
            slot['mGoods'][1]['mModelPath'] = f"actor/{item_defs[item]['model-path']}"
            slot['mGoods'][1]['mModelName'] = item_defs[item]['model-name']
            slot['mGoods'][1]['mIndex'] = itemIndex


def makeEventChanges(flowchart, placements, item_defs):
    """edit the ToolShopKeeper event flow for the new items. Incomplete, was only testing"""

    # shovel
    item = placements['shop-slot3-1st']
    itemKey = item_defs[item]['item-key']
    itemIndex = placements['indexes']['shop-slot3-1st'] if 'shop-slot3-1st' in placements['indexes'] else -1

    event_tools.setSwitchEventCase(flowchart, 'Event50', 1, 'Event52')
    event_tools.insertEventAfter(flowchart, 'Event52', 'Event61')
    item_get.insertItemGetAnimation(flowchart, itemKey, itemIndex, 'Event53', 'Event43')
