def makeDatasheetChanges(sheet, reward_num, item_key, item_index):
    """Edits the Dampe rewards datasheets to be new items. Progressive items and any items that set flags will not work however"""
    
    sheet['values'][reward_num]['mRewardItem'] = item_key
    sheet['values'][reward_num]['mRewardItemEventEntry'] = item_key
    sheet['values'][reward_num]['mRewardItemIndex'] = item_index