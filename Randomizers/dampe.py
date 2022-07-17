def makeDatasheetChanges(sheet, rewardNum, itemKey, itemIndex):
    """Edits the Dampe rewards datasheets to be new items. Progressive items and any items that set flags will not work however"""
    
    sheet['values'][rewardNum]['mRewardItem'] = itemKey
    sheet['values'][rewardNum]['mRewardItemEventEntry'] = itemKey
    sheet['values'][rewardNum]['mRewardItemIndex'] = itemIndex