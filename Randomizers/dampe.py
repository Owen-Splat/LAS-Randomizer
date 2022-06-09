def make_datasheet_changes(sheet, rewardNum, itemKey, itemIndex):
    sheet['values'][rewardNum]['mRewardItem'] = itemKey
    sheet['values'][rewardNum]['mRewardItemEventEntry'] = itemKey
    sheet['values'][rewardNum]['mRewardItemIndex'] = itemIndex