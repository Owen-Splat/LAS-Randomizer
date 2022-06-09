def make_datasheet_changes(sheet, placements):
    for i in range(len(sheet['values'])):
        if sheet['values'][i]['mKey'] == 'HeartContainer0':
            firstHeartIndex = i
        if sheet['values'][i]['mKey'] == 'AnglerKey':
            sheet['values'][i]['mLotTable'][0]['mType'] = ''
        if sheet['values'][i]['mKey'] == 'FaceKey':
            sheet['values'][i]['mLotTable'][0]['mType'] = ''
        if sheet['values'][i]['mKey'] == 'HookShot':
            sheet['values'][i]['mLotTable'][0]['mType'] = ''
        if sheet['values'][i]['mKey'] == 'Bomb' and placements['settings']['reduce-farming']:
            sheet['values'][i]['mLotTable'][0]['mCookie'] = 3
        if sheet['values'][i]['mKey'] == 'Arrow' and placements['settings']['reduce-farming']:
            sheet['values'][i]['mLotTable'][0]['mCookie'] = 3
        if sheet['values'][i]['mKey'] == 'MagicPowder' and placements['settings']['reduce-farming']:
            sheet['values'][i]['mLotTable'][0]['mCookie'] = 3
        if sheet['values'][i]['mKey'] == 'Grass' and placements['settings']['reduce-farming']:
            sheet['values'][i]['mLotTable'][1]['mWeight'] = 18
            sheet['values'][i]['mLotTable'][2]['mWeight'] = 3
            sheet['values'][i]['mLotTable'][3]['mWeight'] = 71

    for i in range(8):
        sheet['values'][firstHeartIndex+i]['mLotTable'][0]['mType'] = ''
