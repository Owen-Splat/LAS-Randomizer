from Randomizers import data
import Tools.oead_tools as oead_tools
import oead



def makeDatasheetChanges(sheet, placements):
    """Iterates through all the values in the ItemDrop datasheet and makes changes"""
    
    for i in range(len(sheet['values'])):

        # sheet['values'][i]['condition'] = ''
        # if sheet['values'][i]['mKey'] == 'Bomb' and placements['settings']['shuffle-bombs']:
        #     sheet['values'][i]['condition'] = data.BOMBS_FOUND_FLAG
        
        if sheet['values'][i]['mKey'] == 'HeartContainer0':
            first_heart_index = i
        
        if sheet['values'][i]['mKey'] == 'AnglerKey':
            sheet['values'][i]['mLotTable'][0]['mType'] = ''
        if sheet['values'][i]['mKey'] == 'FaceKey':
            sheet['values'][i]['mLotTable'][0]['mType'] = ''
        if sheet['values'][i]['mKey'] == 'HookShot':
            sheet['values'][i]['mLotTable'][0]['mType'] = ''
        
        if sheet['values'][i]['mKey'] == 'Bomb':
            if placements['settings']['reduce-farming']:
                sheet['values'][i]['mLotTable'][0]['mCookie'] = 3
            if placements['settings']['shuffle-bombs']:
                sheet['values'][i]['mLotTable'][0]['mCookie'] = 0
        
        if sheet['values'][i]['mKey'] == 'Arrow' and placements['settings']['reduce-farming']:
            sheet['values'][i]['mLotTable'][0]['mCookie'] = 3
        if sheet['values'][i]['mKey'] == 'MagicPowder' and placements['settings']['reduce-farming']:
            sheet['values'][i]['mLotTable'][0]['mCookie'] = 3
        if sheet['values'][i]['mKey'] == 'Grass' and placements['settings']['reduce-farming']:
            sheet['values'][i]['mLotTable'][1]['mWeight'] = 18
            sheet['values'][i]['mLotTable'][2]['mWeight'] = 3
            sheet['values'][i]['mLotTable'][3]['mWeight'] = 71

    for i in range(8):
        sheet['values'][first_heart_index+i]['mLotTable'][0]['mType'] = ''



# def createDatasheetConditions(sheet):
#     # {name: gettingFlag, type_name: GlobalFlags, type: 4, flags: 9, fields: null}
#     sheet['root_fields'].append(oead_tools.createField(
#     name='mCondition',
#     type_name='Conditions',
#     type=oead.gsheet.Field.Type.String,
#     flags=oead.gsheet.Field.Flag.IsNullable,
#     offset=28
# ))
