from Randomizers import data
import Tools.oead_tools as oead_tools
import oead



def makeDatasheetChanges(sheet, placements):
    for i in range(len(sheet['values'])):

        # sheet['values'][i]['conditions'] = oead.gsheet.StructArray()

        # if sheet['values'][i]['mKey'] == 'Bomb' and placements['settings']['shuffle-bombs']:
        #     sheet['values'][i]['conditions'].append({'category': 1, 'parameter': data.BOMBS_FOUND_FLAG})
        # elif sheet['values'][i]['mKey'] == 'None':
        #     sheet['values'][i]['conditions'].append({'category': 9, 'parameter': 'false'})
        # else:
        #     sheet['values'][i]['conditions'].append({'category': 9, 'parameter': 'true'})
        
        if sheet['values'][i]['mKey'] == 'HeartContainer0':
            firstHeartIndex = i
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
        sheet['values'][firstHeartIndex+i]['mLotTable'][0]['mType'] = ''



def createDatasheetConditions(sheet):
    sheet['root_fields'].append(oead_tools.createField(
    name='conditions',
    type_name='__inline_struct_ItemDrop_conditions',
    type=oead.gsheet.Field.Type.Struct,
    flags=oead.gsheet.Field.Flag.IsArray,
    offset=28
))
