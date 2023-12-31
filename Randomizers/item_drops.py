from Randomizers import data
import Tools.oead_tools as oead_tools
import oead



def makeDatasheetChanges(sheet, settings):
    """Iterates through all the values in the ItemDrop datasheet and makes changes"""

    for i in range(len(sheet['values'])):
        
        if sheet['values'][i]['mKey'] == 'HeartContainer0':
            first_heart_index = i
        
        if sheet['values'][i]['mKey'] == 'AnglerKey':
            sheet['values'][i]['mLotTable'][0]['mType'] = ''
        if sheet['values'][i]['mKey'] == 'FaceKey':
            sheet['values'][i]['mLotTable'][0]['mType'] = ''
        if sheet['values'][i]['mKey'] == 'HookShot':
            sheet['values'][i]['mLotTable'][0]['mType'] = ''
        
        if sheet['values'][i]['mKey'] == 'Bomb':
            if settings['reduce-farming']:
                sheet['values'][i]['mLotTable'][0]['mCookie'] = 3
        
        if sheet['values'][i]['mKey'] == 'MagicPowder':
            if settings['reduce-farming']:
                sheet['values'][i]['mLotTable'][0]['mCookie'] = 3
        
        if sheet['values'][i]['mKey'] == 'Arrow' and settings['reduce-farming']:
            sheet['values'][i]['mLotTable'][0]['mCookie'] = 3

        # Values will be different depending on extended consumable drop and reduce farming settings
        if sheet['values'][i]['mKey'] == 'Grass':
            heartWeight = sheet['values'][i]['mLotTable'][0]['mWeight']
            rupee1Weight = sheet['values'][i]['mLotTable'][1]['mWeight']
            rupee5Weight = sheet['values'][i]['mLotTable'][2]['mWeight']
            nothingWeight = sheet['values'][i]['mLotTable'][3]['mWeight']

            # Managing existing entries
            if settings['reduce-farming']:
                rupee1Weight = 18
                rupee5Weight = 3
                nothingWeight = 71

            if settings['reduce-farming'] and settings['extended-consumable-drop']:
                rupee1Weight = 18
                rupee5Weight = 3
                nothingWeight = 56
            elif settings['extended-consumable-drop']:
                nothingWeight = 70

            sheet['values'][i]['mLotTable'][0]['mWeight'] = heartWeight
            sheet['values'][i]['mLotTable'][1]['mWeight'] = rupee1Weight
            sheet['values'][i]['mLotTable'][2]['mWeight'] = rupee5Weight
            sheet['values'][i]['mLotTable'][3]['mWeight'] = nothingWeight

            # Adding new entries if extended consumable drop setting is enabled
            # Reduce farming won't impact bombs arrow and powder for now. Will depend on the feedbacks
            if settings['extended-consumable-drop']:
                # Using a copy of an existing entry to use as a skeleton for our new data
                bombEntry = oead_tools.parseStruct(sheet['values'][i]['mLotTable'][0])
                bombEntry['mType'] = 'Bomb'
                bombEntry['mCookie'] = 3
                bombEntry['mWeight'] = 5
                sheet['values'][i]['mLotTable'].append(oead_tools.dictToStruct(bombEntry))

                # Using a copy of an existing entry to use as a skeleton for our new data
                arrowEntry = oead_tools.parseStruct(sheet['values'][i]['mLotTable'][0])
                arrowEntry['mType'] = 'Arrow'
                arrowEntry['mCookie'] = 3
                arrowEntry['mWeight'] = 5
                sheet['values'][i]['mLotTable'].append(oead_tools.dictToStruct(arrowEntry))

                # Using a copy of an existing entry to use as a skeleton for our new data
                magicPowderEntry = oead_tools.parseStruct(sheet['values'][i]['mLotTable'][0])
                magicPowderEntry['mType'] = 'MagicPowder'
                magicPowderEntry['mCookie'] = 3
                magicPowderEntry['mWeight'] = 5
                sheet['values'][i]['mLotTable'].append(oead_tools.dictToStruct(magicPowderEntry))


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
