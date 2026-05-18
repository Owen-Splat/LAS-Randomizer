import RandomizerCore.Tools.oead_tools as oead_tools


class ItemDropDatasheetFixes:
    def __init__(self, mod_generator) -> None:
        sheet = mod_generator.file_manager.readFile('ItemDrop.gsheet')
        self.makeDatasheetChanges(sheet, mod_generator.settings)
        mod_generator.file_manager.writeFile('ItemDrop.gsheet', sheet)


    def makeDatasheetChanges(self, sheet, settings):
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
            
            # Values will be different depending on extended consumable drop and reduce farming settings
            if sheet['values'][i]['mKey'] == 'Grass':
                heartWeight = sheet['values'][i]['mLotTable'][0]['mWeight']
                rupee1Weight = sheet['values'][i]['mLotTable'][1]['mWeight']
                rupee5Weight = sheet['values'][i]['mLotTable'][2]['mWeight']
                nothingWeight = sheet['values'][i]['mLotTable'][3]['mWeight']

                # Managing existing entries
                rupee1Weight = 18
                rupee5Weight = 3

                if settings["Consumable Drops"]:
                    nothingWeight = 56
                else:
                    nothingWeight = 71

                sheet['values'][i]['mLotTable'][0]['mWeight'] = heartWeight
                sheet['values'][i]['mLotTable'][1]['mWeight'] = rupee1Weight
                sheet['values'][i]['mLotTable'][2]['mWeight'] = rupee5Weight
                sheet['values'][i]['mLotTable'][3]['mWeight'] = nothingWeight

                # Adding new entries if extended consumable drop setting is enabled
                if settings["Consumable Drops"]:
                    # Using a copy of an existing entry to use as a skeleton for our new data
                    dummyEntry = oead_tools.parseStruct(sheet['values'][i]['mLotTable'][0])

                    dummyEntry['mType'] = 'Bomb'
                    dummyEntry['mWeight'] = 5
                    sheet['values'][i]['mLotTable'].append(oead_tools.dictToStruct(dummyEntry))

                    dummyEntry['mType'] = 'Arrow'
                    dummyEntry['mWeight'] = 5
                    sheet['values'][i]['mLotTable'].append(oead_tools.dictToStruct(dummyEntry))

                    dummyEntry['mType'] = 'MagicPowder'
                    dummyEntry['mWeight'] = 5
                    sheet['values'][i]['mLotTable'].append(oead_tools.dictToStruct(dummyEntry))

        for i in range(8):
            sheet['values'][first_heart_index+i]['mLotTable'][0]['mType'] = ''
