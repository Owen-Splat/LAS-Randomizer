

class FishingDatasheetFixes:
    def __init__(self, mod_generator) -> None:
        if mod_generator.settings["Fast Fishing"] and mod_generator.thread_active:
            sheet = mod_generator.file_manager.readFile('FishingFish.gsheet')

            for fish in sheet['values']:
                if not mod_generator.thread_active:
                    break

                if len(fish['mOpenItem']) > 0:
                    fish['mOpenItem'] = 'ClothesGreen'

            mod_generator.file_manager.writeFile('FishingFish.gsheet', sheet)
