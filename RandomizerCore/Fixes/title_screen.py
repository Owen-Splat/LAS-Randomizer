from RandomizerCore.Tools.bntx_tools import createRandomizerTitleScreenArchive


class TitleScreenFixes:
    """Replaces the Title Screen logo with the Randomizer logo"""

    def __init__(self, mod_generator) -> None:
        try:
            # Read the BNTX file from the sarc file and edit the title screen logo to include the randomizer logo
            sarc_data = mod_generator.file_manager.readFile('StartUp.arc')
            createRandomizerTitleScreenArchive(sarc_data)
            mod_generator.file_manager.writeFile('StartUp.arc', sarc_data)
        except:
            # regardless of any errors, just consider this task done, the logo is not needed to play
            mod_generator.progress_value += 1
            mod_generator.progress_update.emit(mod_generator.progress_value)
