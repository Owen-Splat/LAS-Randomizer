from RandomizerCore.Tools.bntx_tools import createRandomizerTitleScreenArchive


class TitleScreenFixes:
    """Replaces the Title Screen logo with the Randomizer logo"""

    def __init__(self, mod_generator) -> None:
        try:
            # Read the BNTX file from the sarc file and edit the title screen logo to include the randomizer logo
            archive = mod_generator.file_manager.readFile('StartUp.arc')
            bntx_data = archive.getFileData("timg/__Combined.bntx")
            edited_bntx = createRandomizerTitleScreenArchive(bntx_data)
            archive.replaceFile("timg/__Combined.bntx", edited_bntx)
            mod_generator.file_manager.writeFile('StartUp.arc', archive.data)
        except:
            # regardless of any errors, just consider this task done, the logo is not needed to play
            mod_generator.progress_value += 1
            mod_generator.progress_update.emit(mod_generator.progress_value)
