from RandomizerCore.Tools.lvb import Level


class LevelFixes:
    """Makes necessary changes to lvb files depending on settings"""

    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        if self.parent.settings["Bad Pets"] and self.parent.thread_active:
            self.allowCompanionsInDungeons()


    def allowCompanionsInDungeons(self):
        """Edits the config of the lvb files for dungeons to allow companions"""

        levels_path = self.parent.rom_path / "region_common" / "level"

        # allow companions inside every dungeon
        # exception being the Egg since companions can collide with Nightmare and cause a softlock
        folders = [f.name for f in levels_path.iterdir() if f.name.startswith("Lv") and not f.name.startswith("Lv09")]

        for folder in folders:
            if not self.parent.thread_active:
                break

            level = self.parent.file_manager.readFile(f'{folder}.lvb')
            level.config.allow_companions = True
            self.parent.file_manager.writeFile(f'{folder}.lvb', level)

# Music edits are also done though lvb files but we are keeping it in the MusicRandomizer class
