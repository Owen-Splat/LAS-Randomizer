from RandomizerCore.Tools.lvb import Level
from pathlib import Path


# Music edits are also done though lvb files but we are keeping it in the MusicRandomizer class
class LevelFixes:
    """Makes necessary changes to lvb files depending on settings"""

    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator

        if self.parent.settings["Bad Pets"] and self.parent.thread_active:
            self.allowCompanionsInDungeons()

        if self.parent.settings["Randomize Environments"] and self.parent.thread_active:
            self.randomizeEnvironments()


    def allowCompanionsInDungeons(self) -> None:
        """Edits the config of the lvb files for dungeons to allow companions"""

        levels_path: Path = self.parent.rom_path / "region_common" / "level"

        # allow companions inside every dungeon
        # exception being the Egg since companions can collide with Nightmare and cause a softlock
        folders = [f.name for f in levels_path.iterdir() if f.name.startswith("Lv") and not f.name.startswith("Lv09")]

        for folder in folders:
            if not self.parent.thread_active:
                break

            level: Level = self.parent.file_manager.readFile(f"{folder}.lvb")
            level.config.allow_companions = True
            self.parent.file_manager.writeFile(f"{folder}.lvb", level)


    def randomizeEnvironments(self) -> None:
        levels_path: Path = self.parent.rom_path / "region_common" / "level"

        folders = [f.name for f in levels_path.iterdir() if f.is_dir()]

        for folder in folders:
            if not self.parent.thread_active:
                break

            level: Level = self.parent.file_manager.readFile(f"{folder}.lvb")
            zones_edited: bool = False

            for zone in level.zones:
                if zone.environment in TOPDOWN_ENVIRONMENTS:
                    zone.environment = self.parent.cosmetic_rng.choice(TOPDOWN_ENVIRONMENTS)
                    zones_edited = True
                elif zone.environment in SIDESCROLLER_ENVIRONMENTS:
                    zone.environment = self.parent.cosmetic_rng.choice(SIDESCROLLER_ENVIRONMENTS)
                    zones_edited = True

            if zones_edited:
                self.parent.file_manager.writeFile(f"{folder}.lvb", level)


TOPDOWN_ENVIRONMENTS = (
    "AncientRuins",
    "AncientRuins2",
    "AncientRuinsDark",
    "Banana",
    "Bear",
    "BedRoom",
    "Cemetery",
    "Christine",
    "Crane",
    "Cucco",
    "Default",
    "Desert",
    "Dog",
    "DreamShrine",
    "DrWright",
    "DungeonSmall",
    "DungeonSmallTalTal",
    "DungeonSmallUnderground",
    "DungeonSmallWater",
    "DungeonSmallWaterDark",
    "Event1",
    "Event2",
    "EventEnding",
    "EventStairs",
    "Fairy",
    "Field",
    "FieldAncientRuins",
    "FieldBowWow",
    "FieldKanalet",
    "FishingBoat",
    "FishingPond",
    "Ghost",
    "Goponga",
    "GreatFairy",
    "HolyEgg",
    "ItemGet",
    "KanaletCastle",
    "Library",
    "Lv01Altar",
    "Lv01Base",
    "Lv02Altar",
    "Lv02Base",
    "Lv02Dark",
    "Lv02DoorOpen",
    "Lv02Teresa",
    "Lv03Altar",
    "Lv03Base",
    "Lv04Altar",
    "Lv04Base",
    "Lv05Altar",
    "Lv05Base",
    "Lv06Altar",
    "Lv06Base",
    "Lv06Dark",
    "Lv07Altar",
    "Lv07Base",
    "Lv08Altar",
    "Lv08Base",
    "Lv08Base2",
    "Lv08Dark",
    "Lv08Treasurebox",
    "Lv09Base",
    "Lv09Base2",
    "Lv09Base3",
    "Lv09BaseDark",
    "Lv10Base",
    "Lv11Base",
    "Madam",
    "MadBattersWell",
    "Magic",
    "MagicDark",
    "MagicField",
    # "MagicPowderHouse", # crashes if the env name is different, would need to edit the actual environment data
    "MamuCave",
    "MamuCaveDark",
    "MarinTarin",
    "MoriblinCave",
    "MysteriousForest",
    "Photo",
    "Quaduplet",
    "Rabbit",
    "RapidFlow",
    "RapidsRide",
    "Richard",
    "Schule",
    "Seashell",
    "Shop",
    "TalTalMountain",
    "TelBox",
    "ToronboShores",
    "Tracy",
    "Ulrira",
    "Underwater",
    "Zora"
)

SIDESCROLLER_ENVIRONMENTS = (
    "Angler",
    "KanaletCastleEnter",
    "Lv01Side",
    "Lv02Side",
    "Lv02Side2",
    "Lv03Side",
    "Lv04Side",
    "Lv04Side2",
    "Lv04Side3",
    "Lv05Side",
    "Lv05Side2",
    "Lv06Side",
    "Lv07Side",
    "Lv08Side",
    "Lv08Side2",
    "Lv08Side3",
    "MamboCave",

)