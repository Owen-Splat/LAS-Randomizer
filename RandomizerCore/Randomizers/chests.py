from RandomizerCore.Paths.randomizer_paths import RESOURCE_PATH
import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Tools.bntx_tools import createChestBfresWithCustomTexturesIfMissing
from pathlib import Path
import shutil, copy

# TODO: CREATE CUSTOM TEXTURE BFRES FILES IN A SEPARATE THREAD

class ChestRandomizer:
    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        self.makeChestContentFixes()
        self.writeChestEvent()


    def makeChestContentFixes(self):
        """Patch LEB files of rooms with chests to update their contents"""

        chest_rooms = {}
        chest_rooms.update(CHEST_ROOMS)

        # CAMC Pre-Checks
        if self.parent.settings["Chest Types"] == "Texture + Size":
            chest_rooms.update(PANEL_CHEST_ROOMS)

            # Creating custom textures bfres files from the original one in the RomFS
            bfresOutputFolder = RESOURCE_PATH / "textures" / "chest" / "bfres"

            createChestBfresWithCustomTexturesIfMissing(
                str(self.parent.rom_path / "region_common" / "actor" / "ObjTreasureBox.bfres"),
                str(bfresOutputFolder),
                CHEST_TEXTURES
            )

            # Copying files to the custom RomFS
            actorOutputFolder: Path = self.parent.romfs_dir / "region_common" / "actor"
            if not actorOutputFolder.exists():
                actorOutputFolder.mkdir(parents=True)

            for file in bfresOutputFolder.iterdir():
                source = str(bfresOutputFolder / file.name)
                destination = str(actorOutputFolder / file.name)
                shutil.copy(source, destination)

        # CSMC Management (Chest size)
        chest_sizes = copy.deepcopy(CHEST_SIZES)

        if self.parent.settings["Chest Types"] != "Default":
            # if all seashell and trade gift locations are set to junk, set chests that contain them to be small
            if not self.parent.settings["Seashells Important"]:
                chest_sizes['seashell'] = 0.8
            if not self.parent.settings["Trade Important"]:
                chest_sizes['trade'] = 0.8
        else:
            for k in chest_sizes:
                chest_sizes[k] = 1.0  # if scaled chest sizes is off, set every value to normal size

        for room in chest_rooms:
            if not self.parent.thread_active:
                break

            room_data = self.parent.file_manager.readFile(f'{chest_rooms[room]}.leb')

            # Managing panels to set default chest texture for now as I cannot detect chest content (only $PANEL)
            if room.startswith('panel-'):
                for actor in room_data.actors:
                    if actor.name.startswith(b'ObjTreasureBox'):
                        room_data.setChestContent(
                            actor.parameters[1].decode("utf-8"), actor.parameters[2],
                            chest_size=1.0, chest_model=CHEST_TEXTURES['default'])
                self.parent.file_manager.writeFile(f'{PANEL_CHEST_ROOMS[room]}.leb', room_data)
                continue

            item_key, item_index = self.parent.item_info_manager.getItemInfo(room)
            item_type = self.parent.item_defs[self.parent.placements[room]]['type']

            # Managing CSMC on the fly. TODO Make this cleaner. This should not be there.
            if self.parent.settings["Chest Types"] == "Size":
                if item_key in ('HeartContainer', 'ClothesRed', 'ClothesBlue'):
                    size = chest_sizes['junk']
                elif item_key in ('SmallKey', 'Bomb_MaxUp', 'Arrow_MaxUp', 'MagicPowder_MaxUp'):
                    size = chest_sizes['important']
                else:
                    size = chest_sizes[item_type]
            else:
                size = chest_sizes[item_type]

            try:
                item_chest_type = self.parent.item_defs[self.parent.placements[room]]['chest-type']
            except KeyError:
                item_chest_type = None

            # Changing the texture and size of Stone Beaks if dungeon Owl rewards are enabled
            if item_key == "StoneBeak" and self.parent.settings["Owl Gifts"] in ("Dungeons", "All"):
                item_chest_type = 'default'
                size = chest_sizes['important']

            # TODO Manage PanelDungeonPiece thanks to Dampe settings (need to check how it works)

            # CAMC Management (Chest aspect - Texture management)
            model = CHEST_TEXTURES['default'] if self.parent.settings["Chest Types"] == "Texture + Size" else None
            if self.parent.settings["Chest Types"] == "Texture + Size" and item_chest_type is not None:
                model = CHEST_TEXTURES[item_chest_type]

            if room == 'taltal-5-chest-puzzle':
                for i in range(5):
                    room_data.setChestContent(item_key, item_index, i, size, model)
            else:
                room_data.setChestContent(item_key, item_index, chest_size=size, chest_model=model)

            self.parent.file_manager.writeFile(f'{CHEST_ROOMS[room]}.leb', room_data)

            # Two special cases in D7 have duplicate rooms, once for pre-collapse and once for post-collapse
            # We need to make sure we write the same data to both rooms
            if room == 'D7-grim-creeper':
                room_data = self.parent.file_manager.readFile('Lv07EagleTower_06H.leb')
                room_data.setChestContent(item_key, item_index, chest_size=size, chest_model=model)
                self.parent.file_manager.writeFile('Lv07EagleTower_06H.leb', room_data)

            if room == 'D7-3f-horseheads':
                room_data = self.parent.file_manager.readFile('Lv07EagleTower_05G.leb')
                room_data.setChestContent(item_key, item_index, chest_size=size, chest_model=model)
                self.parent.file_manager.writeFile('Lv07EagleTower_05G.leb', room_data)


    def writeChestEvent(self):
        """Writes an itemKey comparision and itemGet chain and connects it to the chest open events"""

        # ### TreasureBox event: Adds in events to make certain items be progressive as well as custom events for other items.
        if not self.parent.thread_active:
            return

        flow = self.parent.file_manager.readFile('TreasureBox.bfevfl')

        auto_save = event_tools.createActionEvent(flow.flowchart, 'GameControl', 'RequestAutoSave', {}, None)

        sword_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'SwordLv1', -1 , None, auto_save)
        sword_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'SwordLv1'},
            {0: sword_get, 1: 'Event33'})

        shield_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'Shield', -1, None, auto_save)
        shield_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'Shield'},
            {0: shield_get, 1: sword_check})

        bracelet_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'PowerBraceletLv1', -1, None, auto_save)
        bracelet_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'PowerBraceletLv1'},
            {0: bracelet_get, 1: shield_check})

        red_tunic_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'ClothesRed', -1, None, auto_save)
        red_tunic_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'ClothesRed'},
            {0: red_tunic_get, 1: bracelet_check})

        blue_tunic_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'ClothesBlue', -1, None, auto_save)
        blue_tunic_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'ClothesBlue'},
            {0: blue_tunic_get, 1: red_tunic_check})

        zap_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'ZapTrap', -1, None, auto_save)
        zap_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'ZapTrap'},
            {0: zap_get, 1: blue_tunic_check})

        drown_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'DrownTrap', -1, None, auto_save)
        drown_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'DrownTrap'},
            {0: drown_get, 1: zap_check})

        squish_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'SquishTrap', -1, None, auto_save)
        squish_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'SquishTrap'},
            {0: squish_get, 1: drown_check})

        deathball_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'DeathballTrap', -1, None, auto_save)
        deathball_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'DeathballTrap'},
            {0: deathball_get, 1: squish_check})

        quake_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'QuakeTrap', -1, None, auto_save)
        last_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'QuakeTrap'},
            {0: quake_get, 1: deathball_check})

        if self.parent.settings["Dungeon Maps"] in ("Any Dungeon", "Anywhere"):
            last_check = self.parent.item_get_manager.getKeysanityItem(flow.flowchart, "DungeonMap", last_check, auto_save)
        if self.parent.settings["Compasses"] in ("Any Dungeon", "Anywhere"):
            last_check = self.parent.item_get_manager.getKeysanityItem(flow.flowchart, "Compass", last_check, auto_save)
        if self.parent.settings["Stone Beaks"] in ("Any Dungeon", "Anywhere"):
            last_check = self.parent.item_get_manager.getKeysanityItem(flow.flowchart, "StoneBeak", last_check, auto_save)
        if self.parent.settings["Small Keys"] in ("Any Dungeon", "Anywhere"):
            last_check = self.parent.item_get_manager.getKeysanityItem(flow.flowchart, "SmallKey", last_check, auto_save)
        if self.parent.settings["Nightmare Keys"] in ("Any Dungeon", "Anywhere"):
            last_check = self.parent.item_get_manager.getKeysanityItem(flow.flowchart, "NightmareKey", last_check, auto_save)

        # add this chain to TreasureBox_Open and TreasureBox_ShockOpen
        event_tools.insertEventAfter(flow.flowchart, 'Event32', last_check)
        event_tools.insertEventAfter(flow.flowchart, 'Event28', last_check)

        # now make the rest of the items also request an autosave
        event_tools.insertEventAfter(flow.flowchart, 'Event40', auto_save)
        event_tools.insertEventAfter(flow.flowchart, 'Event5', auto_save)

        # make the D6 pot chest check if it contains an enemy
        event_tools.insertEventAfter(flow.flowchart, 'TreasureBox_ShockOpen', 'Event27')
        event_tools.insertEventAfter(flow.flowchart, 'Event15', 'Event28')
        check_enemy = event_tools.createSwitchEvent(flow.flowchart, 'TreasureBox', 'ContainsEnemy',
            {}, {0: 'Event15', 1: 'Event42'})
        event_tools.insertEventAfter(flow.flowchart, 'Event27', check_enemy)

        if self.parent.settings["Chest Animations"]:
            # remove the cameraLookAt event and the secret unlocked music
            del event_tools.findEvent(flow.flowchart, 'Event44').data.forks[0]
            event_tools.insertEventAfter(flow.flowchart, 'Event52', None)

        self.parent.file_manager.writeFile('TreasureBox.bfevfl', flow)


CHEST_ROOMS = {
 'beach-chest': 'Field_15F',
 'taltal-entrance-chest': 'Tamaranch04_02D',
 'taltal-east-left-chest': 'Field_02I',
 'dream-shrine-right': 'DreamShrine_01B',
 'armos-cave': 'ArmosShrineCave_01A',
 'goponga-cave-left': 'GopongaCave_01A',
 'goponga-cave-right': 'GopongaCave_01B',
 'ukuku-cave-west-chest': 'UkukuCave01_01A',
 'ukuku-cave-east-chest': 'UkukuCave02_02A',
 'kanalet-south-cave': 'KanaletCastleSouthCave_01A',
 'rapids-middle-island': 'Field_06N',
 'rapids-south-island': 'Field_07M',
 'swamp-chest': 'Field_04E',
 'taltal-left-ascent-cave': 'Tamaranch02_01B',
 'taltal-ledge-chest': 'Field_02N',
 'taltal-5-chest-puzzle': 'Tamaranch05_04A',
 'taltal-west-chest': 'Field_02E',
 'villa-cave': 'RichardCave_01A',
 'woods-crossing-cave-chest': 'MysteriousWoodsCave01_02B',
 'woods-north-cave-chest': 'MysteriousWoodsCave02_01A',
 'woods-south-chest': 'Field_08B',
 'woods-north-chest': 'Field_05B',
 'D1-west-hallway': 'Lv01TailCave_05A',
 'D1-middle-ledge': 'Lv01TailCave_05D',
 'D1-3-of-a-kind': 'Lv01TailCave_05F',
 'D1-bomb-room': 'Lv01TailCave_06B',
 'D1-middle-kill-chest': 'Lv01TailCave_06C',
 'D1-spark-chest': 'Lv01TailCave_06D',
 'D1-button-chest': 'Lv01TailCave_07D',
 'D1-stalfos-chest': 'Lv01TailCave_07E',
 'D1-4-zols-chest': 'Lv01TailCave_08B',
 'D2-boos': 'Lv02BottleGrotto_02B',
 'D2-long-room-west': 'Lv02BottleGrotto_02C',
 'D2-long-room-east': 'Lv02BottleGrotto_02D',
 'D2-vacuum-mouth-room': 'Lv02BottleGrotto_03C',
 'D2-kill-puzzle': 'Lv02BottleGrotto_03F',
 'D2-west-chest': 'Lv02BottleGrotto_06B',
 'D2-entrance-chest': 'Lv02BottleGrotto_08C',
 'D2-single-shy-guy': 'Lv02BottleGrotto_08D',
 'D2-peg-circle': 'Lv02BottleGrotto_08E',
 'D2-button-chest': 'Lv02BottleGrotto_08F',
 'D3-north-chest': 'Lv03KeyCavern_01C',
 'D3-central-ledge': 'Lv03KeyCavern_02A',
 'D3-central-chest': 'Lv03KeyCavern_02C',
 'D3-east-ledge': 'Lv03KeyCavern_02D',
 'D3-hallway-4': 'Lv03KeyCavern_04B',
 'D3-hallway-3': 'Lv03KeyCavern_05B',
 'D3-hallway-2': 'Lv03KeyCavern_06B',
 'D3-hallway-side-room': 'Lv03KeyCavern_06C',
 'D3-hallway-1': 'Lv03KeyCavern_07B',
 'D3-vacuum-mouth': 'Lv03KeyCavern_08C',
 'D4-north-chest': 'Lv04AnglersTunnel_02D',
 'D4-east-side-north': 'Lv04AnglersTunnel_03G',
 'D4-east-side-south': 'Lv04AnglersTunnel_05G',
 'D4-west-ledge': 'Lv04AnglersTunnel_07C',
 'D4-east-of-puzzle': 'Lv04AnglersTunnel_04D',
 'D4-south-of-puzzle': 'Lv04AnglersTunnel_05C',
 'D4-central-room': 'Lv04AnglersTunnel_05D',
 'D4-small-island': 'Lv04AnglersTunnel_06F',
 'D4-ledge-north': 'Lv04AnglersTunnel_04F',
 'D4-statues-chest': 'Lv04AnglersTunnel_07F',
 'D4-lobby': 'Lv04AnglersTunnel_07E',
 'D4-crystals': 'Lv04AnglersTunnel_08E',
 'D5-past-master-stalfos-3': 'Lv05CatfishsMaw_01E',
 'D5-water-tunnel': 'Lv05CatfishsMaw_02E',
 'D5-right-side-north': 'Lv05CatfishsMaw_02G',
 'D5-right-side-middle': 'Lv05CatfishsMaw_03G',
 'D5-right-side-east': 'Lv05CatfishsMaw_03H',
 'D5-past-master-stalfos-1': 'Lv05CatfishsMaw_05G',
 'D5-west-chest': 'Lv05CatfishsMaw_06C',
 'D5-helmasaurs': 'Lv05CatfishsMaw_07D',
 'D5-west-stairs-chest': 'Lv05CatfishsMaw_08E',
 'D5-near-entrance': 'Lv05CatfishsMaw_08G',
 'D6-far-northwest': 'Lv06FaceShrine_02A',
 'D6-far-northeast': 'Lv06FaceShrine_02H',
 'D6-statue-line-north': 'Lv06FaceShrine_03B',
 'D6-statue-line-south': 'Lv06FaceShrine_04B',
 'D6-pot-chest': 'Lv06FaceShrine_03G',
 'D6-canal': 'Lv06FaceShrine_04G',
 'D6-3-wizzrobes': 'Lv06FaceShrine_05A',
 'D6-gated-hallway-north': 'Lv06FaceShrine_06C',
 'D6-gated-hallway-south': 'Lv06FaceShrine_07C',
 'D6-southwest-chest': 'Lv06FaceShrine_07B',
 'D6-wizzrobes-ledge': 'Lv06FaceShrine_07G',
 'D7-1f-west': 'Lv07EagleTower_07A',
 'D7-west-ledge': 'Lv07EagleTower_05A',
 'D7-east-ledge': 'Lv07EagleTower_05D',
 'D7-3ofakind-north': 'Lv07EagleTower_01B',
 'D7-2f-horseheads': 'Lv07EagleTower_01C',
 'D7-3ofakind-south': 'Lv07EagleTower_04B',
 'D7-blue-pegs-chest': 'Lv07EagleTower_03D',
 'D7-3f-horseheads': 'Lv07EagleTower_01G',
 'D7-grim-creeper': 'Lv07EagleTower_02H',
 'D8-far-northwest': 'Lv08TurtleRock_02A',
 'D8-far-northeast': 'Lv08TurtleRock_02H',
 'D8-left-exit-chest': 'Lv08TurtleRock_03C',
 'D8-dodongos': 'Lv08TurtleRock_03F',
 'D8-northern-ledge': 'Lv08TurtleRock_02E',
 'D8-beamos-chest': 'Lv08TurtleRock_04B',
 'D8-torches': 'Lv08TurtleRock_05B',
 'D8-west-roomba': 'Lv08TurtleRock_06B',
 'D8-surrounded-by-blocks': 'Lv08TurtleRock_06D',
 'D8-sparks-chest': 'Lv08TurtleRock_07B',
 'D8-east-of-pots': 'Lv08TurtleRock_07F',
 'D8-far-southwest': 'Lv08TurtleRock_08A',
 'D8-far-southeast': 'Lv08TurtleRock_08H',
 'D0-northern-chest': 'Lv10ClothesDungeon_04F',
 'D0-zol-pots': 'Lv10ClothesDungeon_05D',
 'D0-south-orbs': 'Lv10ClothesDungeon_07F',
 'D0-west-color-puzzle': 'Lv10ClothesDungeon_07D',
 'D0-putters': 'Lv10ClothesDungeon_08E'
}

PANEL_CHEST_ROOMS = {
 'panel-D1-west-hallway': 'PanelLv01TailCave_05A',
 'panel-D1-3-of-a-kind': 'PanelLv01TailCave_05F',
 'panel-D1-bomb-room': 'PanelLv01TailCave_06B',
 'panel-D1-button-chest': 'PanelLv01TailCave_07D',
 'panel-D1-stalfos-chest': 'PanelLv01TailCave_07E',
 'panel-D1-4-zols-chest': 'PanelLv01TailCave_08B',
 'panel-D1-beetles': 'PanelLv01TailCave_08C',
 'panel-D2-boos': 'PanelLv02BottleGrotto_02B',
 'panel-D2-vacuum-mouth-room': 'PanelLv02BottleGrotto_03C',
 'panel-D2-kill-puzzle': 'PanelLv02BottleGrotto_03F',
 'panel-D2-west-chest': 'PanelLv02BottleGrotto_06B',
 'panel-D2-double-stalfos': 'PanelLv02BottleGrotto_07D',
 'panel-D2-single-shy-guy': 'PanelLv02BottleGrotto_08D',
 'panel-D2-button-chest': 'PanelLv02BottleGrotto_08F',
 'panel-D3-basement-north': 'PanelLv03KeyCavern_03G',
 'panel-D3-five-zols': 'PanelLv03KeyCavern_04C',
 'panel-D3-extra-1': 'PanelLv03KeyCavern_04D',
 'panel-D3-basement-west': 'PanelLv03KeyCavern_04F',
 'panel-D3-extra-2': 'PanelLv03KeyCavern_04H',
 'panel-D3-basement-south': 'PanelLv03KeyCavern_05G',
 'panel-D3-hallway-side-room': 'PanelLv03KeyCavern_06C',
 'panel-D3-vacuum-mouth': 'PanelLv03KeyCavern_08C',
 'panel-D3-pre-boss': 'PanelLv03KeyCavern_08G',
 'panel-D4-crystals': 'PanelLv04AnglersTunnel_08E',
 'panel-D4-north-chest': 'PanelLv04AnglersTunnel_02D',
 'panel-D4-east-side-north': 'PanelLv04AnglersTunnel_03G',
 'panel-D5-crystal-blocks': 'PanelLv05CatfishsMaw_01C',
 'panel-D5-past-master-stalfos-3': 'PanelLv05CatfishsMaw_01E',
 'panel-D5-past-master-stalfos-1': 'PanelLv05CatfishsMaw_05G',
 'panel-D5-helmasaurs': 'PanelLv05CatfishsMaw_07D',
 'panel-D5-west-stairs-chest': 'PanelLv05CatfishsMaw_08E',
 'panel-D6-far-northwest': 'PanelLv06FaceShrine_02A',
 'panel-D6-extra-1': 'PanelLv06FaceShrine_02D',
 'panel-D6-far-northeast': 'PanelLv06FaceShrine_02H',
 'panel-D6-3-wizzrobes': 'PanelLv06FaceShrine_05A',
 'panel-D6-extra-2': 'PanelLv06FaceShrine_05H',
 'panel-D6-southwest-chest': 'PanelLv06FaceShrine_07B',
 'panel-D7-3ofakind-north': 'PanelLv07EagleTower_01B',
 'panel-D7-2f-horseheads': 'PanelLv07EagleTower_01C',
 'panel-D7-extra-1': 'PanelLv07EagleTower_02D',
 'panel-D7-hinox': 'PanelLv07EagleTower_04A',
 'panel-D7-3f-horseheads': 'PanelLv07EagleTower_05G',
 'panel-D7-grim-creeper': 'PanelLv07EagleTower_06H',
 'panel-D8-far-northwest': 'PanelLv08TurtleRock_02A',
 'panel-D8-dodongos': 'PanelLv08TurtleRock_03F',
 'panel-D8-gibdos': 'PanelLv08TurtleRock_03G',
 'panel-D8-extra-1': 'PanelLv08TurtleRock_03H',
 'panel-D8-extra-2': 'PanelLv08TurtleRock_04A',
 'panel-D8-statue': 'PanelLv08TurtleRock_04C',
 'panel-D8-extra-3': 'PanelLv08TurtleRock_04H',
 'panel-D8-extra-4': 'PanelLv08TurtleRock_05H',
 'panel-D8-west-vire': 'PanelLv08TurtleRock_06A',
 'panel-D8-west-roomba': 'PanelLv08TurtleRock_06B',
 'panel-D8-sparks-chest': 'PanelLv08TurtleRock_07B',
 'panel-D8-east-of-pots': 'PanelLv08TurtleRock_07F',
 'panel-D8-east-roomba': 'PanelLv08TurtleRock_07G',
 'panel-D8-far-southwest': 'PanelLv08TurtleRock_08A',
 'panel-D8-far-southeast': 'PanelLv08TurtleRock_08H',
 'panel-D0-northern-chest': 'PanelLv10ClothesDungeon_04F',
 'panel-D0-zol-pots': 'PanelLv10ClothesDungeon_05D',
 'panel-D0-north-orbs': 'PanelLv10ClothesDungeon_05E',
 'panel-D0-east-color-puzzle': 'PanelLv10ClothesDungeon_05F',
 'panel-D0-west-color-puzzle': 'PanelLv10ClothesDungeon_07D',
 'panel-D0-south-orbs': 'PanelLv10ClothesDungeon_07F',
 'panel-D0-putters': 'PanelLv10ClothesDungeon_08E'
}

CHEST_SIZES = {
    'important': 1.2,
    'important-health': 1.2,
    'trade': 1.2,
    'seashell': 1.2,
    'good': 0.8,
    'junk': 0.8,
    # 'D1': 1.0,
    # 'D2': 1.0,
    # 'D3': 1.0,
    # 'D4': 1.0,
    # 'D5': 1.0,
    # 'D6': 1.0,
    # 'D7': 1.0,
    # 'D8': 1.0,
    # 'D0': 1.0
}

CHEST_TEXTURES = {
    'default': 'ObjTreasureBox.bfres',
    'junk': "ObjTreasureBoxJunk.bfres",
    'life-upgrade': "ObjTreasureBoxLifeUpgrade.bfres",
    'key': "ObjTreasureBoxKey.bfres"
}
