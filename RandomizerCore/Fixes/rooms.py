from RandomizerCore.Tools.leb import Room


class RoomFixes:
    """Fix some LEB files in ways that are always done, regardless of item placements"""

    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        self.makeGeneralRoomChanges()
        self.fixRapidsRespawn()
        self.fixWaterLoadingZones()
        if self.parent.settings["Open Mabe"]:
            self.openMabe()
        if self.parent.settings["Randomize Enemies"]:
            self.openArmosStairs()


    def makeGeneralRoomChanges(self):
        ### Mad Batters: Give the batters a 3rd parameter for the event entry point to run
        # A: Bay
        if self.parent.thread_active:
            room_data = self.parent.file_manager.readFile('MadBattersWell01_01A.leb')
            room_data.actors[2].parameters[2] = b'BatterA'
            self.parent.file_manager.writeFile('MadBattersWell01_01A.leb', room_data)

        # B: Woods
        if self.parent.thread_active:
            room_data = self.parent.file_manager.readFile('MadBattersWell02_01A.leb')
            room_data.actors[6].parameters[2] = b'BatterB'
            self.parent.file_manager.writeFile('MadBattersWell02_01A.leb', room_data)

        # C: Mountain
        if self.parent.thread_active:
            room_data = self.parent.file_manager.readFile('MadBattersWell03_01A.leb')
            room_data.actors[0].parameters[2] = b'BatterC'
            self.parent.file_manager.writeFile('MadBattersWell03_01A.leb', room_data)

        ### Lanmola Cave: Remove the AnglerKey actor
        if self.parent.thread_active:
            room_data = self.parent.file_manager.readFile('LanmolaCave_02A.leb')
            room_data.actors.pop(5)
            self.parent.file_manager.writeFile('LanmolaCave_02A.leb', room_data)

        ### Classic D2: Turn the rock in front of Dungeon 2 into a swamp flower
        if self.parent.settings["Classic D2"] and self.parent.thread_active:
            room_data = self.parent.file_manager.readFile('Field_03E.leb')
            room_data.actors[12].type = 0x0E
            self.parent.file_manager.writeFile('Field_03E.leb', room_data)

        ### Remove the BoyA and BoyB cutscene after getting the FullMoonCello
        if self.parent.thread_active:
            room_data = self.parent.file_manager.readFile('Field_12A.leb')

            # remove link between boy[1] and AreaEventBox[8]
            room_data.actors[1].relationships.x -= 1
            room_data.actors[1].relationships.section_1.pop(0)
            room_data.actors[8].relationships.y -=1
            room_data.actors[8].relationships.section_3.pop(0)

            self.parent.file_manager.writeFile('Field_12A.leb', room_data)

        ### Make Honeycomb show new graphics in tree, a different NPC key is used for when the player obtains the item
        if self.parent.thread_active:
            room_data = self.parent.file_manager.readFile('Field_09H.leb')

            item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel('tarin-ukuku', self.parent.trap_models)
            room_data.actors[0].parameters[0] = bytes(model_path, 'utf-8')
            room_data.actors[0].parameters[1] = bytes(model_name, 'utf-8')

            self.parent.file_manager.writeFile('Field_09H.leb', room_data)


    def openMabe(self):
        """Removes grass / monsters / rocks that block access to go outside of Mabe village"""

        rooms_to_fix = {
            'Field_10A': [0x624A97005CD29205],
            'Field_10E': [0x62000A005D15AC9E, 0x620015005D15AC9E],
            'Field_15B': [0x7200BB005CFF3740, 0x7200B9005CFF3740],
            'Field_15C': [0x7200DC005CFF3741, 0x7200D6005CFF3741],
        }

        for room, elements_to_remove in rooms_to_fix.items():
            if not self.parent.thread_active:
                break

            room_data = self.parent.file_manager.readFile(f'{room}.leb')

            for element_key in elements_to_remove:
                for index, actor in enumerate(room_data.actors):
                    if actor.key == element_key:
                        room_data.actors.pop(index)
                        break

            self.parent.file_manager.writeFile(f'{room}.leb', room_data)


    def fixWaterLoadingZones(self):
        """Changes each water loading zone to be deactivated until the player has flippers

        This is to prevent the player from potentially softlocking by entering them with the rooster"""

        for room in WATER_LOADING_ZONES:
            if not self.parent.thread_active:
                break

            room_data = self.parent.file_manager.readFile(f'{room}.leb')

            for actor in WATER_LOADING_ZONES[room]:
                room_data.actors[actor].switches[0] = (1, self.parent.flag_manager.flags['FlippersFound'])

            self.parent.file_manager.writeFile(f'{room}.leb', room_data)


    def fixRapidsRespawn(self):
        """If the player reloads an autosave after completing the Rapids Race without flippers,
        they will drown and then be sent to 0,0,0 in an endless falling loop

        This is fixed by iterating over every touching water tile, and prevent reloading on them"""

        rooms_to_fix = (
            'Field_09N',
            'Field_09O',
            'Field_09P',
            'Field_10P',
        )

        for room in rooms_to_fix:
            if not self.parent.thread_active:
                break

            # we want to edit the grid info, which is skipped over by default since we mostly leave it untouched
            # so we have readFile() early return the path, and read the Room data here with edit_grid=True
            room_path = self.parent.file_manager.readFile(f'{room}.leb', return_path=True)
            with open(room_path, 'rb') as f:
                room_data = Room(f.read(), edit_grid=True)

            for tile in room_data.grid.tilesdata:
                if tile.flags3['iswaterlava']:
                    tile.flags3['respawnload'] = 0

            self.parent.file_manager.writeFile(f'{room}.leb', room_data)


    def openArmosStairs(self) -> None:
        """Although we already set the global flags for the 2 stairs under armos,
        I still had a sword stalfos need to be killed before the stairs appeared

        Instead of figuring out every outlier, it is easier to just delete the enemy actors"""

        room_data: Room = self.parent.file_manager.readFile("Field_10N.leb")
        del room_data.actors[0]
        self.parent.file_manager.writeFile("Field_10N.leb", room_data)

        room_data: Room = self.parent.file_manager.readFile("Field_11O.leb")
        del room_data.actors[2]
        self.parent.file_manager.writeFile("Field_11O.leb", room_data)


WATER_LOADING_ZONES = {
    'Field_02O': [10],
    'Field_03K': [3],
    'Field_03O': [1],
    'Field_14J': [5, 6],
    'Field_15K': [1]
}
