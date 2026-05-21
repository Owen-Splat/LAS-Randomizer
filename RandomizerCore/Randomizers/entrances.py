from RandomizerCore.Randomizers.data import DUNGEON_ENTRANCES, DUNGEON_MAP_ICONS


class EntranceRandomizer:
    """Handles randomizing entrances. Currently just dungeon front entrances"""

    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        if self.parent.settings["Shuffled Dungeons"] and self.parent.thread_active:
            self.shuffleDungeons()
            self.shuffleDungeonIcons()


    def shuffleDungeons(self):
        """Shuffles the entrances of each dungeon"""

        ent_keys = list(self.parent.placements['dungeon-entrances'].keys())
        ent_values = list(self.parent.placements['dungeon-entrances'].values())

        for k,v in DUNGEON_ENTRANCES.items():

            ######################################################################## - dungeon in
            if not self.parent.thread_active:
                break

            room_data = self.parent.file_manager.readFile(f'{v[2]}.leb')

            d = DUNGEON_ENTRANCES[self.parent.placements['dungeon-entrances'][k]]
            destin = d[0] + d[1]
            room_data.setLoadingZoneTarget(destin, v[4])

            self.parent.file_manager.writeFile(f'{v[2]}.leb', room_data)

            ######################################################################## - dungeon out
            if not self.parent.thread_active:
                break

            room_data = self.parent.file_manager.readFile(f'{v[0]}.leb')

            d = DUNGEON_ENTRANCES[ent_keys[ent_values.index(k)]]
            destin = d[2] + d[3]
            room_data.setLoadingZoneTarget(destin, 0)

            self.parent.file_manager.writeFile(f'{v[0]}.leb', room_data)


    def shuffleDungeonIcons(self):
        """Shuffle the dungeon icons so that players can use the in-game map to track dungeon entrances"""

        icon_keys = list(DUNGEON_MAP_ICONS.keys())
        icon_values = list(DUNGEON_MAP_ICONS.values())
        maps = [i[0] for i in icon_values]
        sheet = self.parent.file_manager.readFile('UiFieldMapIcons.gsheet')
        for icon in sheet['values']:
            if not self.parent.thread_active:
                break

            if icon['mNameLabel'] in maps:
                k = icon_keys[maps.index(icon['mNameLabel'])]
                new_k = self.parent.placements['dungeon-entrances'][k]
                icon['mNameLabel'] = DUNGEON_MAP_ICONS[new_k][0]
                icon['mFirstShowFlagName'] = DUNGEON_MAP_ICONS[new_k][1]

        self.parent.file_manager.writeFile('UiFieldMapIcons.gsheet', sheet)
