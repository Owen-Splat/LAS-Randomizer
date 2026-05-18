from RandomizerCore.Tools.event_tools import setEventSong
import copy

class MusicRandomizer:
    def __init__(self, mod_generator):
        self.parent = mod_generator
        self.setting = self.parent.settings["Music"]
        self.createSongMap()
        if self.setting != "Vanilla":
            self.editMusic()


    def createSongMap(self) -> None:
        """Maps out what each song should change to

        No change if vanilla, different song if shuffled, empty string if removed"""

        self.songs_dict = {}
        bgms = list(copy.deepcopy(BGM_TRACKS))

        for t in BGM_TRACKS:
            if not self.parent.thread_active:
                break

            if self.setting == "Vanilla":
                self.songs_dict[t] = t
            elif self.setting == "Shuffled":
                ind = bgms.index(self.parent.cosmetic_rng.choice(bgms))
                self.songs_dict[t] = bgms.pop(ind)
            else:
                self.songs_dict[t] = ""


    def editMusic(self):
        """Replaces the BGM info in the lvb files with the shuffled songs"""

        levels_path = self.parent.rom_path / "region_common" / "level"
        folders = [f.name for f in levels_path.iterdir() if f.is_dir()]

        for folder in folders:
            if not self.parent.thread_active:
                break

            level = self.parent.file_manager.readFile(f'{folder}.lvb')
            for zone in level.zones:
                if zone.bgm in self.songs_dict:
                    zone.bgm = self.songs_dict[zone.bgm]

            self.parent.file_manager.writeFile(f'{folder}.lvb', level)

        # edit music that is played through events
        if self.parent.thread_active:
            self.editEventMusic()


    def editEventMusic(self):
        '''Goes through and randomizes the music controlled by events

        Also skips over some music that either would overlap or cut out otherwise

        Some will be handled when editing items. This focuses on the rest'''

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('Bossblin.bfevfl')
            setEventSong(flow.flowchart, 'Event64', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            setEventSong(flow.flowchart, 'Event68', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.parent.file_manager.writeFile('Bossblin.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('BossBlob.bfevfl')
            setEventSong(flow.flowchart, 'Event6', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            setEventSong(flow.flowchart, 'Event19', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            setEventSong(flow.flowchart, 'Event12', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.parent.file_manager.writeFile('BossBlob.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('Dodongo.bfevfl')
            setEventSong(flow.flowchart, 'Event5', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            setEventSong(flow.flowchart, 'Event43', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            setEventSong(flow.flowchart, 'Event3', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.parent.file_manager.writeFile('Dodongo.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('DonPawn.bfevfl')
            setEventSong(flow.flowchart, 'Event21', self.songs_dict['BGM_DUNGEON_BOSS'])
            setEventSong(flow.flowchart, 'Event30', self.songs_dict['BGM_PANEL_RESULT'])
            setEventSong(flow.flowchart, 'Event38', self.songs_dict['BGM_DUNGEON_BOSS'])
            setEventSong(flow.flowchart, 'Event6', self.songs_dict['BGM_DUNGEON_BOSS'])
            self.parent.file_manager.writeFile('DonPawn.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('Gohma.bfevfl')
            setEventSong(flow.flowchart, 'Event0', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            setEventSong(flow.flowchart, 'Event1', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.parent.file_manager.writeFile('Gohma.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('Hinox.bfevfl')
            setEventSong(flow.flowchart, 'Event37', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            setEventSong(flow.flowchart, 'Event55', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            setEventSong(flow.flowchart, 'Event1', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.parent.file_manager.writeFile('Hinox.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('HiploopHover.bfevfl')
            setEventSong(flow.flowchart, 'Event38', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            setEventSong(flow.flowchart, 'Event7', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.parent.file_manager.writeFile('HiploopHover.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('Jacky.bfevfl')
            setEventSong(flow.flowchart, 'Event37', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            setEventSong(flow.flowchart, 'Event6', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.parent.file_manager.writeFile('Jacky.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('MightPunch.bfevfl')
            setEventSong(flow.flowchart, 'Event56', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            setEventSong(flow.flowchart, 'Event6', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.parent.file_manager.writeFile('MightPunch.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('PiccoloMaster.bfevfl')
            setEventSong(flow.flowchart, 'Event48', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            setEventSong(flow.flowchart, 'Event53', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            setEventSong(flow.flowchart, 'Event3', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.parent.file_manager.writeFile('PiccoloMaster.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('Rola.bfevfl')
            setEventSong(flow.flowchart, 'Event20', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            setEventSong(flow.flowchart, 'Event1', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.parent.file_manager.writeFile('Rola.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('Shadow.bfevfl')
            # setEventSong(flow.flowchart, 'Event6', self.songs_dict['BGM_LASTBOSS_DEMO_TEXT'])
            setEventSong(flow.flowchart, 'Event37', self.songs_dict['BGM_LASTBOSS_WIN'])
            setEventSong(flow.flowchart, 'Event60', self.songs_dict['BGM_LASTBOSS_BATTLE'])
            setEventSong(flow.flowchart, 'Event71', self.songs_dict['BGM_LASTBOSS_BATTLE'])
            # setEventSong(flow.flowchart, 'Event44', self.songs_dict['BGM_LASTBOSS_DEMO_TEXT'])
            self.parent.file_manager.writeFile('Shadow.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('StoneHinox.bfevfl')
            setEventSong(flow.flowchart, 'Event4', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            setEventSong(flow.flowchart, 'Event35', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            setEventSong(flow.flowchart, 'Event29', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.parent.file_manager.writeFile('StoneHinox.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('ToolShopkeeper.bfevfl')
            setEventSong(flow.flowchart, 'Event87', self.songs_dict['BGM_DUNGEON_BOSS'])
            self.parent.file_manager.writeFile('ToolShopkeeper.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('TurtleRock.bfevfl')
            setEventSong(flow.flowchart, 'Event1', self.songs_dict['BGM_DUNGEON_LV8_ENT_BATTLE'])
            setEventSong(flow.flowchart, 'Event26', self.songs_dict['BGM_DUNGEON_LV8_ENT_BATTLE'])
            setEventSong(flow.flowchart, 'Event11', self.songs_dict['BGM_DUNGEON_LV8_ENT_BATTLE'])
            self.parent.file_manager.writeFile('TurtleRock.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('WindFish.bfevfl')
            setEventSong(flow.flowchart, 'Event73', self.songs_dict['BGM_DEMO_AFTER_LASTBOSS'])
            # setEventSong(flow.flowchart, 'Event101', self.songs_dict['BGM_DEMO_AFTER_LASTBOSS_WIND_FISH'])
            setEventSong(flow.flowchart, 'Event74', self.songs_dict['BGM_DEMO_AFTER_LASTBOSS'])
            setEventSong(flow.flowchart, 'Event93', self.songs_dict['BGM_LASTBOSS_WIN'])
            # setEventSong(flow.flowchart, 'Event118', self.songs_dict['BGM_DEMO_AFTER_LASTBOSS_WIND_FISH'])
            self.parent.file_manager.writeFile('WindFish.bfevfl', flow)


BGM_TRACKS = (
    'BGM_DUNGEON_LV6_FACE',
    'BGM_DUNGEON_LV4_ANGLER',
    'BGM_CHICKEN_HURT',
    'BGM_GHOST_HOUSE',
    'BGM_ANIMAL_VILLAGE',
    'BGM_DUNGEON_LV1_TAIL',
    'BGM_DUNGEON_2D_SIDEVIEW',
    'BGM_DUGEON_CASTLE',
    'BGM_DUNGEON_LV3_KEY',
    'BGM_CAVE',
    'BGM_TARUTARU',
    'BGM_HOUSE',
    'BGM_MEVE',
    'BGM_FISHINGMAN',
    'BGM_DUNGEON_LV2_POT',
    'BGM_STRANGE_FOREST',
    'BGM_DUNGEON_HOLY_EGG',
    'BGM_SEASHELL_HOUSE',
    'BGM_TELEPHONE',
    'BGM_DANPEI',
    'BGM_SHOP',
    # 'BGM_SHOP_FAST',
    'BGM_GAME_SHOP',
    'BGM_GOAT_HOUSE',
    'BGM_DREAMSHRINE',
    'BGM_WRIGHT',
    'BGM_GAME_SHOP_FOR_POND',
    'BGM_RICHARD',
    'BGM_EVENT_RESCUE_BOWBOW',
    'BGM_DUNGEON_LV10_CLOTH',
    # 'BGM_DREAMSHRINE_ENT',
    'BGM_PLACE_OF_FACE_KEY',
    'BGM_DUNGEON_LV5_CATFISH',
    'BGM_FAIRY',
    'BGM_DUNGEON_LV7_TOWER',
    'BGM_DUNGEON_LV8_TURTLE',
    'BGM_FIELD_NORMAL',
    'BGM_FIELD_MARINE_NORMAL',
    'BGM_LASTBOSS_APPEAR',
    'BGM_LASTBOSS_BATTLE',
    'BGM_MARINE_NAME',
    # 'BGM_MARINE_SING',
    'BGM_MINIGAME_FISHING',
    'BGM_PANEL_DUNG_BEGINNER',
    'BGM_PANEL_DUNG_DIFFICULT',
    'BGM_PANEL_DUNG_MEDIUM',
    'BGM_PANEL_EDIT_MODE',
    'BGM_NAME_INPUT',
    'BGM_DUNGEON_BOSS',
    'BGM_DUNGEON_BOSS_MIDDLE',
    'BGM_DUNGEON_LV8_ENT_BATTLE',
    'BGM_EVENT_MARINE_IN_BEACH',
    'BGM_EVENT_RESCUE_BOWBOW_INTRO',
    'BGM_FIELD_FIRST',
    'BGM_FIELD_NORMAL_INTRO',
    'BGM_GAME_OF_RAFT',
    # 'BGM_NAZOTOKI_SEIKAI',
    'BGM_PANEL_SHADOW_LINK',
    'BGM_RAFTING_TIMEATTACK',
    'BGM_RICHARD_230',
    'BGM_STRANGE_FOREST_MARINE',
    'BGM_TARUTARU2_AFTER_THE_RESCUE',
    'BGM_TARUTARU_MARINE',
    'BGM_TOTAKEKE_SONG',
    'BGM_ZELDA_NAME',
    # 'BGM_DEFEAT_LOOP',
    # 'BGM_FANFARE_BOSS_HEART_GET',
    'BGM_PANEL_RESULT',
    'BGM_DUNGEON_LV7_BOSS',
    'BGM_HOUSE_FIRST',
    # 'BGM_EVENT_BASIN_ANGLER_OPEN',
    # 'BGM_EVENT_MONKEY',
    'BGM_MADBATTER',
    'BGM_EVENT_DATE',
    # 'BGM_RESUSCITATION_OF_CHICKEN',
    # 'BGM_LASTBOSS_DEMO_TEXT',
    'BGM_LASTBOSS_WIN',
    'BGM_OWL',
    'BGM_OWL_LAST',
    # 'BGM_EVENT_BEE',
    # 'BGM_MARINE_SING_WALRUS',
    'BGM_DEMO_AFTER_LASTBOSS',
    # 'BGM_DEMO_AFTER_LASTBOSS_WIND_FISH'
)
