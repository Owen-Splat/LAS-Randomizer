import RandomizerCore.Tools.event_tools as event_tools


class BossDropRandomizer:
    """Handles placing items when bosses are defeated"""

    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        if self.parent.thread_active: self.moldormChanges()
        if self.parent.thread_active: self.genieChanges()
        if self.parent.thread_active: self.slimeEyeChanges()
        if self.parent.thread_active: self.anglerChanges()
        if self.parent.thread_active: self.slimeEelChanges()
        if self.parent.thread_active: self.facadeChanges()
        if self.parent.thread_active: self.eagleChanges()
        if self.parent.thread_active: self.hotheadChanges()
        if self.parent.thread_active: self.lanmolaChanges()
        if self.parent.thread_active: self.armosKnightChanges()
        if self.parent.thread_active: self.masterStalfosChanges()


    def moldormChanges(self):
        '''Edits Moldorm to give the randomized item over spawning the Heart Container'''

        flow = self.parent.file_manager.readFile('DeguTail.bfevfl')
        self.parent.item_get_manager.get(flow.flowchart, 'D1-moldorm', 'Event8', 'Event45', True)

        event_tools.setEventSong(flow.flowchart, 'Event16', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event19', self.parent.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event65', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event30', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.parent.file_manager.writeFile('DeguTail.bfevfl', flow)


    def genieChanges(self):
        '''Edits Genie to give the randomized item over spawning the Heart Container'''

        flow = self.parent.file_manager.readFile('PotDemonKing.bfevfl')
        self.parent.item_get_manager.get(flow.flowchart, 'D2-genie', 'Event29', 'Event56', True)

        event_tools.setEventSong(flow.flowchart, 'Event5', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event6', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event53', self.parent.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event50', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.parent.file_manager.writeFile('PotDemonKing.bfevfl', flow)


    def slimeEyeChanges(self):
        '''Edits Slime Eye to give the randomized item over spawning the Heart Container'''

        flow = self.parent.file_manager.readFile('DeguZol.bfevfl')
        self.parent.item_get_manager.get(flow.flowchart, 'D3-slime-eye', 'Event29', 'Event43', True)

        event_tools.setEventSong(flow.flowchart, 'Event17', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event36', self.parent.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event32', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.parent.file_manager.writeFile('DeguZol.bfevfl', flow)


    def anglerChanges(self):
        '''Edits Angler Fish to give the randomized item over spawning the Heart Container'''

        flow = self.parent.file_manager.readFile('Angler.bfevfl')
        self.parent.item_get_manager.get(flow.flowchart, 'D4-angler', 'Event25', 'Event50', True)

        event_tools.setEventSong(flow.flowchart, 'Event5', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event28', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event29', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event51', self.parent.music_randomizer.songs_dict['BGM_PANEL_RESULT'])

        self.parent.file_manager.writeFile('Angler.bfevfl', flow)


    def slimeEelChanges(self):
        '''Edits Slime Eel to give the randomized item over spawning the Heart Container'''

        flow = self.parent.file_manager.readFile('Hooker.bfevfl')
        self.parent.item_get_manager.get(flow.flowchart, 'D5-slime-eel', 'Event28', 'Event13', True)

        event_tools.setEventSong(flow.flowchart, 'Event26', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event33', self.parent.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event49', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event20', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.parent.file_manager.writeFile('Hooker.bfevfl', flow)


    def facadeChanges(self):
        '''Edits Facade to give the randomized item over spawning the Heart Container'''

        flow = self.parent.file_manager.readFile('MatFace.bfevfl')
        self.parent.item_get_manager.get(flow.flowchart, 'D6-facade', 'Event8', 'Event35', True)

        event_tools.setEventSong(flow.flowchart, 'Event22', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event29', self.parent.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event78', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event19', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.parent.file_manager.writeFile('MatFace.bfevfl', flow)


    def eagleChanges(self):
        '''Edits Evil Eagle to give the randomized item over spawning the Heart Container'''

        flow = self.parent.file_manager.readFile('Albatoss.bfevfl')
        self.parent.item_get_manager.get(flow.flowchart, 'D7-eagle', 'Event40', 'Event51', True)

        event_tools.setEventSong(flow.flowchart, 'Event15', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_LV7_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event20', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event66', self.parent.music_randomizer.songs_dict['BGM_PANEL_RESULT'])

        self.parent.file_manager.writeFile('Albatoss.bfevfl', flow)


    def hotheadChanges(self):
        '''Edits HotHead to give the randomized item over spawning the Heart Container'''

        flow = self.parent.file_manager.readFile('DeguFlame.bfevfl')
        self.parent.item_get_manager.get(flow.flowchart, 'D8-hothead', 'Event13', 'Event15', True)

        event_tools.setEventSong(flow.flowchart, 'Event28', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event40', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event63', self.parent.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event17', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event70', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.parent.file_manager.writeFile('DeguFlame.bfevfl', flow)


    def lanmolaChanges(self):
        '''Edits Lanmola to give the randomized item over dropping the Angler Key'''

        flow = self.parent.file_manager.readFile('Lanmola.bfevfl')
        self.parent.item_get_manager.get(flow.flowchart, 'lanmola', 'Event34', 'Event9', True)

        event_tools.setEventSong(flow.flowchart, 'Event2', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event18', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event22', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])

        self.parent.file_manager.writeFile('Lanmola.bfevfl', flow)


    def armosKnightChanges(self):
        '''Edits Armos Knight to open the doors before giving the randomized item'''

        flow = self.parent.file_manager.readFile('DeguArmos.bfevfl')
        event_tools.removeEventAfter(flow.flowchart, 'Event2')
        event_tools.insertEventAfter(flow.flowchart, 'Event2', 'Event8')
        self.parent.item_get_manager.get(flow.flowchart, 'armos-knight', 'Event47', None, True)

        event_tools.setEventSong(flow.flowchart, 'Event4', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event23', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])

        self.parent.file_manager.writeFile('DeguArmos.bfevfl', flow)


    def masterStalfosChanges(self):
        '''Edits Master Stalfos to give the randomized item over dropping the Hookshot'''

        flow = self.parent.file_manager.readFile('MasterStalfon.bfevfl')
        self.parent.item_get_manager.get(flow.flowchart, 'D5-master-stalfos', 'Event37', 'Event194', True)

        event_tools.setEventSong(flow.flowchart, 'Event0', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event1', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event3', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event132', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event157', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event2', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event4', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event10', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event23', self.parent.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])

        self.parent.file_manager.writeFile('MasterStalfon.bfevfl', flow)
