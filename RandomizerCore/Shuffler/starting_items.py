class ShufflerStartingItems:
    """Edits the logic and item pool to support the starting items"""

    def __init__(self, shuffler) -> None:
        self.shuffler = shuffler
        self.addStartingItems()


    def addStartingItems(self) -> None:
        instruments = [
            'full-moon-cello',
            'conch-horn',
            'sea-lilys-bell',
            'surf-harp',
            'wind-marimba',
            'coral-triangle',
            'evening-calm-organ',
            'thunder-drum'
        ]

        start_instruments = []
        for i in [x for x in self.shuffler.settings["Starting Gear"] if x in instruments]:
            self.shuffler.settings["Starting Gear"].remove(i)
            start_instruments.append(i)
            instruments.remove(i)

        instrument_locations = [k for k,v in self.shuffler.logic_defs.items()
            if v['type'] == 'item'
            and v['subtype'] == 'standing'
            and v['content'] in instruments
        ]

        # shuffle the instrument placements, and for each starting instrument, remove one and store the content
        self.shuffler.rng.shuffle(instrument_locations)
        num = self.shuffler.settings["Starting Instruments"]
        num = num - len(start_instruments)
        if num <= 0:
            num = 0
        for i in range(num):
            inst = instrument_locations.pop(0)
            start_instruments.append(self.shuffler.logic_defs[inst]['content'])

        # if randomized instruments is off, make sure the remaining instruments are in their vanilla locations
        if self.shuffler.settings["Shuffle Instruments"] == "Vanilla":
            for inst in instrument_locations:
                self.shuffler.vanilla_locations.add(inst)

        # add the starting instruments to the list of starting items since we are done with them
        self.shuffler.settings["Starting Gear"].extend(start_instruments)

        # if start with compass & map setting is enabled, adding them into the starting item setting
        for i in range(9):
            if self.shuffler.settings["Dungeon Maps"] == "Start With":
                self.shuffler.settings["Starting Gear"].append(f"map-D{i}")
            if self.shuffler.settings["Compasses"] == "Start With":
                self.shuffler.settings["Starting Gear"].append(f"compass-D{i}")
            if self.shuffler.settings["Stone Beaks"] == "Start With":
                self.shuffler.settings["Starting Gear"].append(f"stone-beak-D{i}")
            if self.shuffler.settings["Small Keys"] == "Start With":
                self.shuffler.settings["Starting Gear"].append(f"key-D{i}")
            if self.shuffler.settings["Nightmare Keys"] == "Start With":
                self.shuffler.settings["Starting Gear"].append(f"nightmare-key-D{i}")

        # heart pieces and containers
        for i in range(self.shuffler.settings["Pieces"]):
            self.shuffler.settings["Starting Gear"].append("heart-piece")
        for i in range(self.shuffler.settings["Containers"]):
            self.shuffler.settings["Starting Gear"].append("heart-container")

        # for all the starting items, we must now add a new location with the item as a vanilla location
        # then replace the item slot with a purple rupee for each
        hp_index = 0
        hc_index = 0
        for e, item in enumerate(self.shuffler.settings["Starting Gear"]):
            self.shuffler.logic_defs[f'starting-item-{e+1}'] = { # add a location for each starting item
                'type': 'item',
                'subtype': 'npc',
                'content': item,
                'region': 'mabe',
                'spoiler-region': 'mabe-village'
            }
            if item == "heart-piece":
                self.shuffler.logic_defs[f'starting-item-{e+1}']["index"] = hp_index
                hp_index += 1
                if hp_index == 25: # 2 heart pieces in trendy are still vanilla
                    hp_index = 27
            elif item == "heart-container":
                self.shuffler.logic_defs[f'starting-item-{e+1}']["index"] = hc_index
                hc_index += 1
            self.shuffler.vanilla_locations.add(f'starting-item-{e+1}')
            self.shuffler.item_defs['rupee-50']['quantity'] += 1 # since we add a location for each item, add a 50 rupee in the pool for each
