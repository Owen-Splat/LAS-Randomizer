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

        # if start with compass & map setting is enabled, adding them into the starting item setting
        to_check = []
        if self.shuffler.settings["Dungeon Maps"] == "Start With":
            to_check.append("map")
        if self.shuffler.settings["Compasses"] == "Start With":
            to_check.append("compass")
        if self.shuffler.settings["Stone Beaks"] == "Start With":
            to_check.append("stone-beak")
        if self.shuffler.settings["Small Keys"] == "Start With":
            to_check.append("key")
        if self.shuffler.settings["Nightmare Keys"] == "Start With":
            to_check.append("nightmare-key")
        if len(to_check) > 0:
            start_dungeon_items = [s for s in self.shuffler.item_defs if s.startswith(tuple(to_check))]
            start_dungeon_items_with_count = [s for s in start_dungeon_items for _ in range(self.shuffler.item_defs[s]['quantity'])]
            for e, item in enumerate(start_dungeon_items_with_count):
                self.shuffler.logic_defs[f'starting-dungeon-item-{e + 1}'] = {  # add a location for each starting item
                    'type': 'item',
                    'subtype': 'npc',
                    'content': item,
                    'region': 'mabe',
                    'spoiler-region': 'mabe-village'
                }
                self.shuffler.vanilla_locations.add(f'starting-dungeon-item-{e + 1}')
                self.shuffler.item_defs['rupee-50']['quantity'] += 1  # since we add a location for each item, add a 50 rupee in the pool for each

        # add the starting instruments to the list of starting items since we are done with them
        self.shuffler.settings["Starting Gear"].extend(start_instruments)

        # do the same for the remaining starting items
        for e, item in enumerate(self.shuffler.settings["Starting Gear"]):
            self.shuffler.logic_defs[f'starting-item-{e+1}'] = { # add a location for each starting item
                'type': 'item',
                'subtype': 'npc',
                'content': item,
                'region': 'mabe',
                'spoiler-region': 'mabe-village'
            }
            self.shuffler.vanilla_locations.add(f'starting-item-{e+1}')
            self.shuffler.item_defs['rupee-50']['quantity'] += 1 # since we add a location for each item, add a 50 rupee in the pool for each
