class ShufflerInstruments:
    """Assigns the placement of instruments based on user settings"""

    def __init__(self, shuffler, access) -> None:
        self.shuffler = shuffler
        self.assignItems(access)


    def assignItems(self, access) -> None:
        setting = self.shuffler.settings["Shuffle Instruments"]
        if setting in ("Vanilla", "Anywhere"):
            return

        item_pool = [i for i in self.shuffler.items if i in INSTRUMENTS]
        for item in item_pool:
            if setting == "Dungeon Rewards":
                location_pool = [l for l in self.shuffler.locations if l in DUNGEON_REWARD_LOCATIONS]
            elif setting == "Own Dungeon":
                dungeon_index = INSTRUMENTS.index(item) + 1
                location_pool = [l for l in self.shuffler.locations if l[:2] == f"D{dungeon_index}"]
            elif setting == "Any Dungeon":
                location_pool = [l for l in self.shuffler.locations if l[0] == 'D' and l[2] == '-']
            else:
                raise ValueError("Invalid instrument shuffle setting!")
            self.makePlacement(item, location_pool, access)


    def makePlacement(self, item, location_pool, access) -> None:
        self.shuffler.rng.shuffle(location_pool)

        # Keep track of where we placed items. this is necessary to undo placements if we get stuck
        placement_tracker = []

        # if verbose: print(item+' -> ', end='')
        first_location_tried = location_pool[0]

        # Until we make a valid placement for this item
        valid_placement = False
        while not valid_placement and self.shuffler.thread_active:
            # Try placing the first item in the list in the first location
            self.shuffler.placements[location_pool[0]] = item
            access = self.shuffler.removeAccess(access, item)

            # Check if it's reachable there
            valid_placement = self.shuffler.canReachLocation(location_pool[0], access)
            if not valid_placement:
                # If it's not, take back the item and shift that location to the end of the list
                access = self.shuffler.addAccess(access, item)
                self.shuffler.placements[location_pool[0]] = None
                location_pool.append(location_pool.pop(0))
                if location_pool[0] == first_location_tried: 
                    raise ValueError("None of the locations are valid to place the instrument!")
                    # # If we tried every location and none work, undo the previous placement and try putting it somewhere else. Also rerandomize the location list to ensure things aren't placed back in the same spots
                    # undo_location = placement_tracker.pop(0)
                    # location_pool.append(undo_location)
                    # self.shuffler.locations.append(undo_location)
                    # self.shuffler.rng.shuffle(location_pool)
                    # self.shuffler.items.insert(0, self.shuffler.placements[undo_location])
                    # item_pool.insert(0, self.shuffler.placements[undo_location])
                    # access = self.shuffler.addAccess(access, self.shuffler.placements[undo_location])
                    # self.shuffler.placements[undo_location] = None
                    # # if verbose: print("can't place")
                    # break

        if valid_placement and self.shuffler.thread_active:
            # After we successfully made a valid placement, remove the item and location from consideration
            self.shuffler.items.remove(item)
            # item_pool.remove(item)
            # if verbose: print(location_pool[0])
            self.shuffler.locations.remove(location_pool[0])
            placement_tracker.append(location_pool.pop(0))


INSTRUMENTS = (
    "full-moon-cello",
    "conch-horn",
    "sea-lilys-bell",
    "surf-harp",
    "wind-marimba",
    "coral-triangle",
    "evening-calm-organ",
    "thunder-drum"
)

DUNGEON_REWARD_LOCATIONS = (
    "D1-instrument",
    "D2-instrument",
    "D3-instrument",
    "D4-instrument",
    "D5-instrument",
    "D6-instrument",
    "D7-instrument",
    "D8-instrument",
    "D0-fairy-1",
    "D0-fairy-2"
)
