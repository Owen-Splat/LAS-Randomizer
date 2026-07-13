class ShufflerDungeonItems:
    """Assigns the placement of dungeon items based on user settings"""

    def __init__(self, shuffler, access) -> None:
        self.shuffler = shuffler
        self.assignItems(access)


    def assignItems(self, access) -> None:
        for setting_name, item_prefix in ITEM_SETTINGS_KEYS.items():
            if not self.shuffler.thread_active:
                return

            setting: str = str(self.shuffler.settings[setting_name])
            if setting in ("Start With", "Anywhere"):
                continue

            for i in range(len(DUNGEONS)):
                item_pool = [s for s in self.shuffler.items if s.startswith(item_prefix) and s[-2:] == f'D{i}']

                if setting == "Own Dungeon":
                    location_pool = [s for s in self.shuffler.locations if s[:2] == f'D{i}']
                elif setting == "Any Dungeon":
                    location_pool = [s for s in self.shuffler.locations if s[0] == 'D' and s[2] == '-']
                else:
                    raise ValueError("Invalid dungeon item setting!")

                self.makePlacements(item_pool, location_pool, access)


    def makePlacements(self, item_pool, location_pool, access) -> None:
        self.shuffler.rng.shuffle(location_pool)

        # Keep track of where we placed items. this is necessary to undo placements if we get stuck
        placement_tracker = []

        # Iterate through the dungeon items for that dungeon (inherently in order of nightmare key, small keys, stone beak, compass, map)
        while item_pool and self.shuffler.thread_active:
            item = item_pool[0]
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
                        # If we tried every location and none work, undo the previous placement and try putting it somewhere else. Also rerandomize the location list to ensure things aren't placed back in the same spots
                        undo_location = placement_tracker.pop(0)
                        location_pool.append(undo_location)
                        self.shuffler.locations.append(undo_location)
                        self.shuffler.rng.shuffle(location_pool)
                        self.shuffler.items.insert(0, self.shuffler.placements[undo_location])
                        item_pool.insert(0, self.shuffler.placements[undo_location])
                        access = self.shuffler.addAccess(access, self.shuffler.placements[undo_location])
                        self.shuffler.placements[undo_location] = None
                        # if verbose: print("can't place")
                        break

            if valid_placement and self.shuffler.thread_active:
                # After we successfully made a valid placement, remove the item and location from consideration
                self.shuffler.items.remove(item)
                item_pool.remove(item)
                # if verbose: print(location_pool[0])
                self.shuffler.locations.remove(location_pool[0])
                placement_tracker.append(location_pool.pop(0))


ITEM_SETTINGS_KEYS = {
    "Dungeon Maps":     "map",
    "Compasses":        "compass",
    "Stone Beaks":      "stone-beak",
    "Small Keys":       "key",
    "Nightmare Keys":   "nightmare-key"
}

DUNGEONS = (
    'color-dungeon',
    'tail-cave',
    'bottle-grotto',
    'key-cavern',
    'angler-tunnel',
    'catfish-maw',
    'face-shrine',
    'eagle-tower',
    'turtle-rock'
)
