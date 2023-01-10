from PySide6 import QtCore

import spoiler

import re
import random
import traceback



class ItemShuffler(QtCore.QThread):
    
    # sends signals to main thread when emitted
    progress_update = QtCore.Signal(int)
    give_placements = QtCore.Signal(dict)
    is_done = QtCore.Signal()
    error = QtCore.Signal()

    
    # initialize
    def __init__(self, rom_path, out_dir, seed, logic, settings, item_defs, logic_defs, parent=None):
        QtCore.QThread.__init__(self, parent)

        self.rom_path = rom_path
        self.out_dir = out_dir
        self.seed = seed
        random.seed(self.seed)
        self.logic = logic
        self.settings = settings
        self.item_defs = item_defs
        self.logic_defs = logic_defs
        
        self.force_chests = ['zol-trap', 'stalfos-note']
        # self.force_out_shop = ['zap-trap']

        self.progress_value = 0
        self.thread_active = True
    
    
    # thread automatically starts the run method
    def run(self):
        if not self.settings['owl-overworld-gifts']:
            owls = [k for k, v in self.logic_defs.items()
                   if v['type'] == 'item'
                   and v['subtype'] == 'overworld-statue']
            for owl in owls:
                del self.logic_defs[owl]
        else:
            self.item_defs['rupee-20']['quantity'] += 9 # 33 total owl statues
        
        if not self.settings['owl-dungeon-gifts']:
            owls = [k for k, v in self.logic_defs.items()
                   if v['type'] == 'item'
                   and v['subtype'] == 'dungeon-statue']
            for owl in owls:
                del self.logic_defs[owl]
        else:
            self.item_defs['rupee-20']['quantity'] += 24 # 33 total owl statues

        # TEMPORARY CODE HERE to make it so that everything that isn't randomized yet is set to vanilla
        vanilla_locations = [k for k, v in self.logic_defs.items()
                            if v['type'] == 'item'
                            and v['subtype'] not in ('chest', 'boss', 'drop', 'npc', 'standing', 'overworld-statue', 'dungeon-statue')]
        vanilla_locations.append('trendy-prize-1') # yoshi doll stays until trendy is properly shuffled
        vanilla_locations.append('trendy-prize-2')
        vanilla_locations.append('trendy-prize-3')
        vanilla_locations.append('trendy-prize-4')
        vanilla_locations.append('trendy-prize-5')
        vanilla_locations.append('trendy-prize-6')
        # vanilla_locations.remove('bay-passage-sunken')
        # vanilla_locations.remove('river-crossing-cave')
        # vanilla_locations.remove('kanalet-moat-south')
        # vanilla_locations.remove('south-bay-sunken')
        # vanilla_locations.remove('taltal-east-drop')
        
        # if not self.settings['shuffle-companions']:
        # vanilla_locations.append('moblin-cave')
        # vanilla_locations.append('rooster-statue')

        if not self.settings['blup-sanity']:
            blupees = [k for k, v in self.logic_defs.items()
                      if k.startswith('D0-rupee')]
            for blup in blupees:
                vanilla_locations.append(blup)

        ### ITEM_DEF CHANGES DEPENDING ON SEED SETTINGS
        instruments = [k for k, v in self.logic_defs.items()
            if v['type'] == 'item'
            and v['subtype'] == 'standing'
            and v['content'] in (
                'full-moon-cello',
                'conch-horn',
                'sea-lilys-bell',
                'surf-harp',
                'wind-marimba',
                'coral-triangle',
                'evening-calm-organ',
                'thunder-drum')
        ]
        start_instruments = []
        if self.settings['starting-instruments'] > 0:
            random.shuffle(instruments)
            for i in range(self.settings['starting-instruments']):
                inst = instruments.pop(0)
                start_instruments.append(self.logic_defs[inst]['content'])
            for e, i in enumerate(start_instruments):
                self.logic_defs[f'starting-instrument-{e+1}'] = {
                    'type': 'item',
                    'subtype': 'npc',
                    'content': i,
                    'region': 'mabe',
                    'spoiler-region': 'mabe-village'
                }
                vanilla_locations.append(f'starting-instrument-{e+1}')
                self.item_defs['rupee-50']['quantity'] += 1

        if not self.settings['shuffle-instruments']:
            for inst in instruments:
                vanilla_locations.append(inst)

        if self.settings['assured-sword-shield']:
            vanilla_locations.append('tarin')
            vanilla_locations.append('washed-up')
        
        if self.settings['classic-d2']:
            self.logic_defs['bottle-grotto']['condition-basic'] = 'swamp & kill-flower'
        
        if self.settings['shuffle-bombs']:
            self.item_defs['bomb']['type'] = 'important'
            self.logic_defs['bombs']['condition-basic'] =\
                '(can-shop | (can-farm-rupees & color-dungeon) | (rapids & (feather | boomerang)) | (angler-tunnel & (sword | feather | boomerang))) & bomb'
        
        if not self.settings['shuffle-tunics']:
            self.item_defs['red-tunic']['quantity'] = 0
            self.item_defs['blue-tunic']['quantity'] = 0
            self.item_defs['rupee-50']['quantity'] += 2 # +100 rupees
        
        if self.settings['zap-sanity']:
            if self.settings['blup-sanity']:
                self.item_defs['rupee-5']['quantity'] -= 14 # replace half of the blue rupees with zap traps because fun :D
                self.item_defs['zap-trap']['quantity'] += 14
            
            if self.settings['owl-overworld-gifts']:
                self.item_defs['rupee-20']['quantity'] -= 3 # replace a third of the owl 20 rupees with zap traps because fun :D
                self.item_defs['zap-trap']['quantity'] += 3
            
            if self.settings['owl-dungeon-gifts']:
                self.item_defs['rupee-20']['quantity'] -= 8 # replace a third of the owl 20 rupees with zap traps because fun :D
                self.item_defs['zap-trap']['quantity'] += 8
            
            self.item_defs['rupee-50']['quantity'] -= 18 # -900 rupees
            self.item_defs['rupee-100']['quantity'] += 5 # +500 rupees
            self.item_defs['rupee-300']['quantity'] += 1 # +300 rupees
            self.item_defs['zol-trap']['quantity'] -= 3
            self.item_defs['zap-trap']['quantity'] += 15
        
        placements = None
        try:
            # Create a placement, spoiler log, and game mod.
            if self.thread_active:
                placements = self.makeRandomizedPlacement(self.logic, self.settings['excluded-locations'],
                                                          vanilla_locations, self.settings, start_instruments, False)
            
            if self.thread_active:
                self.give_placements.emit(placements)
        
        except (AttributeError, IndexError, KeyError, ValueError, TypeError):
            self.error.emit(placements, traceback.format_exc())
        
        self.is_done.emit()
    
    
    
    ########################################################################################################################
    # STOP THREAD
    def stop(self):
        self.thread_active = False
    
    
    
    ########################################################################################################################
    # SHUFFLE ITEMS
    def addAccess(self, access, new):
        if new in access:
            access[new] += 1
        else:
            access[new] = 1
        return access
    
    
    def removeAccess(self, access, toRemove):
        if toRemove in access:
            access[toRemove] -= 1
            if access[toRemove] == 0:
                access.pop(toRemove)
        return access
    
    
    def hasAccess(self, access, key, amount=1):
        return key in access and access[key] >= amount
    
    
    def checkAccess(self, newCheck, access, logic):
        # get the name of the check without the parameter sometimes applied to enemy checks
        no_params = re.match('[a-zA-Z0-9-]+', newCheck).group(0)
        
        if logic == 'none': return True
        
        if self.logic_defs[no_params]['type'] == 'enemy':
            param = re.search('\\[([a-z]+)\\]', newCheck)
            if param:
                return eval(self.parseCondition(self.logic_defs[no_params]['condition-basic'])) or eval(self.parseCondition(self.logic_defs[no_params]['condition-'+param.group(1)]))
            else:
                return eval(self.parseCondition(self.logic_defs[no_params]['condition-basic']))
        else:
            # For item and follower checks, see if you have access to the region. Otherwise, check on the conditions, if they exist
            region_access = self.hasAccess(access, self.logic_defs[newCheck]['region']) if (self.logic_defs[newCheck]['type'] in ('item', 'follower')) else True
            basic        = eval(self.parseCondition(self.logic_defs[newCheck]['condition-basic']))    if ('condition-basic' in self.logic_defs[newCheck]) else True
            advanced     = eval(self.parseCondition(self.logic_defs[newCheck]['condition-advanced'])) if (('condition-advanced' in self.logic_defs[newCheck]) and (logic in ('advanced', 'glitched', 'death'))) else False
            glitched     = eval(self.parseCondition(self.logic_defs[newCheck]['condition-glitched'])) if (('condition-glitched' in self.logic_defs[newCheck]) and logic in ('glitched', 'death')) else False
            death        = eval(self.parseCondition(self.logic_defs[newCheck]['condition-death']))    if (('condition-death' in self.logic_defs[newCheck]) and logic == 'death') else False
            return region_access and (basic or advanced or glitched or death)
    
    
    def parseCondition(self, condition):
        func = condition
        func = re.sub('([a-zA-Z0-9\\-\\[\\]]+)(:(\\d+))?', lambda match: f'self.hasAccess(access, "{match.group(1)}", {match.group(3) or 1})', func)
        func = re.sub('\\|', 'or', func)
        func = re.sub('&', 'and', func)
        return func
    
    
    def canReachLocation(self, to_reach, placements, starting_access, logic):
        """Given a set of item placements, and a starting item set, verify whether the location toReach is possible from the start of the game
        
        Parameters
        ----------
        toReach : str
            The name of the location to check
        placements : dict
            Full of <location : str, item : str> pairs to represent items placed in locations. Currently empty locations have the value None.
        startingAccess : dict
            A dict of <item : str, quantity : int> pairs. The starting item/access set to consider, i.e. all items not yet placed
        logic : str
            The logic to use in verifying. 'basic', 'advanced', or 'glitched'
        
        Returns True or False depending on whether access is eventually gained to toReach.
        """
        
        # If this location is disabled (force junk), consider it to be unreachable. This will result in no important items being placed there.
        if to_reach in placements['force-junk']:
            return False
        
        # if using no logic, we don't have to check if it's reachable, we just assume it is.
        if logic == 'none':
            return True
        
        access = starting_access.copy()
        access_added = True
        
        while access_added and self.thread_active:
            access_added = False
            for key in self.logic_defs:
                if self.thread_active:
                    if key not in access:
                        if self.checkAccess(key, access, logic):
                            access = self.addAccess(access, key)
                            access_added = True
                            # if this is the location we were looking for, we're done!
                            if key == to_reach:
                                return True
                            
                            # if we're looking at an item or follower location, at the item it holds, if it has one
                            if (self.logic_defs[key]['type'] in ['item', 'follower']) and placements[key] != None:
                                access = self.addAccess(access, placements[key])
                            
                            # if we're looking at an enemy, and we CAN kill it, then we can also kill it with access to pits or heavy objects, so add those too
                            if self.logic_defs[key]['type'] == 'enemy':
                                access = self.addAccess(access, key+'[pit]')
                                access = self.addAccess(access, key+'[heavy]')
                        
                        # if we can't do the thing, but it's an enemy, we might be able to use pits or heavy throwables, so check those cases independently
                        elif self.logic_defs[key]['type'] == 'enemy':
                            if 'condition-pit' in self.logic_defs[key] and not self.hasAccess(access, key+'[pit]'):
                                if self.checkAccess(key+'[pit]', access, logic):
                                    access = self.addAccess(access, key+'[pit]')
                                    access_added = True
                            if 'condition-heavy' in self.logic_defs[key] and not self.hasAccess(access, key+'[heavy]'):
                                if self.checkAccess(key+'[heavy]', access, logic):
                                    access = self.addAccess(access, key+'[heavy]')
                                    access_added = True
                else: break
            
        # If we get stuck and can't find any more locations to add, then we're stuck and can't reach toReach
        return False
    
    
    def verifySeashellsAttainable(self, placements, starting_access, logic, goal):
        # Verify, given the starting access to items, whether it is possible to get up to [goal] seashells. This includes already placed shells (vanilla) or 
        locations = []
        access = starting_access.copy()
        access_added = True
        
        # This check is run before random shells are placed, so any seashell come across during this runthrough
        # must have been forced vanilla. We don't want to count these directly in access.
        vanilla_seashells = 0
        
        while access_added and self.thread_active:
            access_added = False
            for key in self.logic_defs:
                if self.thread_active:
                    if key not in access:
                        if self.checkAccess(key, access, logic) or logic == 'none':
                            access = self.addAccess(access, key)
                            access_added = True
                            
                            # if we're looking at an item or follower location, at the item it holds, if it has one
                            if (self.logic_defs[key]['type'] in ['item', 'follower']) and placements[key] != None:
                                if placements[key] == 'seashell':
                                    vanilla_seashells += 1
                                else:
                                    access = self.addAccess(access, placements[key])
                            
                            if self.logic_defs[key]['type'] == 'item' and placements[key] == None:
                                locations.append(key)
                            
                            # if we're looking at an enemy, and we CAN kill it, then we can also kill it with access to pits or heavy objects, so add those too
                            if self.logic_defs[key]['type'] == 'enemy':
                                access = self.addAccess(access, key+'[pit]')
                                access = self.addAccess(access, key+'[heavy]')
                        # if we can't do the thing, but it's an enemy, we might be able to use pits or heavy throwables, so check those cases independently
                        elif self.logic_defs[key]['type'] == 'enemy':
                            if 'condition-pit' in self.logic_defs[key] and not self.hasAccess(access, key+'[pit]'):
                                if self.checkAccess(key+'[pit]', access, logic):
                                    access = self.addAccess(access, key+'[pit]')
                                    access_added = True
                            if 'condition-heavy' in self.logic_defs[key] and not self.hasAccess(access, key+'[heavy]'):
                                if self.checkAccess(key+'[heavy]', access, logic):
                                    access = self.addAccess(access, key+'[heavy]')
                                    access_added = True
                else: break
        
        #print(len(locations), numRandom, access['seashell'], goal)
        #print(access)
        return len(locations) + vanilla_seashells >= goal
    
    
    
    def makeRandomizedPlacement(self, logic, force_junk, force_vanilla, settings, starting_instruments, verbose=False):
        """Creates and returns a a randomized placement of items, adhering to the logic
        
        Parameters
        ----------
        seed : int
            The seed to initialize the randomness.
        logic : str
            The logic to use in verifying. 'basic', 'advanced', or 'glitched'
        forceJunk : list
            A list of strings as location names, which should be forced to hold junk items.
        forceVanilla : list
            A list of strings as location names, which should be forced to hold the same item they do in the normal game.
            forceJunk takes priority over forceVanilla
        
        """
        
        if not set(force_junk).isdisjoint(force_vanilla):
            print('Warning! Some locations set as disabled are unrandomized. These locations will not actually be considered out of logic.')
            force_junk = [l for l in force_junk if l not in force_vanilla]
        
        # Ensure all excluded locations are actually location names
        force_junk = [l for l in force_junk if l in self.logic_defs and self.logic_defs[l]['type'] == 'item']
        
        # # Make sure logic is a valid value, default to basic
        # if logic not in ['basic', 'advanced', 'glitched', 'none']:
        #     logic = 'basic'
        
        # Initialize the item and location lists, and the structures for tracking placements and access
        access = {}
        important_items = []
        seashell_items = []
        good_items = []
        junk_items = []
        dungeon_items = []
        locations = []
        placements = {}
        
        vanilla_seashells = 0 # Keep track of how many seashells were forced into their vanilla locations. This is important for ensuring there is enough room to place the random ones.
        
        placements['settings'] = settings
        placements['force-junk'] = force_junk
        placements['force-vanilla'] = force_vanilla
        placements['starting-instruments'] = starting_instruments
        placements['indexes'] = {}
        
        indexes_available = {'seashell': list(range(50)), 'heart-piece': list(range(32)), 'heart-container': list(range(9)), 'bottle': list(range(3)), 'golden-leaf': list(range(5)), 'chamber-stone': [3, 4, 8, 10, 11, 12, 13, 20, 21, 22, 23, 24, 25, 26]}
        
        for key in self.logic_defs:
            if self.thread_active:
                if self.logic_defs[key]['type'] == 'item':
                    locations.append(key)
                    placements[key] = None
                    access = self.addAccess(access, self.logic_defs[key]['content']) # we're going to assume the player starts with everything, then slowly loses things as they get placed into the wild
            else: break
        
        # Add the settings into the access. This affects some logic like with fast trendy, free fishing, etc.
        settings_access = {setting: 1 for setting in settings if settings[setting] == True}
        access.update(settings_access)
        
        # For each type of item in the item pool, add its quantity to the item lists
        for key in self.item_defs:
            if self.thread_active:
                if self.item_defs[key]['type'] == 'important':
                    important_items += [key] * self.item_defs[key]['quantity']
                elif self.item_defs[key]['type'] == 'seashell':
                    seashell_items += [key] * self.item_defs[key]['quantity']
                elif self.item_defs[key]['type'] == 'good':
                    good_items += [key] * self.item_defs[key]['quantity']
                elif self.item_defs[key]['type'] == 'junk':
                    junk_items += [key] * self.item_defs[key]['quantity']
                else:
                    dungeon_items += [key] * self.item_defs[key]['quantity']
            else: break
        
        # Force the followers to be vanilla (for now)
        placements['moblin-cave'] = 'bow-wow'
        placements['rooster-statue'] = 'rooster'
        
        # Shuffle item and location lists
        random.shuffle(important_items)
        random.shuffle(seashell_items)
        random.shuffle(good_items)

        items = important_items + seashell_items + good_items + junk_items + dungeon_items
        # print(len(items))

        # Assign vanilla contents to forceVanilla locations
        for loc in force_vanilla:
            if self.thread_active:
                # If it's not a valid location name, or already used for forceJunk, just ignore it
                if loc not in locations:
                    continue
                
                # Place the defined vanilla content
                placements[loc] = self.logic_defs[loc]['content']
                items.remove(self.logic_defs[loc]['content'])
                access = self.removeAccess(access, self.logic_defs[loc]['content'])
                locations.remove(loc)
                
                if self.logic_defs[loc]['content'] == 'seashell':
                    vanilla_seashells += 1
                
                # If the item is one that needs an index, assign it its vanilla item index and remove that from the available indexes
                if self.logic_defs[loc]['content'] in indexes_available:
                    placements['indexes'][loc] = self.logic_defs[loc]['index']
                    indexes_available[self.logic_defs[loc]['content']].remove(self.logic_defs[loc]['index'])
            else: break
                
        # Next, assign dungeon items into their own dungeons
        # Some may have been placed already because of forceVanilla so we need to factor that in
        dungeons = ['color-dungeon', 'tail-cave', 'bottle-grotto', 'key-cavern', 'angler-tunnel', 'catfish-maw', 'face-shrine', 'eagle-tower', 'turtle-rock']
        for i in range(len(dungeons)):
            if self.thread_active:
                item_pool = list(filter((lambda s: len(s) >= 2 and s[-2:] == f'D{i}'), items))
                location_pool = list(filter((lambda s: len(s) >= 2 and s[:2] == f'D{i}'), locations))
                random.shuffle(location_pool)
                
                # Keep track of where we placed items. this is necessary to undo placements if we get stuck
                placement_tracker = []
                
                # Iterate through the dungeon items for that dungeon (inherently in order of nightmare key, small keys, stone beak, compass, map)
                while item_pool and self.thread_active:
                    item = item_pool[0]
                    if verbose: print(item+' -> ', end='')
                    first_location_tried = location_pool[0]
                    
                    # Until we make a valid placement for this item
                    valid_placement = False
                    while not valid_placement and self.thread_active:
                        # Try placing the first item in the list in the first location
                        placements[location_pool[0]] = item
                        access = self.removeAccess(access, item)
                                                
                        # Check if it's reachable there
                        valid_placement = self.canReachLocation(location_pool[0], placements, access, logic)
                        if not valid_placement:
                            # If it's not, take back the item and shift that location to the end of the list
                            access = self.addAccess(access, item)
                            placements[location_pool[0]] = None
                            location_pool.append(location_pool.pop(0))
                            if location_pool[0] == first_location_tried: 
                                # If we tried every location and none work, undo the previous placement and try putting it somewhere else. Also rerandomize the location list to ensure things aren't placed back in the same spots
                                undo_location = placement_tracker.pop(0)
                                location_pool.append(undo_location)
                                locations.append(undo_location)
                                random.shuffle(location_pool)
                                items.insert(0, placements[undo_location])
                                item_pool.insert(0, placements[undo_location])
                                access = self.addAccess(access, placements[undo_location])
                                placements[undo_location] = None
                                if verbose: print("can't place")
                                break
                    
                    if valid_placement and self.thread_active:
                        # After we successfully made a valid placement, remove the item and location from consideration
                        items.remove(item)
                        item_pool.remove(item)
                        if verbose: print(location_pool[0])
                        locations.remove(location_pool[0])
                        placement_tracker.append(location_pool.pop(0))
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)

            else: break
        
        # Shuffle remaining locations
        random.shuffle(locations)
        
        # Place the traps and master stalfos note. These HAVE to go in chests so we need to do them first
        to_place = list(filter(lambda s: s in self.force_chests, items))
        chests = list(filter(lambda s: self.logic_defs[s]['subtype'] == 'chest', locations))
        for item in to_place:
            if self.thread_active:
                if verbose: print(item+' -> ', end='')
                chest = chests.pop(0)
                placements[chest] = item
                items.remove(item)
                locations.remove(chest)
                if verbose: print(chests[0])
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
            else: break
                
        # Next, place an item on Tarin. Since Tarin is the only check available with no items, he has to have something out of a certain subset of items
        # Only do this if Tarin has no item placed, i.e. not forced to be vanilla
        if placements['tarin'] == None and self.thread_active:
            success = False
            while not success and self.thread_active:
                placements['tarin'] = items[0]
                success = (self.canReachLocation('can-shop', placements, settings_access, logic)
                        or self.canReachLocation('tail-cave', placements, settings_access, logic)
                        or self.canReachLocation('beach', placements, settings_access, logic)
                        or self.canReachLocation('mamasha', placements, settings_access, logic)
                        or self.canReachLocation('ciao-ciao', placements, settings_access, logic)
                        or self.canReachLocation('marin', placements, settings_access, logic)
                        or self.canReachLocation('trendy', placements, settings_access, logic))
                
                if not success:
                    items.insert(items.index('seashell'), items[0])
                    items.pop(0)
            
            if verbose: print(items[0]+' -> tarin')
            access = self.removeAccess(access, items.pop(0))
            locations.remove('tarin')

            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        # Keep track of where we placed items. this is necessary to undo placements if we get stuck
        placement_tracker = []
        
        # Do a very similar process for all other items
        while items and self.thread_active:
            item = items[0]
            if verbose: print(item+' -> ', end='')
            first_location_tried = locations[0]
            
            # Until we make a valid placement for this item
            valid_placement = False
            while not valid_placement and self.thread_active:
                # Try placing the first item in the list in the first location
                placements[locations[0]] = item
                access = self.removeAccess(access, item)
                
                # Check for item type restrictions, i.e. songs can't be standing items
                if item in ('song-ballad', 'song-mambo', 'song-soul', 'bomb-capacity', 'arrow-capacity', 'powder-capacity', 'red-tunic', 'blue-tunic') and self.logic_defs[locations[0]]['subtype'] in ('standing', 'hidden', 'dig', 'drop', 'boss', 'underwater', 'shop'):
                    valid_placement = False
                elif item in self.force_chests and self.logic_defs[locations[0]]['subtype'] != 'chest':
                    valid_placement = False
                # elif item == 'zap-trap' and self.logic_defs[locations[0]]['region'] == 'trendy' and not locations[0].endswith('final'):
                #     valid_placement = False
                # elif item == 'zap-trap' and self.logic_defs[locations[0]]['subtype'] == 'shop':
                #     valid_placement = False
                elif self.item_defs[item]['type'] in ('important', 'seashell'):
                    # Check if it's reachable there. We only need to do this check for important items! good and junk items are never needed in logic
                    valid_placement = self.canReachLocation(locations[0], placements, access, logic)
                else:
                    valid_placement = True
                
                # If it wasn't valid, put it back and shift the first location to the end of the list
                if not valid_placement:
                    access = self.addAccess(access, item)
                    placements[locations[0]] = None
                    locations.append(locations.pop(0))
                    if locations[0] == first_location_tried: 
                        # If we tried every location and none work, undo the previous placement and try putting it somewhere else
                        undo_location = placement_tracker.pop(0)
                        locations.append(undo_location)
                        random.shuffle(locations)
                        items.insert(0, placements[undo_location])
                        access = self.addAccess(access, placements[undo_location])
                        placements[undo_location] = None
                        if verbose: print("can't place")
                        break
            
            if valid_placement and self.thread_active:
                # After we successfully made a valid placement, remove the item and location from consideration
                if verbose: print(locations[0])
                
                placed_item = items.pop(0)

                # If the item is one that needs an index, give it the next available one
                if placed_item in indexes_available:
                    placements['indexes'][locations[0]] = indexes_available[placed_item].pop(0)
                
                placement_tracker.append(locations.pop(0))
                
                # If we placed the last important item (so that afterward we start placing seashells), we want to ensure there's enough available locations to place a number of seashells required.
                # i.e., are there 40 locations reachable without getting the 40 and 50 rewards? If not, we haven't made a valid placement, so we have to go back and undo things until this is resolved.
                if item != 'seashell' and len(items) > 0 and items[0] == 'seashell':
                    if not ((self.verifySeashellsAttainable(placements, settings_access, logic, 5)) 
                    and (self.verifySeashellsAttainable(placements, settings_access, logic, 15))
                    and (self.verifySeashellsAttainable(placements, settings_access, logic, 30))
                    and (self.verifySeashellsAttainable(placements, settings_access, logic, 40))
                    and (self.verifySeashellsAttainable(placements, settings_access, logic, 50))):
                        if verbose: 
                            print('no room for shells')
                            #print(placements)
                        undo_location = placement_tracker.pop(0)
                        locations.append(undo_location)
                        random.shuffle(locations)
                        items.insert(0, placements[undo_location])
                        access = self.addAccess(access, placements[undo_location])
                        placements[undo_location] = None
                
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        if self.thread_active and placements['settings']['create-spoiler']:
            spoiler.generateSpoilerLog(placements, self.logic_defs, self.out_dir, self.seed)
        
        return placements
