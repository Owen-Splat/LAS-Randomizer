from PySide6 import QtCore

import re
import random

import spoiler



class ItemShuffler(QtCore.QThread):
    
    # sends signals to main thread when emitted
    progress_update = QtCore.Signal(int)
    is_done = QtCore.Signal(bool)
    give_placements = QtCore.Signal(dict)
    
    
    # initialize
    def __init__(self, rom_path, out_dir, seed, logic, settings, items, logic_def, parent=None):
        QtCore.QThread.__init__(self, parent)

        self.rom_path = rom_path
        self.out_dir = out_dir
        self.seed = seed
        self.logic = logic
        self.rom_path = rom_path
        self.out_dir = out_dir
        self.seed = seed
        self.settings = settings
        self.item_defs = items
        self.logic_defs = logic_def
        
        self.forceChests = ['zol-trap', 'zap-trap', 'stalfos-note']

        self.progress_value = 0
        self.threadActive = True
    
    
    # thread automatically starts the run method
    def run(self):
        
        # TEMPORARY CODE HERE to make it so that everything that isn't a chest is set to vanilla
        vanilla_locations = list(filter( lambda l: self.logic_defs[l]['type'] == 'item' and self.logic_defs[l]['subtype'] not in ['chest', 'boss', 'drop'] , self.logic_defs))
        vanilla_locations.remove('tarin')
        vanilla_locations.remove('washed-up')
        vanilla_locations.remove('marin')
        vanilla_locations.remove('christine-grateful')
        vanilla_locations.remove('invisible-zora')
        vanilla_locations.remove('ghost-reward')
        vanilla_locations.remove('walrus')
        vanilla_locations.remove('D0-fairy-1')
        vanilla_locations.remove('D0-fairy-2')
        vanilla_locations.remove('goriya-trader')
        vanilla_locations.remove('manbo')
        vanilla_locations.remove('mamu')
        vanilla_locations.remove('rapids-race-45')
        vanilla_locations.remove('rapids-race-35')
        vanilla_locations.remove('rapids-race-30')
        vanilla_locations.remove('fishing-orange')
        vanilla_locations.remove('fishing-cheep-cheep')
        vanilla_locations.remove('fishing-ol-baron')
        vanilla_locations.remove('fishing-50')
        vanilla_locations.remove('fishing-100')
        vanilla_locations.remove('fishing-150')
        vanilla_locations.remove('fishing-loose')
        vanilla_locations.remove('5-seashell-reward')
        vanilla_locations.remove('15-seashell-reward')
        vanilla_locations.remove('30-seashell-reward')
        vanilla_locations.remove('40-seashell-reward')
        vanilla_locations.remove('50-seashell-reward')
        vanilla_locations.remove('mad-batter-bay')
        vanilla_locations.remove('mad-batter-woods')
        vanilla_locations.remove('mad-batter-taltal')
        vanilla_locations.remove('dampe-page-1')
        vanilla_locations.remove('dampe-page-2')
        vanilla_locations.remove('dampe-final')
        vanilla_locations.remove('dampe-heart-challenge')
        vanilla_locations.remove('dampe-bottle-challenge')
        vanilla_locations.remove('trendy-prize-final')
        vanilla_locations.remove('woods-loose')
        vanilla_locations.remove('taltal-rooster-cave')
        vanilla_locations.remove('dream-shrine-left')

        vanilla_locations.remove('trendy-prize-1')
        self.settings['excluded-locations'].update(['trendy-prize-1'])

        vanilla_locations.remove('mamasha')
        vanilla_locations.remove('ciao-ciao')
        vanilla_locations.remove('sale')
        vanilla_locations.remove('kiki')
        vanilla_locations.remove('tarin-ukuku')
        vanilla_locations.remove('chef-bear')
        vanilla_locations.remove('papahl')
        vanilla_locations.remove('christine-trade')
        vanilla_locations.remove('mr-write')
        vanilla_locations.remove('grandma-yahoo')
        vanilla_locations.remove('bay-fisherman')
        vanilla_locations.remove('mermaid-martha')
        vanilla_locations.remove('mermaid-cave')

        vanilla_locations.append('kanalet-kill-room')
        
        heart_pieces = list(filter( lambda l: self.logic_defs[l]['type'] == 'item' 
        and self.logic_defs[l]['subtype'] in ['standing', 'underwater'] 
        and self.logic_defs[l]['content'] == 'heart-piece' 
        and self.logic_defs[l]['region'] != 'trendy', self.logic_defs))
        for heart in heart_pieces:
            vanilla_locations.remove(heart)

        if self.settings['shuffle-instruments']:
            instruments = list(filter( lambda l: self.logic_defs[l]['type'] == 'item' 
            and self.logic_defs[l]['subtype'] == 'standing' 
            and self.logic_defs[l]['content'] in [
                'full-moon-cello',
                'conch-horn',
                'sea-lilys-bell',
                'surf-harp',
                'wind-marimba',
                'coral-triangle',
                'evening-calm-organ',
                'thunder-drum'
            ], self.logic_defs))
            for inst in instruments:
                vanilla_locations.remove(inst)
                
        if self.settings['assured-sword-shield']:
            vanilla_locations.append('tarin')
            vanilla_locations.append('washed-up')
        
        if self.settings['shuffle-bombs']:
            self.item_defs['bomb']['type'] = 'important'
            self.logic_defs['bombs']['condition-basic'] = 'can-shop & bomb'
        
        if not self.settings['shuffle-tunics']:
            self.item_defs['red-tunic']['quantity'] = 0
            self.item_defs['blue-tunic']['quantity'] = 0
            self.item_defs['rupee-50']['quantity'] += 2
        
        if self.settings['zap-sanity']:
            self.item_defs['zap-trap']['quantity'] = 30
            self.forceChests.remove('zap-trap')
        
        # Create a placement, spoiler log, and game mod.
        if self.threadActive:
            placements = self.makeRandomizedPlacement(self.seed, self.logic, self.settings['excluded-locations'], vanilla_locations, self.settings, False)
        
        if self.threadActive:
            self.give_placements.emit(placements)
        
        self.is_done.emit(True)
    
    
    
    
    
    ########################################################################################################################
    # STOP THREAD
    def stop(self):
        self.threadActive = False
    
    
    
    
    
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
        noParams = re.match('[a-zA-Z0-9-]+', newCheck).group(0)
        
        if logic == 'none': return True
        
        if self.logic_defs[noParams]['type'] == 'enemy':
            param = re.search('\\[([a-z]+)\\]', newCheck)
            if param:
                return eval(self.parseCondition(self.logic_defs[noParams]['condition-basic'])) or eval(self.parseCondition(self.logic_defs[noParams]['condition-'+param.group(1)]))
            else:
                return eval(self.parseCondition(self.logic_defs[noParams]['condition-basic']))
        else:
            # For item and follower checks, see if you have access to the region. Otherwise, check on the conditions, if they exist
            regionAccess = self.hasAccess(access, self.logic_defs[newCheck]['region']) if (self.logic_defs[newCheck]['type'] == 'item' or self.logic_defs[newCheck]['type'] == 'follower') else True
            basic        = eval(self.parseCondition(self.logic_defs[newCheck]['condition-basic']))    if ('condition-basic' in self.logic_defs[newCheck]) else True
            advanced     = eval(self.parseCondition(self.logic_defs[newCheck]['condition-advanced'])) if (('condition-advanced' in self.logic_defs[newCheck]) and (logic == 'advanced' or logic == 'glitched')) else False
            glitched     = eval(self.parseCondition(self.logic_defs[newCheck]['condition-glitched'])) if (('condition-glitched' in self.logic_defs[newCheck]) and logic == 'glitched') else False
            return regionAccess and (basic or advanced or glitched)
    
    
    def parseCondition(self, condition):
        func = condition
        func = re.sub('([a-zA-Z0-9\\-\\[\\]]+)(:(\\d+))?', lambda match: f'self.hasAccess(access, "{match.group(1)}", {match.group(3) or 1})', func)
        func = re.sub('\\|', 'or', func)
        func = re.sub('&', 'and', func)
        return func
    
    
    def canReachLocation(self, toReach, placements, startingAccess, logic):
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
        if toReach in placements['force-junk']:
            return False
        
        # if using no logic, we don't have to check if it's reachable, we just assume it is.
        if logic == 'none':
            return True
        
        access = startingAccess.copy()
        accessAdded = True
        
        while accessAdded and self.threadActive:
            accessAdded = False
            for key in self.logic_defs:
                if self.threadActive:
                    if key not in access:
                        if self.checkAccess(key, access, logic):
                            access = self.addAccess(access, key)
                            accessAdded = True
                            # if this is the location we were looking for, we're done!
                            if key == toReach:
                                return True
                            
                            # if we're looking at an item or follower location, at the item it holds, if it has one
                            if (self.logic_defs[key]['type'] == 'item' or self.logic_defs[key]['type'] == 'follower') and placements[key] != None:
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
                                    accessAdded = True
                            if 'condition-heavy' in self.logic_defs[key] and not self.hasAccess(access, key+'[heavy]'):
                                if self.checkAccess(key+'[heavy]', access, logic):
                                    access = self.addAccess(access, key+'[heavy]')
                                    accessAdded = True
                else: break
            
        # If we get stuck and can't find any more locations to add, then we're stuck and can't reach toReach
        return False
    
    
    def verifySeashellsAttainable(self, placements, startingAccess, logic, goal):
        # Verify, given the starting access to items, whether it is possible to get up to [goal] seashells. This includes already placed shells (vanilla) or 
        locations = []
        access = startingAccess.copy()
        accessAdded = True
        
        # This check is run before random shells are placed, so any seashell come across during this runthrough
        # must have been forced vanilla. We don't want to count these directly in access.
        vanillaSeashells = 0
        
        while accessAdded and self.threadActive:
            accessAdded = False
            for key in self.logic_defs:
                if self.threadActive:
                    if key not in access:
                        if self.checkAccess(key, access, logic) or logic == 'none':
                            access = self.addAccess(access, key)
                            accessAdded = True
                            
                            # if we're looking at an item or follower location, at the item it holds, if it has one
                            if (self.logic_defs[key]['type'] == 'item' or self.logic_defs[key]['type'] == 'follower') and placements[key] != None:
                                if placements[key] == 'seashell':
                                    vanillaSeashells += 1
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
                                    accessAdded = True
                            if 'condition-heavy' in self.logic_defs[key] and not self.hasAccess(access, key+'[heavy]'):
                                if self.checkAccess(key+'[heavy]', access, logic):
                                    access = self.addAccess(access, key+'[heavy]')
                                    accessAdded = True
                else: break
        
        #print(len(locations), numRandom, access['seashell'], goal)
        #print(access)
        return len(locations) + vanillaSeashells >= goal
    
    
    
    def makeRandomizedPlacement(self, seed, logic, forceJunk, forceVanilla, settings, verbose=False):
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
        
        random.seed(seed)
        
        if not set(forceJunk).isdisjoint(forceVanilla):
            print('Warning! Some locations set as disabled are unrandomized. These locations will not actually be considered out of logic.')
            forceJunk = [l for l in forceJunk if l not in forceVanilla]
        
        # Ensure all excluded locations are actually location names
        forceJunk = [l for l in forceJunk if l in self.logic_defs and self.logic_defs[l]['type'] == 'item']
        
        # Make sure logic is a valid value, default to basic
        logic = logic.lower()
        if logic not in ['basic', 'advanced', 'glitched', 'none']:
            logic = 'basic'
        
        # Initialize the item and location lists, and the structures for tracking placements and access
        access = {}
        importantItems = []
        seashellItems = []
        goodItems = []
        junkItems = []
        dungeonItems = []
        locations = []
        placements = {}
        
        vanillaSeashells = 0 # Keep track of how many seashells were forced into their vanilla locations. This is important for ensuring there is enough room to place the random ones.
        
        placements['settings'] = self.settings
        placements['force-junk'] = forceJunk
        placements['force-vanilla'] = forceVanilla
        placements['indexes'] = {}
        
        indexesAvailable = {'seashell': list(range(50)), 'heart-piece': list(range(32)), 'heart-container': list(range(9)), 'bottle': list(range(3)), 'golden-leaf': list(range(5)), 'chamber-stone': [3, 4, 8, 10, 11, 12, 13, 20, 21, 22, 23, 24, 25, 26]}
        
        for key in self.logic_defs:
            if self.threadActive:
                if self.logic_defs[key]['type'] == 'item':
                    locations.append(key)
                    placements[key] = None
                    access = self.addAccess(access, self.logic_defs[key]['content']) # we're going to assume the player starts with everything, then slowly loses things as they get placed into the wild
            else: break
        
        # Add the self.settings into the access. This affects some logic like with fast trendy, free fishing, etc.
        self.settingsAccess = {setting: 1 for setting in self.settings if self.settings[setting] == True}
        access.update(self.settingsAccess)
        
        # For each type of item in the item pool, add its quantity to the item lists
        for key in self.item_defs:
            if self.threadActive:
                if self.item_defs[key]['type'] == 'important':
                    importantItems += [key] * self.item_defs[key]['quantity']
                elif self.item_defs[key]['type'] == 'seashell':
                    seashellItems += [key] * self.item_defs[key]['quantity']
                elif self.item_defs[key]['type'] == 'good':
                    goodItems += [key] * self.item_defs[key]['quantity']
                elif self.item_defs[key]['type'] == 'junk':
                    junkItems += [key] * self.item_defs[key]['quantity']
                else:
                    dungeonItems += [key] * self.item_defs[key]['quantity']
            else: break
        
        # Randomly place bow-wow and the rooster
        """followers = ['bow-wow', 'rooster']
        random.shuffle(followers)
        placements['moblin-cave'] = followers[0]
        placements['rooster-statue'] = followers[1]"""
        
        # Force the followers to be vanilla (for now)
        placements['moblin-cave'] = 'bow-wow'
        placements['rooster-statue'] = 'rooster'
        
        # Shuffle item and location lists
        random.shuffle(importantItems)
        random.shuffle(seashellItems)
        random.shuffle(goodItems)
        random.shuffle(junkItems)
        items = importantItems + seashellItems + goodItems + dungeonItems
        
        # Assign vanilla contents to forceVanilla locations
        for loc in forceVanilla:
            if self.threadActive:
                # If it's not a valid location name, or already used for forceJunk, just ignore it
                if loc not in locations:
                    continue
                
                # Place the defined vanilla content
                placements[loc] = self.logic_defs[loc]['content']

                try:
                    items.remove(self.logic_defs[loc]['content'])
                except ValueError:
                    junkItems.remove(self.logic_defs[loc]['content'])
                
                access = self.removeAccess(access, self.logic_defs[loc]['content'])
                locations.remove(loc)
                
                if self.logic_defs[loc]['content'] == 'seashell':
                    vanillaSeashells += 1
                
                # If the item is one that needs an index, assign it its vanilla item index and remove that from the available indexes
                if self.logic_defs[loc]['content'] in indexesAvailable:
                    placements['indexes'][loc] = self.logic_defs[loc]['index']
                    indexesAvailable[self.logic_defs[loc]['content']].remove(self.logic_defs[loc]['index'])
            else: break
                
        # Next, assign dungeon items into their own dungeons
        # Some may have been placed already because of forceVanilla so we need to factor that in
        dungeons = ['color-dungeon', 'tail-cave', 'bottle-grotto', 'key-cavern', 'angler-tunnel', 'catfish-maw', 'face-shrine', 'eagle-tower', 'turtle-rock']
        for i in range(len(dungeons)):
            if self.threadActive:
                itemPool = list(filter((lambda s: len(s) >= 2 and s[-2:] == f'D{i}'), items))
                locationPool = list(filter((lambda s: len(s) >= 2 and s[:2] == f'D{i}'), locations))
                random.shuffle(locationPool)
                
                # Keep track of where we placed items. this is necessary to undo placements if we get stuck
                placementTracker = []
                
                # Iterate through the dungeon items for that dungeon (inherently in order of nightmare key, small keys, stone beak, compass, map)
                while itemPool and self.threadActive:
                    item = itemPool[0]
                    if verbose: print(item+' -> ', end='')
                    firstLocationTried = locationPool[0]
                    
                    # Until we make a valid placement for this item
                    validPlacement = False
                    while not validPlacement and self.threadActive:
                        # Try placing the first item in the list in the first location
                        placements[locationPool[0]] = item
                        access = self.removeAccess(access, item)
                                                
                        # Check if it's reachable there
                        validPlacement = self.canReachLocation(locationPool[0], placements, access, logic)
                        if not validPlacement:
                            # If it's not, take back the item and shift that location to the end of the list
                            access = self.addAccess(access, item)
                            placements[locationPool[0]] = None
                            locationPool.append(locationPool.pop(0))
                            if locationPool[0] == firstLocationTried: 
                                # If we tried every location and none work, undo the previous placement and try putting it somewhere else. Also rerandomize the location list to ensure things aren't placed back in the same spots
                                undoLocation = placementTracker.pop(0)
                                locationPool.append(undoLocation)
                                locations.append(undoLocation)
                                random.shuffle(locationPool)
                                items.insert(0, placements[undoLocation])
                                itemPool.insert(0, placements[undoLocation])
                                access = self.addAccess(access, placements[undoLocation])
                                placements[undoLocation] = None
                                if verbose: print("can't place")
                                break
                    
                    if validPlacement and self.threadActive:
                        # After we successfully made a valid placement, remove the item and location from consideration
                        try:
                            items.remove(item)
                        except ValueError:
                            junkItems.remove(item)
                        itemPool.remove(item)
                        if verbose: print(locationPool[0])
                        locations.remove(locationPool[0])
                        placementTracker.append(locationPool.pop(0))
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)

            else: break
        
        # Shuffle remaining locations
        random.shuffle(locations)
        
        # Place the zol traps and master stalfos note. These HAVE to go in chests so we need to do them first
        toPlace = list(filter(lambda s: s in self.forceChests, items))
        chests = list(filter(lambda s: self.logic_defs[s]['subtype'] == 'chest', locations))
        for item in toPlace:
            if self.threadActive:
                if verbose: print(item+' -> ', end='')
                chest = chests.pop(0)
                placements[chest] = item
                try:
                    items.remove(item)
                except:
                    junkItems.remove(item)
                locations.remove(chest)
                if verbose: print(chests[0])
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
            else: break

        
        # Next, place an item on Tarin. Since Tarin is the only check available with no items, he has to have something out of a certain subset of items
        # Only do this if Tarin has no item placed, i.e. not forced to be vanilla
        if placements['tarin'] == None and self.threadActive:
            success = False
            while not success and self.threadActive:
                placements['tarin'] = items[0]
                success = self.canReachLocation('can-shop', placements, self.settingsAccess, logic) or self.canReachLocation('tail-cave', placements, self.settingsAccess, logic) or self.canReachLocation('beach', placements, self.settingsAccess, logic)
                                
                if not success:
                    items.insert(items.index('seashell'), items[0])
                    items.pop(0)
            
            if verbose: print(items[0]+' -> tarin')
            access = self.removeAccess(access, items.pop(0))
            locations.remove('tarin')

            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        
        # Keep track of where we placed items. this is necessary to undo placements if we get stuck
        placementTracker = []
        
        # Do a very similar process for all other nonjunk items
        while items and locations and self.threadActive:
            item = items[0]
            if verbose: print(item+' -> ', end='')
            firstLocationTried = locations[0]
            
            # Until we make a valid placement for this item
            validPlacement = False
            while not validPlacement and self.threadActive:
                # Try placing the first item in the list in the first location
                placements[locations[0]] = item
                access = self.removeAccess(access, item)
                
                # Check for item type restrictions, i.e. songs can't be standing items
                if (item in ['song-ballad', 'song-mambo', 'song-soul', 'bomb-capacity', 'arrow-capacity', 'powder-capacity', 'red-tunic', 'blue-tunic']) and (self.logic_defs[locations[0]]['subtype'] in ['standing', 'hidden', 'dig', 'drop', 'boss', 'underwater', 'shop']):
                    validPlacement = False
                elif (item in self.forceChests) and self.logic_defs[locations[0]]['subtype'] != 'chest':
                    validPlacement = False
                elif self.item_defs[item]['type'] == 'important' or self.item_defs[item]['type'] == 'seashell':
                    # Check if it's reachable there. We only need to do this check for important items! good and junk items are never needed in logic
                    validPlacement = self.canReachLocation(locations[0], placements, access, logic)
                else:
                    validPlacement = True
                
                # If it wasn't valid, put it back and shift the first location to the end of the list
                if not validPlacement:
                    access = self.addAccess(access, item)
                    placements[locations[0]] = None
                    locations.append(locations.pop(0))
                    if locations[0] == firstLocationTried: 
                        # If we tried every location and none work, undo the previous placement and try putting it somewhere else
                        undoLocation = placementTracker.pop(0)
                        locations.append(undoLocation)
                        random.shuffle(locations)
                        items.insert(0, placements[undoLocation])
                        access = self.addAccess(access, placements[undoLocation])
                        placements[undoLocation] = None
                        if verbose: print("can't place")
                        break
            
            if validPlacement and self.threadActive:
                # After we successfully made a valid placement, remove the item and location from consideration
                if verbose: print(locations[0])
                
                placedItem = items.pop(0)
                # If the item is one that needs an index, give it the next available one
                if placedItem in indexesAvailable:
                    placements['indexes'][locations[0]] = indexesAvailable[placedItem].pop(0)
                
                placementTracker.append(locations.pop(0))
                
                # If we placed the last important item (so that afterward we start placing seashells), we want to ensure there's enough available locations to place a number of seashells required.
                # i.e., are there 40 locations reachable without getting the 40 and 50 rewards? If not, we haven't made a valid placement, so we have to go back and undo things until this is resolved.
                if item != 'seashell' and len(items) > 0 and items[0] == 'seashell':
                    if not ((self.verifySeashellsAttainable(placements, self.settingsAccess, logic, 5)) 
                    and (self.verifySeashellsAttainable(placements, self.settingsAccess, logic, 15))
                    and (self.verifySeashellsAttainable(placements, self.settingsAccess, logic, 30))
                    and (self.verifySeashellsAttainable(placements, self.settingsAccess, logic, 40))
                    and (self.verifySeashellsAttainable(placements, self.settingsAccess, logic, 50))):
                        if verbose: 
                            print('no room for shells')
                            #print(placements)
                        undoLocation = placementTracker.pop(0)
                        locations.append(undoLocation)
                        random.shuffle(locations)
                        items.insert(0, placements[undoLocation])
                        access = self.addAccess(access, placements[undoLocation])
                        placements[undoLocation] = None
                
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        # reset tracker for junk items and shuffle junk
        placementTracker = []

        while junkItems and locations and self.threadActive:
            item = junkItems[0]
            if verbose: print(item+' -> ', end='')
            firstLocationTried = locations[0]
            
            # Until we make a valid placement for this item
            validPlacement = False
            while not validPlacement and self.threadActive:
                # Try placing the first item in the list in the first location
                placements[locations[0]] = item
                access = self.removeAccess(access, item)

                if (item in self.forceChests) and self.logic_defs[locations[0]]['subtype'] != 'chest':
                    validPlacement = False
                else:
                    validPlacement = True
                
                # If it wasn't valid, put it back and shift the first location to the end of the list
                if not validPlacement:
                    access = self.addAccess(access, item)
                    placements[locations[0]] = None
                    locations.append(locations.pop(0))
                    if locations[0] == firstLocationTried: 
                        # If we tried every location and none work, undo the previous placement and try putting it somewhere else
                        undoLocation = placementTracker.pop(0)
                        locations.append(undoLocation)
                        random.shuffle(locations)
                        junkItems.insert(0, placements[undoLocation])
                        access = self.addAccess(access, placements[undoLocation])
                        placements[undoLocation] = None
                        if verbose: print("can't place")
                        break
                
                if validPlacement and self.threadActive:
                    # After we successfully made a valid placement, remove the item and location from consideration
                    if verbose: print(locations[0])
                    
                    placedItem = junkItems.pop(0)
                    # If the item is one that needs an index, give it the next available one
                    if placedItem in indexesAvailable:
                        placements['indexes'][locations[0]] = indexesAvailable[placedItem].pop(0)
                
                    placementTracker.append(locations.pop(0))

            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        if self.threadActive and placements['settings']['create-spoiler']:
            spoiler.generateSpoilerLog(placements, self.logic_defs, self.out_dir, self.seed)
        
        return placements
