import Tools.oead_tools as oead_tools
from Randomizers import data



def makeNpcChanges(npcSheet, placements):
    for npc in npcSheet['values']:
        if npc['symbol'] == 'NpcMadBatter':
            npc['eventTriggers'][0]['entryPoint'] = '$2'
            npc['layoutConditions'].pop(1)
        
        if npc['symbol'] == 'ItemSmallKey':
            npc['graphics']['path'] = '$1'
            npc['graphics']['model'] = '$2'
            npc['eventTriggers'][2]['entryPoint'] = '$3'
        
        if npc['symbol'] == 'ItemYoshiDoll':
            npc['graphics']['path'] = '$0'
            npc['graphics']['model'] = '$1'
            npc['eventInfo'] = {'eventAsset': 'SinkingSword.bfevfl', 'actorName': 'SinkingSword'}
            # npc['eventTriggers'][0]['condition'] = 0
            npc['eventTriggers'][0]['entryPoint'] = '$2'
            npc['doAction'] = {'type': 7, 'yOffset': 0.0, 'xzDistance': 1.2999999523162842, 'yDistance': 1.7999999523162842, 'playerAngleRange': 45.0, 'reactionAngleRange': 180.0}
            npc['layoutConditions'].append({'category': 1, 'parameter': '$3', 'layoutID': -1})
            # npc['behavior'] = oead_tools.createBehavior(type=0, datas=None)
            npc['collision']['traits'] = ''
            npc['collision']['isStatic'] = True
            # npc['collision']['offset'] = {'x': 0.0, 'y': 0.0, 'z': 0.0}
            npc['collision']['filter'] = 5

        
        if npc['symbol'] == 'ItemClothesGreen':
            npc['graphics']['path'] = 'ItemSmallKey.bfres'
            npc['graphics']['model'] = 'SmallKey'
        
        if npc['symbol'] == 'ItemClothesRed':
            npc['graphics']['path'] = 'ItemYoshiDoll.bfres'
            npc['graphics']['model'] = 'YoshiDoll'
            
        if npc['symbol'] == 'ObjClothBag':
            npc['layoutConditions'][1] = {'category': 1, 'parameter': 'TradePineappleGet', 'layoutID': 0}

        if npc['symbol'] == 'NpcGrandmaUlrira':
            npc['layoutConditions'][1] = {'category': 9, 'parameter': 'true', 'layoutID': 4}
        
        if npc['symbol'] == 'ObjSinkingSword':
            npc['graphics']['path'] = '$0'
            npc['graphics']['model'] = '$1'
            npc['eventTriggers'][0]['condition'] = 0
            npc['eventTriggers'][0]['entryPoint'] = '$2'
            npc['eventTriggers'].append(oead_tools.createEventTrigger(2, [(2, '$3')], '$2')) # require flippers for sunken ones
            npc['eventTriggers'].append(oead_tools.createEventTrigger(2, [(9, '$4')], '$2')) # true/false
            npc['layoutConditions'][0]['parameter'] = '$5'
            npc['layoutConditions'][0]['layoutID'] = 1
            # npc['layoutConditions'].append({'category': 2, 'parameter': '$6', 'layoutID': -1})
        
        if npc['symbol'] == 'ObjRoosterBones':
            npc['layoutConditions'].pop(0)
        
        if npc['symbol'] == 'ObjTelephone':
            npc['talk'] = {'personalSpace': 1.5, 'talkerLabel': 'NpcFairyQueen'}
        

        # change dungeon lock statues to be able to be opened from any direction
        if npc['symbol'] == 'ObjTailLockStatue':
            npc['doAction'] = {'type': 2, 'yOffset': 0.0, 'xzDistance': 1.7999999523162842, 'yDistance': 1.7999999523162842, 'playerAngleRange': 45.0, 'reactionAngleRange': 180.0}

        if npc['symbol'] == 'ObjSlimeLockStatue':
            npc['doAction'] = {'type': 2, 'yOffset': 0.0, 'xzDistance': 1.7999999523162842, 'yDistance': 1.7999999523162842, 'playerAngleRange': 45.0, 'reactionAngleRange': 180.0}

        if npc['symbol'] == 'ObjAnglersKeyhole':
            npc['doAction'] = {'type': 2, 'yOffset': 0.0, 'xzDistance': 1.7999999523162842, 'yDistance': 1.7999999523162842, 'playerAngleRange': 45.0, 'reactionAngleRange': 180.0}

        if npc['symbol'] == 'ObjFaceLockStatue':
            npc['doAction'] = {'type': 2, 'yOffset': 0.0, 'xzDistance': 1.7999999523162842, 'yDistance': 1.7999999523162842, 'playerAngleRange': 45.0, 'reactionAngleRange': 180.0}

        if npc['symbol'] == 'ObjEaglesLockRock':
            npc['doAction'] = {'type': 2, 'yOffset': 0.0, 'xzDistance': 1.7999999523162842, 'yDistance': 1.7999999523162842, 'playerAngleRange': 45.0, 'reactionAngleRange': 180.0}


        # make the flying bomb refills not appear until you find your bombs
        if npc['symbol'] == 'ItemFeatherBomb':
            if placements['settings']['shuffle-bombs']:
                npc['layoutConditions'].append({'category': 1, 'parameter': f'!{data.BOMBS_FOUND_FLAG}', 'layoutID': -1})
        

        if npc['symbol'] == 'NpcBowWow':
            npc['layoutConditions'][2] = {'category': 3, 'parameter': 'BowWow', 'layoutID': -1}
        
        if npc['symbol'] == 'NpcMadamMeowMeow':
            npc['layoutConditions'][2] = {'category': 1, 'parameter': 'BowWowJoin', 'layoutID': 3}
            npc['layoutConditions'].pop(1)
        
        if npc['symbol'] == 'NpcChorusFrog':
            npc['layoutConditions'].pop(0)
        
        if npc['symbol'] == 'NpcKiki':
            npc['layoutConditions'][0] = {'category': 1, 'parameter': 'KikiGone', 'layoutID': -1}
        
        if npc['symbol'] == 'NpcPapahl':
            npc['layoutConditions'][1] = {'category': 1, 'parameter': 'TradePineappleGet', 'layoutID': 2}


        # Adjustments for NPCs that can have seashells, to make the sensor work properly
        if npc['symbol'] == 'NpcChristine':
            npc['shellSensor'].pop()

            if placements['christine-trade'] == 'seashell':
                npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['christine-trade']}"})

            if placements['christine-grateful'] == 'seashell':
                npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['christine-grateful']}"})
        
        if npc['symbol'] == 'NpcTarin':
            npc['eventTriggers'][5]['additionalConditions'][0] = {'category': 1, 'parameter': '!ShieldGet'} # Make Tarin detain based on talking to him, not having Shield
            if placements['tarin'] == 'seashell':
                npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['tarin']}"})
            
            npc['eventTriggers'][1]['additionalConditions'][0] = {'category': 4, 'parameter': '3'} # Only the instance of Tarin-Ukuku should trigger the trade event
            npc['shellSensor'].append({'category': 4, 'parameter': '3'}) # Only the instance of Tarin-Ukuku should ring the sensor
            if placements['tarin-ukuku'] == 'seashell':
                npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['tarin-ukuku']}"})
            
            npc['layoutConditions'][2] = {'category': 1, 'parameter': 'HoneycombDrop', 'layoutID': -1}
            npc['layoutConditions'][4] = {'category': 1, 'parameter': 'TradeStickGet', 'layoutID': 3} # Make Tarin-ukuku appear when you get the stick
        
        if npc['symbol'] == 'NpcPapahl':
            if placements['papahl'] == 'seashell':
                npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['papahl']}"})
        

        if npc['symbol'] == 'NpcMarin':
            npc['shellSensor'].append({'category': 4, 'parameter': '2'}) # Only the instance of Marin in Mabe should ring the sensor
            if placements['marin'] == 'seashell':
                npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['marin']}"})
        if npc['symbol'] == 'NpcSecretZora':
            npc['shellSensor'].pop()
            if placements['invisible-zora'] == 'seashell':
                npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['invisible-zora']}"})
        if npc['symbol'] == 'NpcGoriya':
            if placements['goriya-trader'] == 'seashell':
                npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['goriya-trader']}"})
        if npc['symbol'] == 'ObjGhostsGrave':
            if placements['ghost-reward'] == 'seashell':
                npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['ghost-reward']}"})
        if npc['symbol'] == 'NpcWalrus':
            npc['shellSensor'].pop()
            if placements['walrus'] == 'seashell':
                npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['walrus']}"})
        if npc['symbol'] == 'NpcFairyQueen':
            if placements['D0-fairy-1'] == 'seashell':
                npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['D0-fairy-1']}"})
            if placements['D0-fairy-2'] == 'seashell':
                npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['D0-fairy-2']}"})
        if npc['symbol'] == 'NpcManboTamegoro':
            if placements['manbo'] == 'seashell':
                npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['manbo']}"})
        if npc['symbol'] == 'NpcMamu':
            npc['layoutConditions'].pop(0) # removes the frog's song layout condition so he's always there
            if placements['mamu'] == 'seashell':
                npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['mamu']}"})
        if npc['symbol'] == 'NpcGameShopOwner':
            if placements['trendy-prize-final'] == 'seashell':
                npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['trendy-prize-final']}"})
        if npc['symbol'] == 'NpcDanpei':
            npc['shellSensor'].append({'category': 9, 'parameter': '!DampeShellsComplete'})
        if npc['symbol'] == 'NpcRaftShopMan':
            npc['shellSensor'].append({'category': 9, 'parameter': '!RapidsShellsComplete'})
        if npc['symbol'] == 'NpcFisherman':
            npc['shellSensor'].append({'category': 9, 'parameter': '!FishingShellsComplete'})
        if npc['symbol'] == 'NpcShellMansionMaster':
            npc['shellSensor'].append({'category': 9, 'parameter': '!MansionShellsComplete'})
