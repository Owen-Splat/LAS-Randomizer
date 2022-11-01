from Randomizers import data
import Tools.oead_tools as oead_tools
import oead
import copy



def makeNpcChanges(npcSheet, placements):
    """Makes lots of changes to the Npc datasheet to make this randomizer work, 
    ranging from event triggers to layout conditions to even graphics changes. 
    Also makes the shell sensor go off if the Npc holds a seashell"""
    
    for npc in npcSheet['values']:
        if npc['symbol'] == 'NpcMadBatter':
            npc['eventTriggers'][0]['entryPoint'] = '$2'
            npc['layoutConditions'].pop(1)
        
        # if npc['symbol'] == 'ItemGoldenLeaf':
        #     npc['graphics']['path'] = '$1'
        #     npc['graphics']['model'] = '$2'
        #     npc['eventTriggers'][0]['additionalConditions'][0] = {'category': 8, 'parameter': '!1'}
        #     npc['eventTriggers'][1]['entryPoint'] = '$3'

        #     cons = oead.gsheet.StructArray()
        #     cons.append({'category': 4, 'parameter': 'Lv4_04E'})
        #     cons.append({'category': 8, 'parameter': '!1'})
        #     npc['eventTriggers'].append({'condition': 14, 'additionalConditions': cons, 'entryPoint': 'Lv4_04E_pop'})
        
        if npc['symbol'] == 'ItemSmallKey':
            npc['graphics']['path'] = '$1'
            npc['graphics']['model'] = '$2'
            npc['eventTriggers'][2]['entryPoint'] = '$3'
        
        if npc['symbol'] == 'ItemYoshiDoll': # This is for Ocarina and Instruments since I still want the player to press A to get them
            npc['graphics']['path'] = '$0'
            npc['graphics']['model'] = '$1'
            npc['eventInfo'] = {'eventAsset': 'SinkingSword.bfevfl', 'actorName': 'SinkingSword'}
            npc['eventTriggers'][0]['entryPoint'] = '$2'
            npc['doAction'] = {'type': 7, 'yOffset': 0.0, 'xzDistance': 1.2999999523162842, 'yDistance': 1.7999999523162842, 'playerAngleRange': 45.0, 'reactionAngleRange': 180.0}
            npc['layoutConditions'].append({'category': 1, 'parameter': '$3', 'layoutID': -1})
            npc['collision']['traits'] = ''
            npc['collision']['isStatic'] = True
            npc['collision']['filter'] = 5
        
        if npc['symbol'] == 'ItemClothesGreen':
            npc['graphics']['path'] = 'ItemSmallKey.bfres'
            npc['graphics']['model'] = 'SmallKey'
        
        if npc['symbol'] == 'ItemClothesRed':
            npc['graphics']['path'] = 'ItemYoshiDoll.bfres'
            npc['graphics']['model'] = 'YoshiDoll'
        

        # ### make some trade quest items properly show in the cutscenes before obtaining them
        # if npc['symbol'] == 'ItemHoneycomb':
        #     npc['graphics']['path'] = '$0'
        #     npc['graphics']['model'] = '$1'


        if npc['symbol'] == 'ObjClothBag':
            npc['layoutConditions'][1] = {'category': 1, 'parameter': 'TradePineappleGet', 'layoutID': 0}

        if npc['symbol'] == 'NpcGrandmaUlrira':
            npc['layoutConditions'][1] = {'category': 9, 'parameter': 'true', 'layoutID': 4}
        
        if npc['symbol'] == 'ObjSinkingSword':
            npc['graphics']['path'] = '$0'
            npc['graphics']['model'] = '$1'
            npc['graphics']['waterChannel']['limitDepth'] = 0.5 # idk what this does but probably helps see the item?
            npc['eventTriggers'][0]['condition'] = 0
            npc['eventTriggers'][0]['entryPoint'] = '$2'
            npc['doAction'] = {'type': 0, 'yOffset': 0.0, 'xzDistance': 0.0, 'yDistance': 0.0, 'playerAngleRange': 0.0, 'reactionAngleRange': 0.0}
            npc['layoutConditions'][0]['parameter'] = '$3'
            npc['collision']['traits'] = 'HeartPiece'
            npc['collision']['isStatic'] = False
            npc['collision']['filter'] = 7
            npc['collision']['offset']['y'] = 0.25
        
        if npc['symbol'] == 'ObjRoosterBones':
            npc['layoutConditions'].pop(0)
        
        if npc['symbol'] == 'ObjTelephone': # since telephones swap tunics, make it so the Fairy Queen is talking
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
        if npc['symbol'] == 'ItemFeatherBomb' and placements['settings']['shuffle-bombs']:
            npc['layoutConditions'].append({'category': 1, 'parameter': f'!{data.BOMBS_FOUND_FLAG}', 'layoutID': -1})
        

        if npc['symbol'] == 'NpcBowWow':
            npc['layoutConditions'][2] = {'category': 3, 'parameter': 'BowWow', 'layoutID': -1}
        
        if npc['symbol'] == 'NpcMadamMeowMeow':
            npc['layoutConditions'][2] = {'category': 1, 'parameter': 'BowWowJoin', 'layoutID': 3}
            npc['layoutConditions'].pop(1)
        
        if npc['symbol'] == 'NpcChorusFrog':
            npc['layoutConditions'].pop(0)
        
        if npc['symbol'] == 'NpcKiki' and placements['settings']['open-bridge']:
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



# def makeNewNpcs(npc_sheet):
#     """add new npcs so that we can properly show item models for items that normally cannot be standing items
#     unfortunately will not by itself make them show properly when obtaining the item, only the freestanding model"""

#     new_npc = copy.deepcopy(DUMMY_NPC)
#     new_npc['symbol'] = 'PatchHoneycomb'
#     new_npc['graphics']['path'] = 'ItemHoneycomb.bfres'
#     new_npc['graphics']['model'] = 'Honeycomb'
#     npc_sheet['values'].append(oead_tools.dictToStruct(new_npc))

#     mambo = copy.deepcopy(DUMMY_NPC)
#     mambo['symbol'] = 'ItemMambo'
#     mambo['graphics']['path'] = 'ItemMambo.bfres'
#     npc_sheet['values'].append(oead_tools.dictToStruct(mambo))

#     soul = copy.deepcopy(DUMMY_NPC)
#     soul['symbol'] = 'ItemSoul'
#     soul['graphics']['path'] = 'ItemSoul.bfres'
#     npc_sheet['values'].append(oead_tools.dictToStruct(soul))

#     bombBag = copy.deepcopy(DUMMY_NPC)
#     bombBag['symbol'] = 'ObjBombBag'
#     bombBag['graphics']['path'] = 'ObjBombBag.bfres'
#     bombBag['graphics']['model'] = 'BombBag'
#     npc_sheet['values'].append(oead_tools.dictToStruct(bombBag))

#     arrowBag = copy.deepcopy(DUMMY_NPC)
#     arrowBag['symbol'] = 'ObjArrowBag'
#     arrowBag['graphics']['path'] = 'ObjArrowBag.bfres'
#     arrowBag['graphics']['model'] = 'ArrowBag'
#     npc_sheet['values'].append(oead_tools.dictToStruct(arrowBag))




# DUMMY_NPC = {
#     'symbol': 'ItemOcarina',
#     'graphics': {
#         'path': 'ItemOcarina.bfres',
#         'model': 'Ocarina',
#         'animations': {'idle': '', 'talk': '', 'walk': '', 'run': ''},
#         'rootAnimEnabled': False,
#         'animSettings': [
#             {'name': 'wait', 'blendTime': 4, 'lipsync': 0, 'cull': 2},
#             {'name': 'talk', 'blendTime': 4, 'lipsync': 1, 'cull': 2},
#             {'name': 'walk', 'blendTime': 4, 'lipsync': 0, 'cull': 2},
#             {'name': 'run', 'blendTime': 4, 'lipsync': 0, 'cull': 2}
#         ],
#         'drsb': 'ItemOcarina.drsb',
#         'waterChannel': {'enable': True, 'offsetY': 0.0, 'limitDepth': 0.5},
#         'facial': '',
#         'interestIK': '',
#         'turn': {'enable': False, 'autoTurn': False, 'threshold': 30.0, 'reactionTime': 1.0, 'duration': 0.25},
#         'cull': 1
#     },
#     'eventInfo': {'eventAsset': 'ItemCommon.bfevfl', 'actorName': 'Item'},
#     'eventTriggers': [{'condition': 2, 'additionalConditions': [], 'entryPoint': 'Ocarina'}],
#     'doAction': {'type': 7, 'yOffset': 0.0, 'xzDistance': 1.5, 'yDistance': 1.7999999523162842,
#         'playerAngleRange': 45.0, 'reactionAngleRange': 180.0},
#     'talk': {'personalSpace': 1.5, 'talkerLabel': ''},
#     'actorArgs': {'layoutID': 0, 'identifier': 0},
#     'popConditions': {
#         'conditions': [],
#         'depopEnable': False
#     },
#     'layoutConditions': [],
#     'lookAtOffsetY': 0.0,
#     'behavior': {
#         'type': 2,
#         'parameters': ['0', '0', '0', '0', '0']
#     },
#     'movement': {
#         'walk': {'moveSpeed': 1.5, 'turnSpeed': 45.0},
#         'run': {'moveSpeed': 2.5, 'turnSpeed': 120.0}
#     },
#     'collision': {
#         'shape': 3,
#         'traits': 'Ocarina',
#         'component': 1,
#         'isStatic': False,
#         'filter': 5,
#         'material': 0,
#         'groundCheck': True,
#         'offset': {'x': 0.0, 'y': 0.25, 'z': 0.0},
#         'rotation': {'x': 0.0, 'y': 0.0, 'z': 0.0},
#         'parameters': [1.7999999523162842, 0.5, 1.7999999523162842]
#     },
#     'damageCollision': {'enable': False, 'sizeDiff': 0.0},
#     'ocarina': {'enable': False, 'distance': 0.0},
#     'shellSensor': [],
#     'attribute': 0
# }
