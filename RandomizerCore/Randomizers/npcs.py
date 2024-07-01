from RandomizerCore.Randomizers import data
import RandomizerCore.Tools.oead_tools as oead_tools
import copy



def makeNpcChanges(npc, placements, settings):
    """Makes lots of changes to the Npc datasheet to make this randomizer work, 
    ranging from event triggers to layout conditions to even graphics changes. 
    Also makes the shell sensor go off if the Npc holds a seashell"""
    
    if npc['symbol'] == 'NpcMadBatter':
        npc['eventTriggers'][0]['entryPoint'] = '$2'
        del npc['layoutConditions'][1]
        return
    
    if npc['symbol'] == 'ItemGoldenLeaf': # Makes it so golden leaf actors will not spawn, and also removes event just in case
        npc['eventTriggers'] = []
        del npc['layoutConditions'][0]
        del npc['layoutConditions'][0]
        del npc['layoutConditions'][0]
        return
    
    if npc['symbol'] == 'ItemSmallKey':
        npc['graphics']['path'] = '$1'
        npc['graphics']['model'] = '$2'
        npc['eventTriggers'][2]['entryPoint'] = '$3'
        npc['shellSensor'].append({'category': 9, 'parameter': '$4'}) # make specific smallkey actors trigger the shell sensor
        return
    
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
        # npc['collision']['offset']['y'] = 0.5
        npc['shellSensor'].append({'category': 9, 'parameter': '$4'}) # make specific yoshidoll actors trigger the shell sensor
        return
    
    if npc['symbol'] == 'ItemHoneycomb': # Make the Honeycomb object ring the sensor instead of Tarin
        npc['graphics']['path'] = '$0'
        npc['graphics']['model'] = '$1'
        if placements['tarin-ukuku'] == 'seashell':
            npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['tarin-ukuku']}"})
        return
    
    if npc['symbol'] == 'ItemStick': # Change the model of the item that Kiki drops
        npc['graphics']['path'] = '$1'
        npc['graphics']['model'] = '$2'
    
    if npc['symbol'] == 'ObjClothBag': # Make it so Papahl's bag appears with him when you get the Pineapple
        npc['layoutConditions'][1] = {'category': 1, 'parameter': 'TradePineappleGet', 'layoutID': 0}
        return

    if npc['symbol'] == 'NpcGrandmaUlrira':
        npc['layoutConditions'][1] = {'category': 9, 'parameter': 'true', 'layoutID': 4}
        return
    
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
        npc['shellSensor'].append({'category': 9, 'parameter': '$4'}) # make specific sinkingsword actors trigger the shell sensor
        return
    
    if npc['symbol'] == 'ObjRoosterBones':
        del npc['layoutConditions'][0]
        return
    
    if npc['symbol'] == 'ObjTelephone': # since telephones swap tunics, make it so the Fairy Queen is talking
        npc['talk'] = {'personalSpace': 1.5, 'talkerLabel': 'NpcFairyQueen'}
        return
    
    # make the bomb refills not appear until you find your bombs
    if npc['symbol'] == 'ItemBomb' and settings['shuffle-bombs']:
        npc['layoutConditions'].append({'category': 1, 'parameter': f'!{data.BOMBS_FOUND_FLAG}', 'layoutID': -1})
        return
    if npc['symbol'] == 'ItemFeatherBomb' and settings['shuffle-bombs']:
        npc['layoutConditions'].append({'category': 1, 'parameter': f'!{data.BOMBS_FOUND_FLAG}', 'layoutID': -1})
        return
    
    # make the powder refills not appear until you find your powder
    if npc['symbol'] == 'ItemMagicPowder' and settings['shuffle-powder']:
        npc['layoutConditions'].append({'category': 1, 'parameter': '!GetMagicPowder', 'layoutID': -1})
        return
    if npc['symbol'] == 'ItemFeatherMagicPowder' and settings['shuffle-powder']:
        npc['layoutConditions'].append({'category': 1, 'parameter': '!GetMagicPowder', 'layoutID': -1})
        return
    
    # Adjustments to NPC layouts and shell sensor trigger conditions
    if npc['symbol'] == 'NpcBowWow':
        npc['layoutConditions'][2] = {'category': 3, 'parameter': 'BowWow', 'layoutID': -1}
        return

    if npc['symbol'] == 'NpcMadamMeowMeow':
        npc['layoutConditions'][2] = {'category': 1, 'parameter': 'BowWowJoin', 'layoutID': 3}
        del npc['layoutConditions'][1]
        return
    
    if npc['symbol'] == 'NpcChorusFrog':
        del npc['layoutConditions'][0]
        return
    
    if npc['symbol'] == 'NpcKiki' and settings['open-bridge']:
        npc['layoutConditions'][0] = {'category': 1, 'parameter': 'KikiGone', 'layoutID': -1}
        return
    
    if npc['symbol'] == 'NpcChristine':
        del npc['shellSensor'][0]
        if placements['christine-trade'] == 'seashell':
            npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['christine-trade']}"})
        if placements['christine-grateful'] == 'seashell':
            npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['christine-grateful']}"})
        return
    
    if npc['symbol'] == 'NpcTarin':
        npc['eventTriggers'][5]['additionalConditions'][0] = {'category': 1, 'parameter': '!ShieldGet'} # Make Tarin detain based on talking to him, not having Shield
        npc['eventTriggers'][1]['additionalConditions'][0] = {'category': 4, 'parameter': '3'} # Only the instance of Tarin-Ukuku should trigger the trade event
        npc['layoutConditions'][2] = {'category': 1, 'parameter': 'HoneycombDrop', 'layoutID': -1}
        npc['layoutConditions'][4] = {'category': 1, 'parameter': 'TradeStickGet', 'layoutID': 3} # Make Tarin-ukuku appear when you get the stick
        return
    
    if npc['symbol'] == 'NpcPapahl':
        npc['layoutConditions'][1] = {'category': 1, 'parameter': 'TradePineappleGet', 'layoutID': 2}
        if placements['papahl'] == 'seashell':
            npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['papahl']}"})
        return

    if npc['symbol'] == 'NpcMarin':
        if placements['marin'] == 'seashell':
            npc['shellSensor'].append({'category': 4, 'parameter': '2'}) # Only the instance of Marin in Mabe should ring the sensor
            npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['marin']}"})
        return

    if npc['symbol'] == 'NpcSecretZora':
        del npc['shellSensor'][0]
        if placements['invisible-zora'] == 'seashell':
            npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['invisible-zora']}"})
        return
    
    if npc['symbol'] == 'NpcGoriya':
        if placements['goriya-trader'] == 'seashell':
            npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['goriya-trader']}"})
        return

    if npc['symbol'] == 'ObjGhostsGrave':
        if placements['ghost-reward'] == 'seashell':
            npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['ghost-reward']}"})
        return

    if npc['symbol'] == 'NpcWalrus':
        del npc['shellSensor'][0]
        if placements['walrus'] == 'seashell':
            npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['walrus']}"})
        return

    if npc['symbol'] == 'NpcFairyQueen':
        if placements['D0-fairy-1'] == 'seashell':
            npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['D0-fairy-1']}"})
        if placements['D0-fairy-2'] == 'seashell':
            npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['D0-fairy-2']}"})
        return

    if npc['symbol'] == 'NpcManboTamegoro':
        if placements['manbo'] == 'seashell':
            npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['manbo']}"})
        return

    if npc['symbol'] == 'NpcMamu':
        del npc['layoutConditions'][0] # removes the frog's song layout condition so he's always there
        if placements['mamu'] == 'seashell':
            npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['mamu']}"})
        return

    if npc['symbol'] == 'NpcGameShopOwner':
        if placements['trendy-prize-final'] == 'seashell':
            npc['shellSensor'].append({'category': 2, 'parameter': f"!Seashell:{placements['indexes']['trendy-prize-final']}"})
        return

    if npc['symbol'] == 'NpcDanpei':
        npc['shellSensor'].append({'category': 9, 'parameter': '!DampeShellsComplete'})
        return

    if npc['symbol'] == 'NpcRaftShopMan':
        npc['shellSensor'].append({'category': 9, 'parameter': '!RapidsShellsComplete'})
        return

    if npc['symbol'] == 'NpcFisherman':
        npc['shellSensor'].append({'category': 9, 'parameter': '!FishingShellsComplete'})
        return

    if npc['symbol'] == 'NpcShellMansionMaster':
        npc['shellSensor'].append({'category': 9, 'parameter': '!MansionShellsComplete'})
        return

    # Chest matching texture feature
    if npc['symbol'] == 'ObjTreasureBox' and settings['chest-aspect'] == 'camc':
        npc['graphics']['path'] = '$6'
        npc['graphics']['model'] = '$7'
        return

def makeNewNpcs(npc_sheet, placements, item_defs):
    """We change the graphics for some items, so create new npcs to show the correct model when obtaining them"""

    dummy = copy.deepcopy(DUMMY_NPC)
    dummy['symbol'] = 'PatchSmallKey'
    dummy['graphics']['path'] = 'ItemSmallKey.bfres'
    dummy['graphics']['model'] = 'SmallKey'
    npc_sheet['values'].append(oead_tools.dictToStruct(dummy))

    dummy['symbol'] = 'PatchYoshiDoll'
    dummy['graphics']['path'] = 'ItemYoshiDoll.bfres'
    dummy['graphics']['model'] = 'YoshiDoll'
    npc_sheet['values'].append(oead_tools.dictToStruct(dummy))

    dummy['symbol'] = 'PatchHoneycomb'
    dummy['graphics']['path'] = 'ItemHoneycomb.bfres'
    dummy['graphics']['model'] = 'Honeycomb'
    npc_sheet['values'].append(oead_tools.dictToStruct(dummy))

    dummy['symbol'] = 'PatchStick'
    dummy['graphics']['path'] = 'ItemStick.bfres'
    dummy['graphics']['model'] = 'Stick'
    npc_sheet['values'].append(oead_tools.dictToStruct(dummy))

    item = placements['syrup']
    dummy['symbol'] = 'SyrupPowder'
    dummy['graphics']['path'] = item_defs[item]['model-path']
    dummy['graphics']['model'] = item_defs[item]['model-name']
    npc_sheet['values'].append(oead_tools.dictToStruct(dummy))

    item = placements['walrus']
    dummy['symbol'] = 'WalrusShell'
    dummy['graphics']['path'] = item_defs[item]['model-path']
    dummy['graphics']['model'] = item_defs[item]['model-name']
    npc_sheet['values'].append(oead_tools.dictToStruct(dummy))

    item = placements['bay-fisherman']
    dummy['symbol'] = 'FishNecklace'
    dummy['graphics']['path'] = item_defs[item]['model-path']
    dummy['graphics']['model'] = item_defs[item]['model-name']
    npc_sheet['values'].append(oead_tools.dictToStruct(dummy))

    # bombBag['symbol'] = 'ObjBombBag'
    # bombBag['graphics']['path'] = 'ObjBombBag.bfres'
    # bombBag['graphics']['model'] = 'BombBag'
    # npc_sheet['values'].append(oead_tools.dictToStruct(bombBag))

    # arrowBag['symbol'] = 'ObjArrowBag'
    # arrowBag['graphics']['path'] = 'ObjArrowBag.bfres'
    # arrowBag['graphics']['model'] = 'ArrowBag'
    # npc_sheet['values'].append(oead_tools.dictToStruct(arrowBag))




DUMMY_NPC = {
    'symbol': 'ItemOcarina',
    'graphics': {
        'path': 'ItemOcarina.bfres',
        'model': 'Ocarina',
        'animations': {'idle': '', 'talk': '', 'walk': '', 'run': ''},
        'rootAnimEnabled': False,
        'animSettings': [
            {'name': 'wait', 'blendTime': 4, 'lipsync': 0, 'cull': 2},
            {'name': 'talk', 'blendTime': 4, 'lipsync': 1, 'cull': 2},
            {'name': 'walk', 'blendTime': 4, 'lipsync': 0, 'cull': 2},
            {'name': 'run', 'blendTime': 4, 'lipsync': 0, 'cull': 2}
        ],
        'drsb': 'ItemOcarina.drsb',
        'waterChannel': {'enable': True, 'offsetY': 0.0, 'limitDepth': 0.5},
        'facial': '',
        'interestIK': '',
        'turn': {'enable': False, 'autoTurn': False, 'threshold': 30.0, 'reactionTime': 1.0, 'duration': 0.25},
        'cull': 1
    },
    'eventInfo': {'eventAsset': 'ItemCommon.bfevfl', 'actorName': 'Item'},
    'eventTriggers': [{'condition': 2, 'additionalConditions': [], 'entryPoint': 'Ocarina'}],
    'doAction': {'type': 7, 'yOffset': 0.0, 'xzDistance': 1.5, 'yDistance': 1.7999999523162842,
        'playerAngleRange': 45.0, 'reactionAngleRange': 180.0},
    'talk': {'personalSpace': 1.5, 'talkerLabel': ''},
    'actorArgs': {'layoutID': 0, 'identifier': 0},
    'popConditions': {
        'conditions': [],
        'depopEnable': False
    },
    'layoutConditions': [],
    'lookAtOffsetY': 0.0,
    'behavior': {
        'type': 2,
        'parameters': ['0', '0', '0', '0', '0']
    },
    'movement': {
        'walk': {'moveSpeed': 1.5, 'turnSpeed': 45.0},
        'run': {'moveSpeed': 2.5, 'turnSpeed': 120.0}
    },
    'collision': {
        'shape': 3,
        'traits': 'Ocarina',
        'component': 1,
        'isStatic': False,
        'filter': 5,
        'material': 0,
        'groundCheck': True,
        'offset': {'x': 0.0, 'y': 0.25, 'z': 0.0},
        'rotation': {'x': 0.0, 'y': 0.0, 'z': 0.0},
        'parameters': [1.7999999523162842, 0.5, 1.7999999523162842]
    },
    'damageCollision': {'enable': False, 'sizeDiff': 0.0},
    'ocarina': {'enable': False, 'distance': 0.0},
    'shellSensor': [],
    'attribute': 0
}
