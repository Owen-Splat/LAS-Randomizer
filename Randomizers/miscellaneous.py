import Tools.event_tools as event_tools
from Randomizers import item_get
from Randomizers import data



def changeSunkenSword(flowchart, itemKey, itemIndex, modelPath, modelName, room):
    item_get.insertItemGetAnimation(flowchart, itemKey, itemIndex, 'Event5', 'Event8')

    fork = event_tools.findEvent(flowchart, 'Event0')
    fork.data.forks.pop(0) # remove the itemget animation event
    event_tools.removeEventAfter(flowchart, 'Event10')
    # event_tools.findEvent(flowchart, 'Event1').data.params.data['itemType'] = -1

    fork = event_tools.findEvent(flowchart, 'Event8')
    fork.data.forks.pop(1) # remove the sword spin attack animation event

    # Keep the normal model if it's a sword
    room.actors[4].parameters[0] = bytes('ObjSinkingSword.bfres' if itemKey == 'SwordLv1' else modelPath, 'utf-8')
    room.actors[4].parameters[1] = bytes('SinkingSword' if itemKey == 'SwordLv1' else modelName, 'utf-8')
    room.actors[4].parameters[2] = bytes('examine', 'utf-8')
    room.actors[4].parameters[3] = bytes('SwordGet', 'utf-8')



def changeBirdKey(flowchart, itemKey, itemIndex, modelPath, modelName, room):
    birdKeyItemGet = item_get.insertItemGetAnimation(flowchart, itemKey, itemIndex, None, None)

    event_tools.addEntryPoint(flowchart, 'TalTal')
    event_tools.createActionChain(flowchart, 'TalTal', [
        ('SinkingSword', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': data.ROOSTER_CAVE_FLAG, 'value': True})
    ], birdKeyItemGet)

    room.actors[0].type = 0x194 # sinking sword
    room.actors[0].parameters[0] = bytes(modelPath, 'utf-8')
    room.actors[0].parameters[1] = bytes(modelName, 'utf-8')
    room.actors[0].parameters[2] = bytes('TalTal', 'utf-8')
    room.actors[0].parameters[3] = bytes(data.ROOSTER_CAVE_FLAG, 'utf-8')



def changeOcarina(flowchart, itemKey, itemIndex, modelPath, modelName, room):
    dreamShrineItemGet = item_get.insertItemGetAnimation(flowchart, itemKey, itemIndex, None, None)

    event_tools.addEntryPoint(flowchart, 'DreamShrine')
    event_tools.createActionChain(flowchart, 'DreamShrine', [
        ('SinkingSword', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': data.DREAM_SHRINE_FLAG, 'value': True})
    ], dreamShrineItemGet)

    room.actors[5].type = 0x194 # sinking sword
    room.actors[5].parameters[0] = bytes(modelPath, 'utf-8')
    room.actors[5].parameters[1] = bytes(modelName, 'utf-8')
    room.actors[5].parameters[2] = bytes('DreamShrine', 'utf-8')
    room.actors[5].parameters[3] = bytes(data.DREAM_SHRINE_FLAG, 'utf-8')



def changeMushroom(flowchart, itemKey, itemIndex, modelPath, modelName, room):
    woodsItemGet = item_get.insertItemGetAnimation(flowchart, itemKey, itemIndex, None, None)

    event_tools.addEntryPoint(flowchart, 'Woods')
    event_tools.createActionChain(flowchart, 'Woods', [
        ('SinkingSword', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': data.WOODS_LOOSE_FLAG, 'value': True})
    ], woodsItemGet)

    room.actors[3].type = 0x194 # sinking sword
    room.actors[3].parameters[0] = bytes(modelPath, 'utf-8')
    room.actors[3].parameters[1] = bytes(modelName, 'utf-8')
    room.actors[3].parameters[2] = bytes('Woods', 'utf-8')
    room.actors[3].parameters[3] = bytes(data.WOODS_LOOSE_FLAG, 'utf-8')



def changeLens(flowchart, itemKey, itemIndex, modelPath, modelName, room):
    lensItemGet = item_get.insertItemGetAnimation(flowchart, itemKey, itemIndex)

    event_tools.addEntryPoint(flowchart, 'MermaidCave')
    event_tools.createActionChain(flowchart, 'MermaidCave', [
        ('SinkingSword', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': data.MERMAID_CAVE_FLAG, 'value': True})
    ], lensItemGet)

    room.actors[7].type = 0x194 # sinking sword
    room.actors[7].parameters[0] = bytes(modelPath, 'utf-8')
    room.actors[7].parameters[1] = bytes(modelName, 'utf-8')
    room.actors[7].parameters[2] = bytes('MermaidCave', 'utf-8')
    room.actors[7].parameters[3] = bytes(data.MERMAID_CAVE_FLAG, 'utf-8')
