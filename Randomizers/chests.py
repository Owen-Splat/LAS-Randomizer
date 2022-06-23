import Tools.event_tools as event_tools
from Randomizers import item_get



def writeChestEvent(flow, room, itemKey, itemIndex):
    if itemKey not in ['$ENEMY', '$EXT:MasterStalfonLetter'] and room != 'taltal-5-chest-puzzle':
        event_tools.addEntryPoint(flow.flowchart, room)

    if itemKey == 'SecretMedicine':
        itemGet = insertChestMedicineEvent(flow.flowchart)
    # elif itemKey == 'ShadowTrap':
    #     itemGet = insertShadowLinkEvent(flow.flowchart)
    else:
        itemGet = item_get.insertItemGetAnimation(flow.flowchart, itemKey, itemIndex)
    
    actorSwitch = event_tools.createActionChain(flow.flowchart, None, [
        ('TreasureBox', 'SetActorSwitch', {'switchIndex': 1, 'value': True}),
        ('TreasureBox', 'PopItem', {})
    ], itemGet)

    boxOpenEvent = event_tools.createSubFlowEvent(flow.flowchart, '', 'BoxOpen', {'channel': 'open'}, actorSwitch)

    event_tools.insertEventAfter(flow.flowchart, room, boxOpenEvent)

    if room == 'taltal-5-chest-puzzle':
        event_tools.removeEventAfter(flow.flowchart, 'Event32')
        event_tools.insertEventAfter(flow.flowchart, 'Event32', itemGet)



# special event to heal player and close box if they already have medicine
def insertChestMedicineEvent(flowchart):
    takeMedicineEvent = event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'AddItemByKey', {'itemKey': 'SecretMedicine', 'count': 1, 'index': -1, 'autoEquip': False}),
        ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'SecretMedicine', 'keepCarry': False, 'messageEntry': ''}),
        ('Link', 'Heal', {'amount': 99})
    ], None)

    healEvent = event_tools.createActionEvent(flowchart, 'Link', 'Heal', {'amount': 99}, None)
    actorSwitch = event_tools.createActionEvent(flowchart, 'TreasureBox', 'SetActorSwitch', {'switchIndex': 1, 'value': False}, healEvent)
    closeEvent = event_tools.createSubFlowEvent(flowchart, '', 'BoxClose', {}, actorSwitch)
    leaveMedicineEvent = event_tools.createActionEvent(flowchart, 'Link', 'GenericItemGetSequenceByKey', {'itemKey': 'SecretMedicine', 'keepCarry': False, 'messageEntry': 'SecretMedicine2'}, closeEvent)

    return event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem', {'count': 1, 'itemType': 22}, {0: takeMedicineEvent, 1: leaveMedicineEvent})



# # special event for the shadow link trap
# def insertShadowLinkEvent(flowchart):
#     enableEvent = event_tools.createActionChain(flowchart, None, [
#         ('ShadowLink', 'ModelVisibility', {'modelIndex': 0, 'visible': True}),
#         ('ShadowLink', 'SetActorSwitch', {'switchIndex': 0, 'value': False})
#     ], None)

#     startEvent = event_tools.createActionChain(flowchart, enableEvent, [
#         ('ShadowLink', 'PopStart', {}),
#         ('ShadowLink', 'PlayAnimation', {'blendTime': 0.1, 'name': 'wait'})
#     ], None)

#     return event_tools.createForkEvent(flowchart, None, [
#         event_tools.createActionEvent(flowchart, 'ShadowLink', 'LookAtCharacter', {'chaseRatio': 0.085, 'distanceOffset': 0.0, 'duration': 0.4}),
#         event_tools.createActionChain(flowchart, None, [
#             ('ShadowLink', 'AimCompassPoint', {'direction': 0, 'duration': 0.02, 'withoutTurn': False}),
#             ('Timer', 'Wait', {'time': 0.5}),
#             ('ShadowLink', 'PlayTailorOtherChannelEx', {'channel': 'Sign', 'index': 0, 'restart': False, 'time': 1.25})
#         ], None)
#     ], startEvent)[0]