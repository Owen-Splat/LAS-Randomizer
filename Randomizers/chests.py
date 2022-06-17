import Tools.event_tools as event_tools



def writeChestEvent(flow, room, itemKey, itemGet):
    if itemKey not in ['$ENEMY', '$EXT:MasterStalfonLetter'] and room != 'taltal-5-chest-puzzle':
        event_tools.addEntryPoint(flow.flowchart, room)

    if itemKey == 'SecretMedicine':
        itemGet = insertChestMedicineEvent(flow.flowchart)
    
    if itemKey == 'ZapTrap':
        itemGet, join = insertZapTrapEvent(flow.flowchart)
    
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



# special event for zap trap
def insertZapTrapEvent(flowchart):
    stopEvent = event_tools.createActionEvent(flowchart, 'Link', 'StopTailorOtherChannel',
    {'channel': 'toolshopkeeper_dmg', 'index': 0})

    return event_tools.createForkEvent(flowchart, {
        event_tools.createActionEvent(flowchart, 'Link', 'PlayAnimation', {'blendTime': 0.1, 'name': 'ev_dmg_elec_lp'}),
        event_tools.createActionEvent(flowchart, 'Link', 'PlayTailorOtherChannelEx', {'channel': 'toolshopkeeper_dmg', 'index': 0, 'restart': False, 'time': 1.5}),
        event_tools.createActionEvent(flowchart, 'Timer', 'Wait', {'time': 3}),
        event_tools.createActionEvent(flowchart, 'Link', 'Damage', {'amount': 8})
    }, stopEvent)
