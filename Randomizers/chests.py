import Tools.event_tools as event_tools



def write_chest_event(flow, room, itemKey, itemGetEvent):
    if itemKey != '$ENEMY' and room != 'taltal-5-chest-puzzle':
        event_tools.addEntryPoint(flow.flowchart, room)

    if itemKey == 'SecretMedicine':
        itemGetEvent = insertChestMedicineEvent(flow.flowchart)
    
    actorSwitch = event_tools.createActionChain(flow.flowchart, None, [
        ('TreasureBox', 'SetActorSwitch', {'switchIndex': 1, 'value': True}),
        ('TreasureBox', 'PopItem', {})
    ], itemGetEvent)

    boxOpenEvent = event_tools.createSubFlowEvent(flow.flowchart, '', 'BoxOpen', {'channel': 'open'}, actorSwitch)

    event_tools.insertEventAfter(flow.flowchart, room, boxOpenEvent)

    if room == 'taltal-5-chest-puzzle':
        event_tools.removeEventAfter(flow.flowchart, 'Event32')
    
    event_tools.insertEventAfter(flow.flowchart, 'Event32', itemGetEvent)

    return flow



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
