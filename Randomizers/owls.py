import Tools.event_tools as event_tools
from Randomizers import item_get



def makeFieldChanges(flowchart, placements, item_defs):
    '''Places items on the field owls. Hint system not implemented'''

    field_owls = {
        'owl-statue-below-D8': 'Event20',
        'owl-statue-pothole': 'Event22',
        'owl-statue-above-cave': 'Event28',
        'owl-statue-moblin-cave': 'Event30',
        'owl-statue-south-bay': 'Event32',
        'owl-statue-desert': 'Event34',
        'owl-statue-maze': 'Event36',
        'owl-statue-taltal-east': 'Event38',
        'owl-statue-rapids': 'Event40'
    }
    for k,v in field_owls.items():
        item = placements[k]
        item_index = placements['indexes'][k] if k in placements['indexes'] else -1
        
        gift_event = item_get.insertItemGetAnimation(flowchart, item_defs[item]['item-key'], item_index, None, None)

        flag_set = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
            {'symbol': k, 'value': True}, gift_event)
        
        flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': k}, {0: flag_set, 1: None})
        
        event_tools.insertEventAfter(flowchart, v, flag_check)




def makeDungeonChanges(flowchart, placements, item_defs):
    '''Places items on the dungeon owls. Hint system not implemented'''

    ### since Tail Cave statues 04B and 05F use the same event, bundle the event into its own entrypoint
    ### then the original entrypoint will be used solely for 05F, and 04B will have its own entrypoint
    ### both will subflow to the shared events and then call the item get animation afterwards
    ### every other statue event can just add the item event after the message fork events
    event_tools.addEntryPoint(flowchart, 'examine_TailShared')
    event_tools.insertEventAfter(flowchart, 'examine_TailShared', 'Event22')

    event_tools.addEntryPoint(flowchart, 'examine_Tail04B')
    subflow_a = event_tools.createSubFlowEvent(flowchart, '', 'examine_TailShared', {})
    event_tools.insertEventAfter(flowchart, 'examine_Tail04B', subflow_a)

    subflow_b = event_tools.createSubFlowEvent(flowchart, '', 'examine_TailShared', {})
    event_tools.insertEventAfter(flowchart, 'examine_Tail04B05F', subflow_b)

    ### all 3 owl statues in Color Dungeon use the same entrypoint, so same thing here
    event_tools.addEntryPoint(flowchart, 'examine_Color06B') # left
    subflow_c = event_tools.createSubFlowEvent(flowchart, '', 'examine_Color', {})
    event_tools.insertEventAfter(flowchart, 'examine_Color06B', subflow_c)

    event_tools.addEntryPoint(flowchart, 'examine_Color07C') # center
    subflow_d = event_tools.createSubFlowEvent(flowchart, '', 'examine_Color', {})
    event_tools.insertEventAfter(flowchart, 'examine_Color07C', subflow_d)

    event_tools.addEntryPoint(flowchart, 'examine_Color05E') # right
    subflow_e = event_tools.createSubFlowEvent(flowchart, '', 'examine_Color', {})
    event_tools.insertEventAfter(flowchart, 'examine_Color05E', subflow_e)

    dungeon_owls = {
        'D1-owl-statue-spinies': subflow_a,
        'D1-owl-statue-3-of-a-kind': subflow_b,
        'D1-owl-statue-long-hallway': 'Event48',
        'D2-owl-statue-first': 'Event59',
        'D2-owl-statue-second': 'Event62',
        'D2-owl-statue-third': 'Event65',
        'D3-owl-statue-basement-north': 'Event27',
        'D3-owl-statue-arrow': 'Event73',
        'D3-owl-statue-northwest': 'Event76',
        'D4-owl-statue': 'Event79',
        'D5-owl-statue-south': 'Event82',
        'D5-owl-statue-north': 'Event85',
        'D6-owl-statue-ledge': 'Event88',
        'D6-owl-statue-southeast': 'Event91',
        'D6-owl-statue-canal': 'Event94',
        'D7-owl-statue-ball': 'Event97',
        'D7-owl-statue-kirbys': 'Event100',
        'D7-owl-statue-4th-pillar': 'Event103',
        'D8-owl-statue-above-smasher': 'Event39',
        'D8-owl-statue-below-gibdos': 'Event109',
        'D8-owl-statue-eye-statue': 'Event112',
        'D0-owl-statue-left': subflow_c,
        'D0-owl-statue-center': subflow_d,
        'D0-owl-statue-right': subflow_e
    }
    for k,v in dungeon_owls.items():
        item = placements[k]
        item_index = placements['indexes'][k] if k in placements['indexes'] else -1

        gift_event = item_get.insertItemGetAnimation(flowchart, item_defs[item]['item-key'], item_index, None, None)

        flag_set = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
            {'symbol': k, 'value': True}, gift_event)

        flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': k}, {0: flag_set, 1: None})
        
        event_tools.insertEventAfter(flowchart, v, flag_check)
