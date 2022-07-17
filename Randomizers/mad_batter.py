import Tools.event_tools as event_tools



def writeEvents(flow, item1, item2, item3):
    """Combine Talk and End entry points into one flow, cutting out the normal choose your upgrade dialogue.
    Then adds separate flows for each Mad Batter to give specific items"""
    
    event_tools.insertEventAfter(flow.flowchart, 'Event19', 'Event13')

    ## Mad Batter A (bay)
    event_tools.addEntryPoint(flow.flowchart, 'BatterA')
    subflowA = event_tools.createSubFlowEvent(flow.flowchart, '', 'talk2', {})
    event_tools.insertEventAfter(flow.flowchart, 'BatterA', subflowA)
    event_tools.insertEventAfter(flow.flowchart, subflowA, item1)

    ## Mad Batter B (woods)
    event_tools.addEntryPoint(flow.flowchart, 'BatterB')
    subflowB = event_tools.createSubFlowEvent(flow.flowchart, '', 'talk2', {})
    event_tools.insertEventAfter(flow.flowchart, 'BatterB', subflowB)
    event_tools.insertEventAfter(flow.flowchart, subflowB, item2)

    ## Mad Batter C (mountain)
    event_tools.addEntryPoint(flow.flowchart, 'BatterC')
    subflowC = event_tools.createSubFlowEvent(flow.flowchart, '', 'talk2', {})
    event_tools.insertEventAfter(flow.flowchart, 'BatterC', subflowC)
    event_tools.insertEventAfter(flow.flowchart, subflowC, item3)

