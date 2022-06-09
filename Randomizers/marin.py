import Tools.event_tools as event_tools



def make_event_changes(flow):
    fork = event_tools.findEvent(flow.flowchart, 'Event249')
    fork.data.forks.pop(0)
    event_tools.insertEventAfter(flow.flowchart, 'Event27', 'Event249')
    event20 = event_tools.findEvent(flow.flowchart, 'Event20')
    event160 = event_tools.findEvent(flow.flowchart, 'Event160')
    event676 = event_tools.findEvent(flow.flowchart, 'Event676')
    event160.data.actor = event20.data.actor
    event676.data.actor = event20.data.actor
    event160.data.actor_query = event20.data.actor_query
    event676.data.actor_query = event20.data.actor_query
    event160.data.params.data['symbol'] = 'MarinsongGet'
    event676.data.params.data['symbol'] = 'MarinsongGet'

    # Make Marin not do beach_talk under any circumstance
    event_tools.setSwitchEventCase(flow.flowchart, 'Event21', 0, 'Event674')
