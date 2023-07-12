import Tools.event_tools as event_tools
from Randomizers import item_get



def makePrizesStack(flowchart, placements, item_defs):
    """Makes the rapids time attack prizes stack, so getting faster times give the slower prizes as well if you do not have them"""

    # 45 prize event doesn't need anything special :)
    item_index = placements['indexes']['rapids-race-45'] if 'rapids-race-45' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, item_defs[placements['rapids-race-45']]['item-key'], item_index, 'Event42', 'Event88')

    # since these events only get called once by using flags, they each can just check the slower goal, and subflow to it
    item_index = placements['indexes']['rapids-race-35'] if 'rapids-race-35' in placements['indexes'] else -1
    get35 = item_get.insertItemGetAnimation(flowchart, item_defs[placements['rapids-race-35']]['item-key'], item_index, None, 'Event86')
    subflow45 = event_tools.createSubFlowEvent(flowchart, '', '5minfirst', {}, get35)
    check45 = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': '5minGaul'}, {0: subflow45, 1: get35})
    event_tools.insertEventAfter(flowchart, 'Event40', check45)

    # 30 prize just needs to subflow to the 35 prize, as the 35 prize event already checks for the 45
    item_index = placements['indexes']['rapids-race-30'] if 'rapids-race-30' in placements['indexes'] else -1
    get30 = item_get.insertItemGetAnimation(flowchart, item_defs[placements['rapids-race-30']]['item-key'], item_index, None, 'Event85')
    subflow35 = event_tools.createSubFlowEvent(flowchart, '', '3minfirst', {}, get30)
    check35 = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': '3minGaul'}, {0: subflow35, 1: get30})
    event_tools.insertEventAfter(flowchart, 'Event38', check35)
