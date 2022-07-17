import Tools.event_tools as event_tools
from Randomizers import actors, item_get


def mamashaChanges(flowchart, placements, itemDefs, romPath):
    actors.addNeededActors(flowchart, romPath)
    item = placements['mamasha']
    itemIndex = placements['indexes']['mamasha'] if 'mamasha' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, itemDefs[item]['item-key'], itemIndex, 'Event15')

    event1 = event_tools.findEvent(flowchart, 'Event1')
    event3 = event_tools.findEvent(flowchart, 'Event3')
    event3.data.actor = event1.data.actor
    event3.data.actor_query = event1.data.actor_query
    event3.data.params.data = {'symbol': 'TradeYoshiDollGet'}



def ciaociaoChanges(flowchart, placements, itemDefs, romPath):
    actors.addNeededActors(flowchart, romPath)
    item = placements['ciao-ciao']
    itemIndex = placements['indexes']['ciao-ciao'] if 'ciao-ciao' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, itemDefs[item]['item-key'], itemIndex, 'Event21')

    event1 = event_tools.findEvent(flowchart, 'Event1')
    event3 = event_tools.findEvent(flowchart, 'Event3')
    event3.data.actor = event1.data.actor
    event3.data.actor_query = event1.data.actor_query
    event3.data.params.data = {'symbol': 'TradeRibbonGet'}



def saleChanges(flowchart, placements, itemDefs, romPath):
    actors.addNeededActors(flowchart, romPath)
    item = placements['sale']
    itemIndex = placements['indexes']['sale'] if 'sale' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, itemDefs[item]['item-key'], itemIndex, 'Event31')

    event0 = event_tools.findEvent(flowchart, 'Event0')
    event2 = event_tools.findEvent(flowchart, 'Event2')
    event2.data.actor = event0.data.actor
    event2.data.actor_query = event0.data.actor_query
    event2.data.params.data = {'symbol': 'TradeDogFoodGet'}



# def move_kiki(roomData): # move kiki and remove other monkeys since we don't need them
#     # kiki_moved = bool(False)
#     # monkeys = []
#     for act in roomData.actors:
#         if act.type == 363:
#             # if not kiki_moved:
#             act.X -= 393216 # move kiki one tile south
#             act.Y += 393216 * 2 # move kiki two tiles east
#                 # kiki_moved = True
#             # else:
#             #     monkeys.append(act)
#     # for monke in monkeys:
#     #     roomData.actors.remove(monke)



def kikiChanges(flowchart, placements, itemDefs, romPath):
    actors.addNeededActors(flowchart, romPath)
    item = placements['kiki']
    itemIndex = placements['indexes']['kiki'] if 'kiki' in placements['indexes'] else -1

    bananasCheck = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': 'TradeBananasGet'}, {0: 'Event118', 1: 'Event32'})

    event_tools.insertEventAfter(flowchart, 'Event91', bananasCheck)
    event_tools.insertEventAfter(flowchart, 'Event9', 'Event31')
    event_tools.insertEventAfter(flowchart, 'Event84', 'Event15')
    event_tools.insertEventAfter(flowchart, 'Event10', 'Event31')

    fork = event_tools.findEvent(flowchart, 'Event28')
    fork.data.forks.pop(1)
    fork.data.forks.pop(1)
    fork.data.forks.pop(1)
    fork.data.forks.pop(1)
    fork.data.forks.pop(2)

    fork = event_tools.findEvent(flowchart, 'Event31')
    fork.data.forks.pop(0)

    event_tools.insertEventAfter(flowchart, 'Event29', 'Event88')
    fork = event_tools.findEvent(flowchart, 'Event88')
    fork.data.forks.pop(0)

    kikiGone = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
    {'symbol': 'KikiGone', 'value': True},
    item_get.insertItemGetAnimation(flowchart, itemDefs[item]['item-key'], itemIndex, None, 'Event102'))

    event_tools.insertEventAfter(flowchart, 'Event89', kikiGone)



def tarinChanges(flowchart, placements, itemDefs):
    item = placements['tarin-ukuku']
    itemIndex = placements['indexes']['tarin-ukuku'] if 'tarin-ukuku' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, itemDefs[item]['item-key'], itemIndex, 'Event130', 'Event29')



def chefChanges(flowchart, placements, itemDefs, romPath):
    actors.addNeededActors(flowchart, romPath)
    item = placements['chef-bear']
    itemIndex = placements['indexes']['chef-bear'] if 'chef-bear' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, itemDefs[item]['item-key'], itemIndex, 'Event16', None) # Event4

    event1 = event_tools.findEvent(flowchart, 'Event1')
    event11 = event_tools.findEvent(flowchart, 'Event11')
    event11.data.actor = event1.data.actor
    event11.data.actor_query = event1.data.actor_query
    event11.data.params.data = {'symbol': 'TradeHoneycombGet'}



def papahlChanges(flowchart, placements, itemDefs, romPath):
    actors.addNeededActors(flowchart, romPath)
    item = placements['papahl']
    itemIndex = placements['indexes']['papahl'] if 'papahl' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, itemDefs[item]['item-key'], itemIndex, 'Event32', 'Event62')

    event81 = event_tools.findEvent(flowchart, 'Event81')
    event2 = event_tools.findEvent(flowchart, 'Event2')
    event2.data.actor = event81.data.actor
    event2.data.actor_query = event81.data.actor_query
    event2.data.params.data = {'symbol': 'TradePineappleGet'}



def christineChanges(flowchart, placements, itemDefs, romPath):
    item = placements['christine-trade']
    itemIndex = placements['indexes']['christine-trade'] if 'christine-trade' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, itemDefs[item]['item-key'], itemIndex, 'Event15', 'Event22')

    event0 = event_tools.findEvent(flowchart, 'Event0')
    event10 = event_tools.findEvent(flowchart, 'Event10')
    event10.data.actor = event0.data.actor
    event10.data.actor_query = event0.data.actor_query
    event10.data.params.data = {'symbol': 'TradeHibiscusGet'}

    event_tools.insertEventAfter(flowchart, 'Event28', 'Event15')



def mrWriteChanges(flowchart, placements, itemDefs, romPath):
    actors.addNeededActors(flowchart, romPath)
    item = placements['mr-write']
    itemIndex = placements['indexes']['mr-write'] if 'mr-write' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, itemDefs[item]['item-key'], itemIndex, 'Event48', 'Event46')

    event0 = event_tools.findEvent(flowchart, 'Event0')
    event2 = event_tools.findEvent(flowchart, 'Event2')
    event2.data.actor = event0.data.actor
    event2.data.actor_query = event0.data.actor_query
    event2.data.params.data = {'symbol': 'TradeLetterGet'}

    event_tools.insertEventAfter(flowchart, 'Event7', 'Event47')

    fork = event_tools.findEvent(flowchart, 'Event47')
    fork.data.forks.pop(1)



def grandmaYahooChanges(flowchart, placements, itemDefs, romPath):
    actors.addNeededActors(flowchart, romPath)
    item = placements['grandma-yahoo']
    itemIndex = placements['indexes']['grandma-yahoo'] if 'grandma-yahoo' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, itemDefs[item]['item-key'], itemIndex, 'Event54', 'Event33')

    broomCheck = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': 'TradeBroomGet'}, {0: 'Event69', 1: 'Event79'})

    event_tools.insertEventAfter(flowchart, 'Event11', 'Event0')

    event_tools.setSwitchEventCase(flowchart, 'Event0', 0, broomCheck)

    event_tools.insertEventAfter(flowchart, 'Event81', 'Event53')

    fork = event_tools.findEvent(flowchart, 'Event53')
    fork.data.forks.pop(1)



def fishermanChanges(flowchart, placements, itemDefs, romPath):
    actors.addNeededActors(flowchart, romPath)
    item = placements['bay-fisherman']
    itemIndex = placements['indexes']['bay-fisherman'] if 'bay-fisherman' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, itemDefs[item]['item-key'], itemIndex, 'Event28', 'Event42')

    event0 = event_tools.findEvent(flowchart, 'Event0')
    event2 = event_tools.findEvent(flowchart, 'Event2')
    event2.data.actor = event0.data.actor
    event2.data.actor_query = event0.data.actor_query
    event2.data.params.data = {'symbol': 'TradeFishingHookGet'}

    event_tools.insertEventAfter(flowchart, 'Event32', 'Event33')

    fork = event_tools.findEvent(flowchart, 'Event27')
    fork.data.forks.pop(1)



def mermaidChanges(flowchart, placements, itemDefs, romPath):
    actors.addNeededActors(flowchart, romPath)
    item = placements['mermaid-martha']
    itemIndex = placements['indexes']['mermaid-martha'] if 'mermaid-martha' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, itemDefs[item]['item-key'], itemIndex, 'Event73', 'Event55')

    event0 = event_tools.findEvent(flowchart, 'Event0')
    event2 = event_tools.findEvent(flowchart, 'Event2')
    event2.data.actor = event0.data.actor
    event2.data.actor_query = event0.data.actor_query
    event2.data.params.data = {'symbol': 'TradeNecklaceGet'}

    fork = event_tools.findEvent(flowchart, 'Event71')
    fork.data.forks.pop(1)



def statueChanges(flowchart, romPath):
    actors.addNeededActors(flowchart, romPath)

    scaleCheck = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': 'TradeMermaidsScaleGet'}, {0: 'Event28', 1: 'Event32'})
    
    event_tools.setSwitchEventCase(flowchart, 'Event3', 0, scaleCheck)
