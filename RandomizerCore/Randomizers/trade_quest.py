import Tools.event_tools as event_tools
from Randomizers import actors, item_get


def mamashaChanges(flowchart, placements, item_defs, rom_path):
    actors.addNeededActors(flowchart, rom_path)
    item = placements['mamasha']
    item_index = placements['indexes']['mamasha'] if 'mamasha' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, item_defs[item]['item-key'], item_index, 'Event15')

    event1 = event_tools.findEvent(flowchart, 'Event1')
    event3 = event_tools.findEvent(flowchart, 'Event3')
    event3.data.actor = event1.data.actor
    event3.data.actor_query = event1.data.actor_query
    event3.data.params.data = {'symbol': 'TradeYoshiDollGet'}



def ciaociaoChanges(flowchart, placements, item_defs, rom_path):
    actors.addNeededActors(flowchart, rom_path)
    item = placements['ciao-ciao']
    item_index = placements['indexes']['ciao-ciao'] if 'ciao-ciao' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, item_defs[item]['item-key'], item_index, 'Event21')

    event1 = event_tools.findEvent(flowchart, 'Event1')
    event3 = event_tools.findEvent(flowchart, 'Event3')
    event3.data.actor = event1.data.actor
    event3.data.actor_query = event1.data.actor_query
    event3.data.params.data = {'symbol': 'TradeRibbonGet'}



def saleChanges(flowchart, placements, item_defs, rom_path):
    actors.addNeededActors(flowchart, rom_path)
    item = placements['sale']
    item_index = placements['indexes']['sale'] if 'sale' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, item_defs[item]['item-key'], item_index, 'Event31')

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



def kikiChanges(flowchart, placements, settings, item_defs, rom_path):
    actors.addNeededActors(flowchart, rom_path)

    item = placements['kiki']
    item_index = placements['indexes']['kiki'] if 'kiki' in placements['indexes'] else -1

    get_event = item_get.insertItemGetAnimation(flowchart, item_defs[item]['item-key'], item_index, None, 'Event102')

    bananas_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': 'TradeBananasGet'}, {0: 'Event118', 1: 'Event32'})

    event_tools.insertEventAfter(flowchart, 'Event91', bananas_check)
    event_tools.insertEventAfter(flowchart, 'Event84', 'Event15') # skip over setting the trade quest slot to be empty
    event_tools.insertEventAfter(flowchart, 'Event29', 'Event88')
    fork = event_tools.findEvent(flowchart, 'Event88')
    fork.data.forks.pop(0)

    if settings['open-bridge']:
        event_tools.insertEventAfter(flowchart, 'Event9', 'Event31')
        event_tools.insertEventAfter(flowchart, 'Event10', 'Event31')

        fork = event_tools.findEvent(flowchart, 'Event28')
        fork.data.forks.pop(1)
        fork.data.forks.pop(1)
        fork.data.forks.pop(1)
        fork.data.forks.pop(1)
        fork.data.forks.pop(2)

        fork = event_tools.findEvent(flowchart, 'Event31')
        fork.data.forks.pop(0)

        kiki_gone = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
        {'symbol': 'KikiGone', 'value': True}, get_event)

        event_tools.insertEventAfter(flowchart, 'Event89', kiki_gone)
    else:
        event_tools.insertEventAfter(flowchart, 'Event89', get_event)



def tarinChanges(flowchart, placements, item_defs):
    item = placements['tarin-ukuku']
    item_index = placements['indexes']['tarin-ukuku'] if 'tarin-ukuku' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, item_defs[item]['item-key'], item_index, 'Event130', 'Event29')



def chefChanges(flowchart, placements, item_defs, rom_path):
    actors.addNeededActors(flowchart, rom_path)
    item = placements['chef-bear']
    item_index = placements['indexes']['chef-bear'] if 'chef-bear' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, item_defs[item]['item-key'], item_index, 'Event16', None) # Event4

    event1 = event_tools.findEvent(flowchart, 'Event1')
    event11 = event_tools.findEvent(flowchart, 'Event11')
    event11.data.actor = event1.data.actor
    event11.data.actor_query = event1.data.actor_query
    event11.data.params.data = {'symbol': 'TradeHoneycombGet'}



def papahlChanges(flowchart, placements, item_defs, rom_path):
    actors.addNeededActors(flowchart, rom_path)
    item = placements['papahl']
    item_index = placements['indexes']['papahl'] if 'papahl' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, item_defs[item]['item-key'], item_index, 'Event32', 'Event62')

    event81 = event_tools.findEvent(flowchart, 'Event81')
    event2 = event_tools.findEvent(flowchart, 'Event2')
    event2.data.actor = event81.data.actor
    event2.data.actor_query = event81.data.actor_query
    event2.data.params.data = {'symbol': 'TradePineappleGet'}



def christineChanges(flowchart, placements, item_defs, rom_path):
    item = placements['christine-trade']
    item_index = placements['indexes']['christine-trade'] if 'christine-trade' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, item_defs[item]['item-key'], item_index, 'Event15', 'Event22')

    event0 = event_tools.findEvent(flowchart, 'Event0')
    event10 = event_tools.findEvent(flowchart, 'Event10')
    event10.data.actor = event0.data.actor
    event10.data.actor_query = event0.data.actor_query
    event10.data.params.data = {'symbol': 'TradeHibiscusGet'}

    event_tools.insertEventAfter(flowchart, 'Event28', 'Event15')



def mrWriteChanges(flowchart, placements, item_defs, rom_path):
    actors.addNeededActors(flowchart, rom_path)
    item = placements['mr-write']
    item_index = placements['indexes']['mr-write'] if 'mr-write' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, item_defs[item]['item-key'], item_index, 'Event48', 'Event46')

    event0 = event_tools.findEvent(flowchart, 'Event0')
    event2 = event_tools.findEvent(flowchart, 'Event2')
    event2.data.actor = event0.data.actor
    event2.data.actor_query = event0.data.actor_query
    event2.data.params.data = {'symbol': 'TradeLetterGet'}

    event_tools.insertEventAfter(flowchart, 'Event7', 'Event47')

    fork = event_tools.findEvent(flowchart, 'Event47')
    fork.data.forks.pop(1)



def grandmaYahooChanges(flowchart, placements, item_defs, rom_path):
    actors.addNeededActors(flowchart, rom_path)
    item = placements['grandma-yahoo']
    item_index = placements['indexes']['grandma-yahoo'] if 'grandma-yahoo' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, item_defs[item]['item-key'], item_index, 'Event54', 'Event33')

    broom_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': 'TradeBroomGet'}, {0: 'Event69', 1: 'Event79'})

    event_tools.insertEventAfter(flowchart, 'Event11', 'Event0')

    event_tools.setSwitchEventCase(flowchart, 'Event0', 0, broom_check)

    event_tools.insertEventAfter(flowchart, 'Event81', 'Event53')

    fork = event_tools.findEvent(flowchart, 'Event53')
    fork.data.forks.pop(1)



def fishermanChanges(flowchart, placements, item_defs, rom_path):
    actors.addNeededActors(flowchart, rom_path)
    item = placements['bay-fisherman']
    item_index = placements['indexes']['bay-fisherman'] if 'bay-fisherman' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, item_defs[item]['item-key'], item_index, 'Event28', 'Event42')

    event0 = event_tools.findEvent(flowchart, 'Event0')
    event2 = event_tools.findEvent(flowchart, 'Event2')
    event2.data.actor = event0.data.actor
    event2.data.actor_query = event0.data.actor_query
    event2.data.params.data = {'symbol': 'TradeFishingHookGet'}

    event_tools.insertEventAfter(flowchart, 'Event32', 'Event33')

    fork = event_tools.findEvent(flowchart, 'Event27')
    fork.data.forks.pop(1)



def mermaidChanges(flowchart, placements, item_defs, rom_path):
    actors.addNeededActors(flowchart, rom_path)
    item = placements['mermaid-martha']
    item_index = placements['indexes']['mermaid-martha'] if 'mermaid-martha' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, item_defs[item]['item-key'], item_index, 'Event73', 'Event55')

    event0 = event_tools.findEvent(flowchart, 'Event0')
    event2 = event_tools.findEvent(flowchart, 'Event2')
    event2.data.actor = event0.data.actor
    event2.data.actor_query = event0.data.actor_query
    event2.data.params.data = {'symbol': 'TradeNecklaceGet'}

    fork = event_tools.findEvent(flowchart, 'Event71')
    fork.data.forks.pop(1)



def statueChanges(flowchart, rom_path):
    actors.addNeededActors(flowchart, rom_path)

    scale_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': 'TradeMermaidsScaleGet'}, {0: 'Event28', 1: 'Event32'})
    
    event_tools.setSwitchEventCase(flowchart, 'Event3', 0, scale_check)
