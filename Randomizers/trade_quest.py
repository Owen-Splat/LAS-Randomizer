import Tools.event_tools as event_tools
import Tools.leb as leb



def trendy_yoshi_changes():
    pass



def mamashaChanges(flow):
    event3 = event_tools.findEvent(flow.flowchart, 'Event3')
    event1 = event_tools.findEvent(flow.flowchart, 'Event1')
    event3.data.actor = event1.data.actor
    event3.data.actor_query = event1.data.actor_query
    event3.data.params.data = {'symbol': 'TradeYoshiDollGet'}



def ciaociaoChanges(flow):
    event3 = event_tools.findEvent(flow.flowchart, 'Event3')
    event1 = event_tools.findEvent(flow.flowchart, 'Event1')
    event3.data.actor = event1.data.actor
    event3.data.actor_query = event1.data.actor_query
    event3.data.params.data = {'symbol': 'TradeRibbonGet'}



def saleChanges(flow):
    event2 = event_tools.findEvent(flow.flowchart, 'Event2')
    event0 = event_tools.findEvent(flow.flowchart, 'Event0')
    event2.data.actor = event0.data.actor
    event2.data.actor_query = event0.data.actor_query
    event2.data.params.data = {'symbol': 'TradeDogFoodGet'}



# def move_kiki(roomData): # move kiki and remove other monkeys since we don't need them, might help with performance too? idk lol
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



def kikiChanges(flow, itemGetAnim):
    bananasCheck = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': 'TradeBananasGet'}, {0: 'Event118', 1: 'Event32'})

    event_tools.insertEventAfter(flow.flowchart, 'Event91', bananasCheck)
    event_tools.insertEventAfter(flow.flowchart, 'Event9', 'Event31')
    event_tools.insertEventAfter(flow.flowchart, 'Event84', 'Event15')
    event_tools.insertEventAfter(flow.flowchart, 'Event10', 'Event31')

    fork = event_tools.findEvent(flow.flowchart, 'Event28')
    fork.data.forks.pop(1)
    fork.data.forks.pop(1)
    fork.data.forks.pop(1)
    fork.data.forks.pop(1)
    fork.data.forks.pop(2)

    fork = event_tools.findEvent(flow.flowchart, 'Event31')
    fork.data.forks.pop(0)

    event_tools.insertEventAfter(flow.flowchart, 'Event29', 'Event88')
    fork = event_tools.findEvent(flow.flowchart, 'Event88')
    fork.data.forks.pop(0)

    kikiGone = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
    {'symbol': 'KikiGone', 'value': True},
    itemGetAnim)

    event_tools.insertEventAfter(flow.flowchart, 'Event89', kikiGone)



def tarinChanges(flow, itemGet):
    pass



def chefChanges(flow, itemGet):
    pass



def papahlChanges(flow, itemGet):
    pass



def christineChanges(flow, itemGet):
    pass



def mrWriteChanges(flow, itemGet):
    pass



def grandmaYahooChanges(flow, itemGet):
    pass



def fishermanChanges(flow, itemGet):
    pass



def mermaidChanges(flow, itemGet):
    pass