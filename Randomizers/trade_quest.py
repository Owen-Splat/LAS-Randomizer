import Tools.event_tools as event_tools



def trendy_yoshi_changes():
    pass



def mamashaChanges(flow):
    event1 = event_tools.findEvent(flow.flowchart, 'Event1')
    event3 = event_tools.findEvent(flow.flowchart, 'Event3')
    event3.data.actor = event1.data.actor
    event3.data.actor_query = event1.data.actor_query
    event3.data.params.data = {'symbol': 'TradeYoshiDollGet'}



def ciaociaoChanges(flow):
    event1 = event_tools.findEvent(flow.flowchart, 'Event1')
    event3 = event_tools.findEvent(flow.flowchart, 'Event3')
    event3.data.actor = event1.data.actor
    event3.data.actor_query = event1.data.actor_query
    event3.data.params.data = {'symbol': 'TradeRibbonGet'}



def saleChanges(flow):
    event0 = event_tools.findEvent(flow.flowchart, 'Event0')
    event2 = event_tools.findEvent(flow.flowchart, 'Event2')
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



def chefChanges(flow):
    event1 = event_tools.findEvent(flow.flowchart, 'Event1')
    event11 = event_tools.findEvent(flow.flowchart, 'Event11')
    event11.data.actor = event1.data.actor
    event11.data.actor_query = event1.data.actor_query
    event11.data.params.data = {'symbol': 'TradeHoneycombGet'}



def papahlChanges(flow):
    event81 = event_tools.findEvent(flow.flowchart, 'Event81')
    event2 = event_tools.findEvent(flow.flowchart, 'Event2')
    event2.data.actor = event81.data.actor
    event2.data.actor_query = event81.data.actor_query
    event2.data.params.data = {'symbol': 'TradePineappleGet'}



def christineChanges(flow):
    event0 = event_tools.findEvent(flow.flowchart, 'Event0')
    event10 = event_tools.findEvent(flow.flowchart, 'Event10')
    event10.data.actor = event0.data.actor
    event10.data.actor_query = event0.data.actor_query
    event10.data.params.data = {'symbol': 'TradeHibiscusGet'}

    event_tools.insertEventAfter(flow.flowchart, 'Event28', 'Event15')



def mrWriteChanges(flow):
    event0 = event_tools.findEvent(flow.flowchart, 'Event0')
    event2 = event_tools.findEvent(flow.flowchart, 'Event2')
    event2.data.actor = event0.data.actor
    event2.data.actor_query = event0.data.actor_query
    event2.data.params.data = {'symbol': 'TradeLetterGet'}

    event_tools.insertEventAfter(flow.flowchart, 'Event7', 'Event47')

    fork = event_tools.findEvent(flow.flowchart, 'Event47')
    fork.data.forks.pop(1)



def grandmaYahooChanges(flow):
    broomCheck = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': 'TradeBroomGet'}, {0: 'Event69', 1: 'Event79'})

    event_tools.insertEventAfter(flow.flowchart, 'Event11', 'Event0')

    event_tools.setSwitchEventCase(flow.flowchart, 'Event0', 0, broomCheck)

    event_tools.insertEventAfter(flow.flowchart, 'Event81', 'Event53')

    fork = event_tools.findEvent(flow.flowchart, 'Event53')
    fork.data.forks.pop(1)



def fishermanChanges(flow):
    event0 = event_tools.findEvent(flow.flowchart, 'Event0')
    event2 = event_tools.findEvent(flow.flowchart, 'Event2')
    event2.data.actor = event0.data.actor
    event2.data.actor_query = event0.data.actor_query
    event2.data.params.data = {'symbol': 'TradeFishingHookGet'}

    event_tools.insertEventAfter(flow.flowchart, 'Event32', 'Event33')

    fork = event_tools.findEvent(flow.flowchart, 'Event27')
    fork.data.forks.pop(1)



def mermaidChanges(flow):
    event0 = event_tools.findEvent(flow.flowchart, 'Event0')
    event2 = event_tools.findEvent(flow.flowchart, 'Event2')
    event2.data.actor = event0.data.actor
    event2.data.actor_query = event0.data.actor_query
    event2.data.params.data = {'symbol': 'TradeNecklaceGet'}

    fork = event_tools.findEvent(flow.flowchart, 'Event71')
    fork.data.forks.pop(1)



def statueChanges(flow):
    scaleCheck = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': 'TradeMermaidsScaleGet'}, {0: 'Event28', 1: 'Event32'})
    
    event_tools.setSwitchEventCase(flow.flowchart, 'Event3', 0, scaleCheck)
