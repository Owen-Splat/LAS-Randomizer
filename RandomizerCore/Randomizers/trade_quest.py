import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers import item_get


def mamashaChanges(flowchart, item_info):
    item_key, item_index = item_info
    item_get.insertItemGetAnimation(flowchart, item_key, item_index, 'Event15')

    event1 = event_tools.findEvent(flowchart, 'Event1')
    event3 = event_tools.findEvent(flowchart, 'Event3')
    event3.data.actor = event1.data.actor
    event3.data.actor_query = event1.data.actor_query
    event3.data.params.data = {'symbol': 'TradeYoshiDollGet'}



def ciaociaoChanges(flowchart, item_info):
    item_key, item_index = item_info
    item_get.insertItemGetAnimation(flowchart, item_key, item_index, 'Event21')

    event1 = event_tools.findEvent(flowchart, 'Event1')
    event3 = event_tools.findEvent(flowchart, 'Event3')
    event3.data.actor = event1.data.actor
    event3.data.actor_query = event1.data.actor_query
    event3.data.params.data = {'symbol': 'TradeRibbonGet'}



def saleChanges(flowchart, item_info):
    item_key, item_index = item_info
    item_get.insertItemGetAnimation(flowchart, item_key, item_index, 'Event31')

    event0 = event_tools.findEvent(flowchart, 'Event0')
    event2 = event_tools.findEvent(flowchart, 'Event2')
    event2.data.actor = event0.data.actor
    event2.data.actor_query = event0.data.actor_query
    event2.data.params.data = {'symbol': 'TradeDogFoodGet'}



def kikiChanges(flowchart, settings, item_key, item_index):
    get_event = item_get.insertItemGetAnimation(flowchart, item_key, item_index, None, 'Event102')

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



def tarinChanges(flowchart, item_info):
    item_key, item_index = item_info
    item_get.insertItemGetAnimation(flowchart, item_key, item_index, 'Event130', 'Event29')



def chefChanges(flowchart, item_info):
    item_key, item_index = item_info
    item_get.insertItemGetAnimation(flowchart, item_key, item_index, 'Event16', None) # Event4

    event1 = event_tools.findEvent(flowchart, 'Event1')
    event11 = event_tools.findEvent(flowchart, 'Event11')
    event11.data.actor = event1.data.actor
    event11.data.actor_query = event1.data.actor_query
    event11.data.params.data = {'symbol': 'TradeHoneycombGet'}



def papahlChanges(flowchart, item_info):
    item_key, item_index = item_info
    item_get.insertItemGetAnimation(flowchart, item_key, item_index, 'Event32', 'Event62')

    event81 = event_tools.findEvent(flowchart, 'Event81')
    event2 = event_tools.findEvent(flowchart, 'Event2')
    event2.data.actor = event81.data.actor
    event2.data.actor_query = event81.data.actor_query
    event2.data.params.data = {'symbol': 'TradePineappleGet'}



def christineChanges(flowchart, item_info):
    item_key, item_index = item_info
    item_get.insertItemGetAnimation(flowchart, item_key, item_index, 'Event15', 'Event22')

    event0 = event_tools.findEvent(flowchart, 'Event0')
    event10 = event_tools.findEvent(flowchart, 'Event10')
    event10.data.actor = event0.data.actor
    event10.data.actor_query = event0.data.actor_query
    event10.data.params.data = {'symbol': 'TradeHibiscusGet'}

    event_tools.insertEventAfter(flowchart, 'Event28', 'Event15')



def mrWriteChanges(flowchart, item_info):
    item_key, item_index = item_info
    item_get.insertItemGetAnimation(flowchart, item_key, item_index, 'Event48', 'Event46')

    event0 = event_tools.findEvent(flowchart, 'Event0')
    event2 = event_tools.findEvent(flowchart, 'Event2')
    event2.data.actor = event0.data.actor
    event2.data.actor_query = event0.data.actor_query
    event2.data.params.data = {'symbol': 'TradeLetterGet'}

    event_tools.insertEventAfter(flowchart, 'Event7', 'Event47')

    fork = event_tools.findEvent(flowchart, 'Event47')
    fork.data.forks.pop(1)



def grandmaYahooChanges(flowchart, item_info):
    item_key, item_index = item_info
    item_get.insertItemGetAnimation(flowchart, item_key, item_index, 'Event54', 'Event33')

    broom_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': 'TradeBroomGet'}, {0: 'Event69', 1: 'Event79'})

    event_tools.insertEventAfter(flowchart, 'Event11', 'Event0')

    event_tools.setSwitchEventCase(flowchart, 'Event0', 0, broom_check)

    event_tools.insertEventAfter(flowchart, 'Event81', 'Event53')

    fork = event_tools.findEvent(flowchart, 'Event53')
    fork.data.forks.pop(1)



def fishermanChanges(flowchart, item_info):
    item_key, item_index = item_info
    item_get.insertItemGetAnimation(flowchart, item_key, item_index, 'Event28', 'Event42')

    event0 = event_tools.findEvent(flowchart, 'Event0')
    event2 = event_tools.findEvent(flowchart, 'Event2')
    event2.data.actor = event0.data.actor
    event2.data.actor_query = event0.data.actor_query
    event2.data.params.data = {'symbol': 'TradeFishingHookGet'}

    event_tools.insertEventAfter(flowchart, 'Event32', 'Event33')

    fork = event_tools.findEvent(flowchart, 'Event27')
    fork.data.forks.pop(1)



def mermaidChanges(flowchart, item_info):
    item_key, item_index = item_info
    item_get.insertItemGetAnimation(flowchart, item_key, item_index, 'Event73', 'Event55')

    event0 = event_tools.findEvent(flowchart, 'Event0')
    event2 = event_tools.findEvent(flowchart, 'Event2')
    event2.data.actor = event0.data.actor
    event2.data.actor_query = event0.data.actor_query
    event2.data.params.data = {'symbol': 'TradeNecklaceGet'}

    fork = event_tools.findEvent(flowchart, 'Event71')
    fork.data.forks.pop(1)



def statueChanges(flowchart):
    scale_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': 'TradeMermaidsScaleGet'}, {0: 'Event28', 1: 'Event32'})
    event_tools.setSwitchEventCase(flowchart, 'Event3', 0, scale_check)
