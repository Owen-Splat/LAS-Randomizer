import evfl

idgen = evfl.util.IdGenerator()


def invertList(l):
	"""Converts a list into a dict of {value: index} pairs"""
	return {l[i]: i for i in range(len(l))}


def readFlow(evflFile):
	"""Reads the flow from the eventflow file and returns it"""
	
	flow = evfl.EventFlow()
	with open(evflFile, 'rb') as file:
		flow.read(file.read())

	return flow


def writeFlow(evflFile, flow):
	"""Writes the given flow to a new eventflowfile"""
	with open(evflFile, 'wb') as modified_file:
		flow.write(modified_file)


def findEvent(flowchart, name):
	"""Finds and returns an event from a flowchart given a name as a string. Returns None if not found"""

	if name == None:
		return

	for event in flowchart.events:
		if event.name == name:
			return event

	return None


def findEntryPoint(flowchart, name):
	"""Finds and returns an entry point from a flowchart given a name as a string. Returns None if not found"""

	if name == None:
		return

	for ep in flowchart.entry_points:
		if ep.name == name:
			return ep

	return None


def findActor(flowchart, name, sub_name=''):
	"""Finds and returns an actor from a flowchart given a name and an optional sub_name as a string
	
	If the actor does not exist, it is created and then returned"""

	identifier = evfl.ActorIdentifier(name, sub_name)
	try:
		return flowchart.find_actor(identifier)
	except ValueError:
		act = evfl.Actor()
		act.identifier = evfl.ActorIdentifier(name, sub_name)
		flowchart.actors.append(act)
		return flowchart.find_actor(act.identifier)	


def addActorAction(actor, action):
	"""Appends an action to the actor in the flowchart"""

	has_action = False
	for act in actor.actions:
		if act.v == action:
			has_action = True
			break
	if not has_action:
		actor.actions.append(evfl.common.StringHolder(action))


def addActorQuery(actor, query):
	"""Appends a query to an actor in the flowchart"""

	has_query = False
	for que in actor.queries:
		if que.v == query:
			has_query = True
			break
	
	if not has_query:
		actor.queries.append(evfl.common.StringHolder(query))


def addEntryPoint(flowchart, name):
	"""Appends an entry point to the flowchart"""
	flowchart.entry_points.append(evfl.entry_point.EntryPoint(name))


def insertEventAfter(flowchart, previous, new):
	"""Change the previous event or entry point to have {new} be the next event 
	{previous} is the name of the event/entry point, {new} is the name of the event to add 
	Return True if any event or entry point was modified and False if not"""

	newEvent = findEvent(flowchart, new)

	prevEvent = findEvent(flowchart, previous)
	if prevEvent:
		prevEvent.data.nxt.v = newEvent
		prevEvent.data.nxt.set_index(invertList(flowchart.events))

		return True

	entry_point = findEntryPoint(flowchart, previous)
	if entry_point:
		entry_point.main_event.v = newEvent
		entry_point.main_event.set_index(invertList(flowchart.events))
		return True

	return False


def setSwitchEventCase(flowchart, switch, case, new):
	"""Changes the specified case in a switch event into the new event"""

	newEvent = findEvent(flowchart, new)

	switchEvent = findEvent(flowchart, switch)
	if switchEvent:
		switchEvent.data.cases[case].v = newEvent
		switchEvent.data.cases[case].set_index(invertList(flowchart.events))

		return True

	return False


def removeEventAfter(flowchart, eventName):
	"""Removes the next event from the specified event, so that there is nothing after it in the flow"""

	event = findEvent(flowchart, eventName)
	if not event:
		print('Not an event!')
		return

	event.data.nxt.v = None
	event.data.nxt.set_index(invertList(flowchart.events))


def insertActionChain(flowchart, before, events):
	"""Inserts a chain of action events after a specified event. Returns if there are no events in the chain"""

	if len(events) == 0:
		return

	insertEventAfter(flowchart, before, events[0])

	for i in range(1, len(events)):
		insertEventAfter(flowchart, events[i-1], events[i])


def createActionChain(flowchart, before, eventDefs, after=None):
	"""Create a series of action events in order after {before} and followed by {after} 
	Return the name of the first event in the chain"""
	if len(eventDefs) == 0:
		return
	
	next = after if len(eventDefs) == 1 else None
	first = createActionEvent(flowchart, eventDefs[0][0], eventDefs[0][1], eventDefs[0][2], next)
	current = first
	insertEventAfter(flowchart, before, current)

	for i in range(1, len(eventDefs)):
		next = None if i != len(eventDefs)-1 else after
		before = current
		current = createActionEvent(flowchart, eventDefs[i][0], eventDefs[i][1], eventDefs[i][2], after)
		insertEventAfter(flowchart, before, current)

	return first


def createProgressiveItemSwitch(flowchart, item1, item2, flag, before=None, after=None):
	"""Create a switch event leading to getting one of two options depending on whether a flag was set beforehand"""

	item1GetSeqEvent = createActionEvent(flowchart, 'Link', 'GenericItemGetSequenceByKey',
		{'itemKey': item1, 'keepCarry': False, 'messageEntry': ''}, after)
	item1AddEvent = createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
		{'itemKey': item1, 'count': 1, 'index': -1, 'autoEquip': False}, item1GetSeqEvent)

	item2GetSeqEvent = createActionEvent(flowchart, 'Link', 'GenericItemGetSequenceByKey',
		{'itemKey': item2, 'keepCarry': False, 'messageEntry': ''}, after)
	item2AddEvent = createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
		{'itemKey': item2, 'count': 1, 'index': -1, 'autoEquip': False}, item2GetSeqEvent)
	
	flagSetEvent = createActionEvent(flowchart, 'EventFlags', 'SetFlag',
		{'symbol': flag, 'value': True}, item1AddEvent)
	flagCheckEvent = createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
		{'symbol': flag}, {0: flagSetEvent, 1: item2AddEvent})

	insertEventAfter(flowchart, before, flagCheckEvent)

	return flagCheckEvent


def createActionEvent(flowchart, actor, action, params, nextev=None):
	"""Creates a new action event. {actor} and {action} should be strings, {params} should be a dict 
	{nextev} is the name of the next event"""

	act = findActor(flowchart, actor)
	addActorAction(act, action)
	
	nextEvent = findEvent(flowchart, nextev)

	if '[' in actor:
		actor = actor.replace(']', '')
		names = actor.split('[')
		act = evfl.ActorIdentifier(names[0], names[1])
	else:
		act = evfl.ActorIdentifier(actor)
	
	new = evfl.event.Event()
	new.data = evfl.event.ActionEvent()
	new.data.actor = evfl.util.make_rindex(flowchart.find_actor(act))
	new.data.actor.set_index(invertList(flowchart.actors))
	new.data.actor_action = evfl.util.make_rindex(new.data.actor.v.find_action(action))
	new.data.actor_action.set_index(invertList(new.data.actor.v.actions))
	new.data.params = evfl.container.Container()
	new.data.params.data = params

	flowchart.add_event(new, idgen)

	if nextEvent:
		new.data.nxt.v = nextEvent
		new.data.nxt.set_index(invertList(flowchart.events))

	return new.name


def createSwitchEvent(flowchart, actor, query, params, cases):
	"""Creates a new switch event and adds it to the flowchart 
	{actor} and {query} should be strings, {params} should be a dict, {cases} is a dict if {int: event name}"""

	act = findActor(flowchart, actor)
	addActorQuery(act, query)

	new = evfl.event.Event()
	new.data = evfl.event.SwitchEvent()
	new.data.actor = evfl.util.make_rindex(flowchart.find_actor(evfl.common.ActorIdentifier(actor)))
	new.data.actor.set_index(invertList(flowchart.actors))
	new.data.actor_query = evfl.util.make_rindex(new.data.actor.v.find_query(query))
	new.data.actor_query.set_index(invertList(new.data.actor.v.queries))
	new.data.params = evfl.container.Container()

	if "value1" in params:
		params["value1"] = evfl.common.Argument(params["value1"])
	new.data.params.data = params

	flowchart.add_event(new, idgen)

	caseEvents = {}
	for case in cases:
		ev = findEvent(flowchart, cases[case])
		if ev:
			caseEvents[case] = evfl.util.make_rindex(ev)
			caseEvents[case].set_index(invertList(flowchart.events))

	new.data.cases = caseEvents

	return new.name


def createSubFlowEvent(flowchart, refChart, entryPoint, params, nextev=None):
	"""Creates a new subflow event and insert it into the flow 
	{nextev} is the name of the next event"""

	nextEvent = findEvent(flowchart, nextev)

	new = evfl.event.Event()
	new.data = evfl.event.SubFlowEvent()
	new.data.params = evfl.container.Container()
	new.data.params.data = params
	new.data.res_flowchart_name = refChart
	new.data.entry_point_name = entryPoint

	flowchart.add_event(new, idgen)

	if nextEvent:
		new.data.nxt.v = nextEvent
		new.data.nxt.set_index(invertList(flowchart.events))

	return new.name


def createForkEvent(flowchart, before, forks, nextev=None):
	"""Creates a new fork event and inserts it into the flow"""

	new = evfl.event.Event()
	new.data = evfl.event.ForkEvent()

	joinEvent = createJoinEvent(flowchart, nextev)
	new.data.join = evfl.util.make_rindex(joinEvent)
	new.data.join.set_index(invertList(flowchart.events))

	flowchart.add_event(new, idgen)
	
	if before != None:
		insertEventAfter(flowchart, before, new.name)

	forkEvents = []
	for branch in forks:
		ev = findEvent(flowchart, branch)
		if ev:
			fork = evfl.util.make_rindex(ev)
			fork.set_index(invertList(flowchart.events))
			forkEvents.append(fork)

	new.data.forks = forkEvents

	return new.name, joinEvent.name


def createJoinEvent(flowchart, nextev=None):
	"""creates a new join event and inserts it into the flow"""

	nextEvent = findEvent(flowchart, nextev)

	new = evfl.event.Event()
	new.data = evfl.event.JoinEvent()

	flowchart.add_event(new, idgen)

	if nextEvent:
		new.data.nxt.v = nextEvent
		new.data.nxt.set_index(invertList(flowchart.events))

	return new


def setForkEventFork(flowchart, forkevent, fork, new):
	"""Changes the specified fork in the forkevent to be {new}"""

	newEvent = findEvent(flowchart, new)

	forkEvent = findEvent(flowchart, forkevent)
	if forkEvent:
		forkEvent.data.forks[forkEvent.data.forks.index(fork)].v = newEvent
		forkEvent.data.forks[forkEvent.data.forks.index(fork)].set_index(invertList(flowchart.events))

		return True

	return False


def addForkEventForks(flowchart, forkevent, forks):
	"""Adds new forks to the forkevent"""

	forkEvent = findEvent(flowchart, forkevent)

	forkEvents = forkEvent.data.forks
	for branch in forks:
		ev = findEvent(flowchart, branch)
		if ev:
			fork = evfl.util.make_rindex(ev)
			fork.set_index(invertList(flowchart.events))
			forkEvents.append(fork)
	
	forkEvent.data.forks = forkEvents


def setEventSong(flowchart, event_name, song):
	findEvent(flowchart, event_name).data.params.data['label'] = song
