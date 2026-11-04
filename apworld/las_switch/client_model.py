"""UI-independent status, delivered-item history and logic tracker models."""
from collections import Counter
from .core.data import ITEM_IDS,CATEGORIES,GAME
from .core.logic import Logic
from .core.runtime import next_actions

ITEM_NAMES={value:name for name,value in ITEM_IDS.items()}

def display_name(value):return str(value).replace('-',' ').replace('_',' ').title()

def snapshot(ctx):
    state=ctx.bridge.state or {}
    checked=set(ctx.checked_locations)&{r['location_id'] for r in ctx.manifest['placements']}
    local=set(state.get('checks',()))
    cursor=state.get('cursor',0)
    valid=False
    if ctx.ap_validated and ctx.history_ready and state:
        try:valid=not next_actions(ctx.manifest,state,ctx.items_received,ctx.checked_locations)['sync_required']
        except (ValueError,TypeError):pass
    valid_cursor=cursor if valid else 0
    history=[]
    for index,item in reversed(list(enumerate(ctx.items_received))[-50:]):
        history.append({'item':display_name(ITEM_NAMES.get(item.item,str(item.item))),
                        'sender':'Starting items' if item.location==-2 else ctx.player_names.get(item.player,'Archipelago' if item.player==0 else 'Player '+str(item.player)),
                        'delivered':valid and index<cursor,'index':index+1})
    inventory=Counter(ITEM_NAMES[item.item] for item in ctx.items_received[:valid_cursor] if item.item in ITEM_NAMES)
    if not hasattr(ctx,'tracker_logic'):
        m=ctx.manifest
        ctx.tracker_logic=Logic(m['profile'],m.get('location_categories'),m.get('player_settings'),m.get('dungeon_entrances'))
    tracker=[]
    for row in ctx.manifest['placements']:
        done=row['location_id'] in checked or row['location_id'] in local
        reachable=valid and ctx.tracker_logic.can_reach(inventory,row['location'])
        tracker.append({'location':display_name(row['location']), 'category':display_name(CATEGORIES[row['location']]),
                        'checked':done,'reachable':reachable,'id':row['location_id']})
    if not ctx.bridge.writer:game='Disconnected'
    elif not state:game='Connecting'
    elif state.get('alive') is False:game='Defeated'
    elif state.get('ready'):game='Playing'
    else:game='Loading or busy'
    return {'room':'Connected' if ctx.ap_validated else 'Disconnected or validating',
            'game':game,'pending':max(0,len(ctx.items_received)-cursor) if valid else None,
            'checked':len(checked),'local_pending_checks':len(local-checked),
            'total':len(ctx.manifest['placements']),'history':history,'tracker':tracker,
            'error':ctx.last_error,'history_validated':valid,
            'deathlink':bool(ctx.death_link_enabled and 'DeathLink' in ctx.tags)}
