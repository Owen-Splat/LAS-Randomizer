"""Actual seed-item presentation with neutral, suppressed physical rewards.

Each display key has its own model/message and a display-only native item ID.
Inventory grants use a separate neutral marker, suppressed by the native hook.
"""
from copy import deepcopy
import json
from pathlib import Path
import textwrap
import struct

GAME="Link's Awakening (Switch)"


def install_message(messages, key, text):
    # Match the vanilla item dialog's button-wait command and attributes.
    # Plain strings finish immediately, closing the box before it can be read.
    template='GetOcarina'
    suffix=b'\x0e\x01\x00\x04\x00\x00\x00'
    raw=text.encode('utf-8')+suffix+b'\0'
    messages.set(key,raw)
    if messages.atr is not None:
        _,size=struct.unpack_from('<II',messages.atr)
        source=8+messages.labels[template]*size
        target=8+messages.labels[key]*size
        attributes=messages.atr[source:source+size]
        messages.atr=messages.atr[:target]+attributes+messages.atr[target+size:]
    return raw


def prepare(contract):
    result=deepcopy(contract)
    manifest=result['native_config']['manifest']
    markers={r['location']:r['marker'] for r in result['native_check_plan']['checks']}
    subtypes={r['location']:r['subtype'] for r in result['native_config']['actions']}
    names=manifest.get('player_names',{})
    displays=[]
    for row in manifest['placements']:
        key=f"AP_Check_{row['location_id']}"
        native=row['item_game']==GAME
        definition=result['item_defs'].get(row['item_name']) if native else None
        usable=definition and all(definition.get(k) for k in ('model-path','model-name','npc-key')) and not row['item_name'].endswith('-trap') and row['item_name']!='stalfos-note'
        if usable:
            display=deepcopy(definition);display_key=definition['item-key']
        else:
            display=deepcopy(result['item_defs']['rupee-5'])
            display.update({'model-path':'ItemRupeeGreen.bfres','model-name':'RupeeGreen',
                            'npc-key':'ItemRupeeGreen','type':'important'})
            display_key='Rupee1'
        display['item-key']=key;display['quantity']=1
        result['item_defs'][key]=display
        result['placements'][row['location']]=key
        recipient=names.get(str(row['recipient_slot']))
        if not recipient:
            recipient=manifest['identity']['slot_name'] if row['recipient_slot']==manifest['identity']['slot'] else f"Player {row['recipient_slot']}"
        label=row['item_name'].replace('-',' ').replace('_',' ')
        item=''.join(c if ord(c)>=32 else ' ' for c in label)[:120]
        player=''.join(c if ord(c)>=32 else ' ' for c in recipient)[:64]
        message='\n'.join(textwrap.wrap(item,32)+textwrap.wrap('For '+player,32))
        displays.append({**row,'key':key,'marker':markers[row['location']],
                         'subtype':subtypes[row['location']],
                         'display_key':display_key,'fallback_model':not usable,
                         'npc_key':display['npc-key'],'message':message})
    reserved=set(range(230,240)) if any(d['subtype']=='shop' for d in displays) else set()
    available=[i for i in [*range(132,200),*range(203,254)] if i not in reserved]
    styles=sorted({d['display_key'] for d in displays})
    if len(styles)>len(available):raise ValueError('Too many distinct game display styles')
    visual_ids=dict(zip(styles,available))
    for display in displays:display['visual_id']=visual_ids[display['display_key']]
    result['native_display_plan']={'schema_version':1,'foreign_model':'GREG (green rupee)',
                                   'manifest_digest':manifest['manifest_digest'],'displays':displays}
    return result


def _redirect(flowchart,old,new,originals):
    from RandomizerCore.Tools import event_tools
    indexes=event_tools.invertList(flowchart.events)
    refs=[ep.main_event for ep in flowchart.entry_points]
    for event in originals:
        data=event.data
        if hasattr(data,'nxt'):refs.append(data.nxt)
        if hasattr(data,'forks'):refs.extend(data.forks)
        if hasattr(data,'cases'):refs.extend(data.cases.values())
    for ref in refs:
        if ref.v is old:ref.v=new;ref.set_index(indexes)


def stage(mod,clean_romfs,plan):
    from RandomizerCore.Tools import event_tools,oead_tools
    from vendor.msbt import Msbt
    mod,clean_romfs=map(Path,(mod,clean_romfs))
    sheet_path=mod/'romfs/region_common/datasheets/Items.gsheet'
    sheet=oead_tools.readSheet(sheet_path)
    # The native vector can reallocate when appending. Snapshot rows into Python
    # values before growing it; retaining Struct views would leave dangling refs.
    rows={r['symbol']:oead_tools.parseStruct(r) for r in sheet['values']}
    neutral=deepcopy(rows['HookShot'])
    for display in plan['displays']:
        if display['key'] in rows:raise ValueError('Duplicate AP display key')
        visual=deepcopy(rows[display['display_key']])
        proxy=deepcopy(neutral)
        for field in ('npcKey','jingle','actorID','tailor'):
            if field in visual:proxy[field]=deepcopy(visual[field])
        proxy.update(symbol=display['key'],itemID=display['visual_id'],gettingFlag='')
        proxy['npcKey']=visual.get('npcKey') or display['npc_key']
        sheet['values'].append(oead_tools.dictToStruct(proxy))
    oead_tools.writeSheet(sheet_path,sheet)
    # High display-only IDs select the requested model without enabling a vanilla
    # progressive/quest reward path. Every physical inventory grant stays neutral.
    marker_keys={d['marker']:d for d in plan['displays']}
    neutralized=0
    for path in (mod/'romfs/region_common/event').glob('*.bfevfl'):
        asset=event_tools.readFlow(path);changed=False
        for event in asset.flowchart.events:
            data=event.data;params=getattr(data,'params',None)
            if (hasattr(data,'actor_action') and data.actor.v.identifier.name=='Inventory' and
                data.actor_action.v.v=='AddItemByKey' and params and
                type(params.data.get('index')) is int and params.data['index'] in marker_keys):
                params.data['itemKey']='HookShot';changed=True;neutralized+=1
        if changed:event_tools.writeFlow(path,asset)
    item_path=mod/'romfs/region_common/event/Item.bfevfl'
    flow=event_tools.readFlow(item_path)
    for display in plan['displays']:
        event_tools.addEntryPoint(flow.flowchart,display['key'])
        dialog=event_tools.createActionEvent(flow.flowchart,'Dialog','Show',{'message':'System:'+display['key']})
        event_tools.insertEventAfter(flow.flowchart,display['key'],dialog)
    event_tools.writeFlow(item_path,flow)
    locales=[]
    for original in sorted(clean_romfs.rglob('System.msbt')):
        relative=original.relative_to(clean_romfs);destination=mod/'romfs'/relative
        data=Msbt(destination.read_bytes() if destination.is_file() else original.read_bytes())
        if data.enc!=0 or data.version!=3:raise ValueError('Unsupported message encoding/version')
        expected={display['key']:install_message(data,display['key'],display['message']) for display in plan['displays']}
        destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(data.pack())
        verify=Msbt(destination.read_bytes())
        for display in plan['displays']:
            if verify.texts[display['key']]!=expected[display['key']]:raise ValueError('AP message round trip failed')
        locales.append(relative.as_posix())
    if not locales:raise ValueError('No game message files found for AP item display')
    # Shared flows retain only an item ID and index. Route by physical marker so
    # duplicate visual styles still show this check's message and neutral grant.
    def routes(fc,old_name,selected,after):
        old=event_tools.findEvent(fc,old_name);originals=list(fc.events);chain=old.name
        for display in reversed(selected):
            give=event_tools.createActionEvent(fc,'Inventory','AddItemByKey',
                {'itemKey':'HookShot','count':1,'index':display['marker'],'autoEquip':False},after)
            show=event_tools.createActionEvent(fc,'Link','GenericItemGetSequenceByKey',
                {'itemKey':display['key'],'keepCarry':False,'messageEntry':display['key']},give)
            chain=event_tools.createSwitchEvent(fc,'FlowControl','CompareInt',
                {'value1':'itemIndex','value2':display['marker']},{0:show,1:chain})
        if selected:_redirect(fc,old,event_tools.findEvent(fc,chain),originals)
    chest_path=mod/'romfs/region_common/event/TreasureBox.bfevfl'
    chest=event_tools.readFlow(chest_path)
    chest_rows=[d for d in plan['displays'] if d['subtype']=='chest']
    for event_name,give_name in (('Event0','Event5'),('Event35','Event25')):
        give=event_tools.findEvent(chest.flowchart,give_name)
        after=give.data.nxt.v.name if give.data.nxt.v else None
        routes(chest.flowchart,event_name,chest_rows,after)
    event_tools.writeFlow(chest_path,chest)
    present_path=mod/'romfs/region_common/event/ShellMansionPresent.bfevfl'
    present=event_tools.readFlow(present_path);fc=present.flowchart
    gifts=[d for d in plan['displays'] if d['location'].endswith('-seashell-reward') and not d['location'].startswith('40-')]
    routes(fc,'Event4',gifts,'Event0')
    routes(fc,'Event11',gifts,'Event0')
    event_tools.writeFlow(present_path,present)
    verify=oead_tools.readSheet(sheet_path)
    by_key={r['symbol']:r for r in verify['values']}
    for display in plan['displays']:
        row=by_key[display['key']]
        if row['itemID']!=display['visual_id'] or row['gettingFlag'] or not row['npcKey']:
            raise ValueError('AP display row lost its neutral reward semantics')
    report={'schema_version':1,'display_count':len(plan['displays']),'locales':locales,
            'foreign_model':plan['foreign_model'],'present_routes':len(gifts),
            'neutral_inventory_grants':neutralized,'chest_routes':len(chest_rows)*2,
            'live_presentation_verified':False}
    (mod/'native-display-report.json').write_text(json.dumps(report,indent=2))
    return report
