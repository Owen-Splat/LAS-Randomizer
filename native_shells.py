"""Native indexed pickups: preserve stock actors and route their item-get flow.

Hidden/buried/bomb-hole shells and seven underwater pickups retain vanilla
world models and behaviour. Their held-up item model/message is the AP reward.
"""
from pathlib import Path
import json


def stage(mod,clean_romfs,contract):
    from RandomizerCore.Tools import event_tools as e
    from native_display import _redirect
    from native_underwater import SPOTS
    nodes=json.loads((Path(__file__).parent/'apworld/las_switch/core/catalog.json').read_text())['logic_nodes']
    displays=[d for d in contract['native_display_plan']['displays'] if d['subtype'] in ('dig','hidden','bomb-hole') or d['location'] in SPOTS]
    if not displays:return []
    base=Path(mod)/'romfs';clean=Path(clean_romfs)
    def read(rel):return base/rel if (base/rel).is_file() else clean/rel
    def write(rel):
        p=base/rel;p.parent.mkdir(parents=True,exist_ok=True);return p
    checks=contract['native_check_plan']['checks'];ordinals={c['location']:c['ordinal'] for c in checks}
    rows=[]
    for d in displays:
        node=nodes[d['location']]
        if node['content'] not in ('seashell','heart-piece'):raise ValueError('Unsupported native indexed pickup')
        definition=contract['item_defs'][d['key']]
        rows.append({'location':d['location'],'native_id':22 if node['content']=='seashell' else 58,
                     'index':node['index'],'ordinal':ordinals[d['location']],
                     'model_path':definition['model-path'],'model_name':definition['model-name']})
    flow=e.readFlow(read('region_common/event/ItemCommon.bfevfl'));fc=flow.flowchart
    old=e.findEvent(fc,'Event0');originals=list(fc.events)
    after=e.findEvent(fc,'Event1').data.nxt.v.name
    chains={'seashell':old.name,'heart-piece':old.name}
    for d in reversed(displays):
        node=nodes[d['location']];kind=node['content']
        give=e.createActionChain(fc,None,[
            ('Link','GenericItemGetSequenceByKey',{'itemKey':d['key'],'messageEntry':d['key'],'keepCarry':False}),
            ('Inventory','AddItemByKey',{'itemKey':'HookShot','count':1,'index':d['marker'],'autoEquip':False})],after)
        chains[kind]=e.createSwitchEvent(fc,'FlowControl','CompareInt',{'value1':'itemIndex','value2':node['index']},{0:give,1:chains[kind]})
    chain=old.name
    for kind,key in (('seashell','Seashell'),('heart-piece','HeartPiece')):
        chain=e.createSwitchEvent(fc,'FlowControl','CompareString',{'value1':'itemKey','value2':key},{0:chains[kind],1:chain})
    _redirect(fc,old,e.findEvent(fc,chain),originals)
    e.writeFlow(write('region_common/event/ItemCommon.bfevfl'),flow)
    (Path(mod)/'native-shell-plan.json').write_text(json.dumps({'plan_digest':contract['native_check_plan']['digest'],'checks':rows,'physical_model_mode':'vanilla_indexed_actors'},indent=2))
    return rows
