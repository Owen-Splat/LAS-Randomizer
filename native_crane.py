# Adapter details derived in part from LASRecomp (MIT); see vendor/LASRecomp-LICENSE.txt.
"""Randomized featured prizes, keeping their vanilla slots and instrument gates."""
from copy import deepcopy
from pathlib import Path


def stage(mod,clean_romfs,contract):
    from RandomizerCore.Tools import oead_tools as o,event_tools as e
    from native_display import _redirect
    selected={d['location']:d for d in contract['native_display_plan']['displays'] if d['location'].startswith('trendy-prize-')}
    if 'trendy-prize-1' not in selected:return []
    base=Path(mod)/'romfs';clean=Path(clean_romfs)
    def read(rel):return base/rel if (base/rel).is_file() else clean/rel
    def write(rel):
        path=base/rel;path.parent.mkdir(parents=True,exist_ok=True);return path
    sheet=o.readSheet(read('region_common/datasheets/CranePrize.gsheet'))
    rows=[o.parseStruct(r) for r in sheet['values']]
    original={r['symbol']:r for r in rows}
    checks=contract['native_check_plan']['checks'];bit_base=1696 if len(checks)>228 else 1808
    ordinals={r['location']:r['ordinal'] for r in checks}
    mappings=[('YoshiDoll',0),('HeartPiece',0),('SecretSeashell',0),('PanelDungeonPiece',0),('HeartPiece',1),('SecretSeashell',1)]
    flags=o.readSheet(read('region_common/datasheets/GlobalFlags.gsheet'))
    used={int(r['index']) for r in flags['values']}
    disabled='AP_CraneOriginalOff'
    flags['values'].append(o.dictToStruct({'symbol':disabled,'index':next(i for i in range(1217,1248) if i not in used)}))
    new=[];by_place={}
    for i,(symbol,layout) in enumerate(mappings,1):
        name='trendy-prize-'+str(i);d=selected[name]
        flag='AP_CheckFlag_'+str(d['location_id'])
        flags['values'].append(o.dictToStruct({'symbol':flag,'index':bit_base+ordinals[name]}))
        row=deepcopy(original[symbol]);row['layouts']=[deepcopy(row['layouts'][layout])]
        place=tuple(row['layouts'][0]['place'][k] for k in ('type','index'))
        conditions=row['layouts'][0]['conditions']
        # Collection is independent of which items AP has delivered.
        conditions=[c for c in conditions if c.get('parameter')!='!TradeYoshiDollGet']
        conditions.append({'category':1,'parameter':'!'+flag})
        if place in by_place:conditions.append({'category':1,'parameter':by_place[place][-1]})
        by_place.setdefault(place,[]).append(flag)
        row['layouts'][0].update(itemIndex=d['marker'],conditions=conditions)
        definition=contract['item_defs'][d['key']]
        model=definition['model-name'];code=str(i).zfill(len(model)-2)
        if len(model)<3 or len(code)!=len(model)-2:raise ValueError('Unsupported crane model name')
        unique='A'+code+model[-1]
        raw=read('region_common/actor/'+definition['model-path']).read_bytes()
        pattern=len(model).to_bytes(2,'little')+model.encode()+b'\0'
        if raw.count(pattern)!=1:raise ValueError('Ambiguous crane model rename: '+model)
        raw=raw.replace(pattern,len(unique).to_bytes(2,'little')+unique.encode()+b'\0')
        write('region_common/actor/Prize'+unique+'.bfres').write_bytes(raw)
        row.update(symbol=unique,getCount=1)
        row['getEvent']['messageEntry']=d['key']
        row['options']['isFeatured']=False
        row['options']['isAutoSave']=False
        new.append(row)
    # Remove the old featured layouts. Generic prizes return after all AP
    # prizes at their position have been won; unrelated figures remain vanilla.
    old_symbols={m[0] for m in mappings}
    for row in rows:
        if row['symbol'] in old_symbols:
            for layout in row['layouts']:
                layout['conditions'].append({'category':1,'parameter':disabled})
        elif not row['options']['isFeatured']:
            for layout in row['layouts']:
                place=tuple(layout['place'][k] for k in ('type','index'))
                if place in by_place:
                    layout['conditions']=[c for c in layout['conditions'] if c.get('parameter')!='TradeYoshiDollGet']
                    layout['conditions'].append({'category':1,'parameter':by_place[place][-1]})
    # Preserve original row indexes (the vanilla AddPrize function uses them).
    sheet['values']=o.listToSheetArray('values',rows+new)
    o.writeSheet(write('region_common/datasheets/CranePrize.gsheet'),sheet)
    o.writeSheet(write('region_common/datasheets/GlobalFlags.gsheet'),flags)
    flow=e.readFlow(read('region_common/event/PrizeCommon.bfevfl'));fc=flow.flowchart
    old=e.findEvent(fc,'Event0');originals=list(fc.events);chain=old.name
    after=e.findEvent(fc,'Event1').data.nxt.v.name
    for i in range(6,0,-1):
        d=selected['trendy-prize-'+str(i)]
        give=e.createActionChain(fc,None,[
            ('Link','GenericItemGetSequenceByKey',{'itemKey':d['key'],'messageEntry':d['key'],'keepCarry':False}),
            ('Inventory','AddItemByKey',{'itemKey':'HookShot','index':d['marker'],'count':1,'autoEquip':False})],after)
        chain=e.createSwitchEvent(fc,'FlowControl','CompareInt',{'value1':'itemIndex','value2':d['marker']},{0:give,1:chain})
    _redirect(fc,old,e.findEvent(fc,chain),originals)
    e.writeFlow(write('region_common/event/PrizeCommon.bfevfl'),flow)
    verify=o.readSheet(read('region_common/datasheets/CranePrize.gsheet'))
    if len(verify['values'])!=27 or any(not len(r['layouts']) for r in verify['values']):
        raise ValueError('Crane prize rows must retain nonempty layouts')
    return ['trendy-prize-'+str(i) for i in range(1,7)]
