"""Opt-in world visuals using the original shell's NPC component constructor.

No room, actor type, spawn parameter, event or inventory changes. NPC clones
retain shell behavior/collision and take only graphics path/model/drsb from the
assigned item's clean definition. Native delivery remains independent.
"""
from pathlib import Path
import json
import hashlib

def stage(mod,clean_romfs,checks,plan_digest):
    from RandomizerCore.Tools import oead_tools as o
    mod=Path(mod);clean=Path(clean_romfs);relative=Path('region_common/datasheets/Npc.gsheet')
    incoming=mod/'romfs'/relative
    sheet=o.readSheet(incoming if incoming.exists() else clean/relative)
    preserved={p.relative_to(mod/'romfs').as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
               for p in (mod/'romfs').rglob('*') if p.is_file() and p!=incoming}
    import oead
    baseline=oead.gsheet.Sheet()
    for field in ('alignment','hash','name','root_fields'):setattr(baseline,field,sheet[field])
    baseline.values=oead.gsheet.StructArray(list(sheet['values']))
    original_count=len(baseline.values)
    original_digest=hashlib.sha256(baseline.to_binary()).hexdigest()
    originals=o.readSheet(clean/relative)
    stock=next(r for r in originals['values'] if r['symbol']=='ItemSecretSeashell')
    records=[];unsupported=[];seen=set()
    for check in checks:
        if check.get('native_id',22)!=22:continue # Heart-piece behavior is separate.
        identity=(22,check['index'])
        if identity in seen:raise ValueError('Duplicate shell visual identity')
        seen.add(identity)
        candidates=[r for r in originals['values'] if r['graphics']['path']==check['model_path']
                    and r['graphics']['model']==check['model_name']]
        if not candidates:
            unsupported.append({'location':check['location'],'reason':'No matching clean NPC graphics definition; stock visual retained'})
            continue
        target=candidates[0]
        safe=True
        for folder,name in (('actor',target['graphics']['path']),('tailor',target['graphics']['drsb'])):
            if not name:continue
            if Path(name).name!=name or not (clean/'region_common'/folder/name).is_file():safe=False
        if not safe:
            unsupported.append({'location':check['location'],'reason':'Missing or unsafe graphics resource; stock visual retained'})
            continue
        key=f'AP_WorldShell_22_{check["index"]}'
        if any(r['symbol']==key for r in sheet['values']):raise ValueError('Visual definition already exists')
        clone=o.parseStruct(stock);clone['symbol']=key
        for field in ('path','model','drsb'):clone['graphics'][field]=target['graphics'][field]
        sheet['values'].append(o.dictToStruct(clone))
        records.append({**check,'native_id':22,'npc_key':key,'drsb':target['graphics']['drsb']})
    incoming.parent.mkdir(parents=True,exist_ok=True);o.writeSheet(incoming,sheet)
    result={'schema_version':1,'mode':'original_shell_npc_component_experimental','plan_digest':plan_digest,
            'checks':records,'unsupported':unsupported,'live_family_validation_complete':False,
            'actor_data_unchanged':True,'heart_piece_visuals_enabled':False}
    result.update(preserved_file_hashes=preserved,original_npc_count=original_count,original_npc_digest=original_digest)
    (mod/'native-world-visual-plan.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result
