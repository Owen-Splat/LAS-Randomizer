"""Validate opt-in visual metadata against generated NPCs and AP identities."""
import json
from pathlib import Path
import oead

def validate(mod_romfs,clean_romfs,plan,shell_rows):
    mod=Path(mod_romfs);clean=Path(clean_romfs)
    data=json.loads((mod.parent/'native-world-visual-plan.json').read_text())
    if data.get('schema_version')!=1 or data.get('mode')!='original_shell_npc_component_experimental' or data.get('plan_digest')!=plan['digest']:
        raise ValueError('World visual plan identity/mode mismatch')
    sheet=oead.gsheet.parse(oead.Bytes((mod/'region_common/datasheets/Npc.gsheet').read_bytes()))
    original=oead.gsheet.parse(oead.Bytes((clean/'region_common/datasheets/Npc.gsheet').read_bytes()))
    stock=next(r for r in original.values if r['symbol']=='ItemSecretSeashell')
    allowed={(r.get('native_id',22),r['index']):r for r in shell_rows}
    seen=set();records=[]
    for row in data['checks']:
        identity=(row['native_id'],row['index']);source=allowed.get(identity)
        if identity in seen or identity[0]!=22 or not source:raise ValueError('Unknown/duplicate shell visual source')
        seen.add(identity)
        for field in ('location','ordinal','model_path','model_name'):
            if row[field]!=source[field]:raise ValueError('Shell visual differs from assigned source/reward')
        key=f'AP_WorldShell_22_{row["index"]}'
        if row.get('npc_key')!=key:raise ValueError('Unexpected NPC visual key')
        found=[r for r in sheet.values if r['symbol']==key]
        if len(found)!=1:raise ValueError('Missing/duplicate generated NPC visual definition')
        npc=found[0]
        for field in stock:
            if field not in ('symbol','graphics') and npc[field]!=stock[field]:
                raise ValueError('NPC visual changed original pickup behavior')
        for field in stock['graphics']:
            if field not in ('path','model','drsb') and npc['graphics'][field]!=stock['graphics'][field]:
                raise ValueError('NPC visual changed unreviewed graphics behavior')
        for field,expected in (('path',row['model_path']),('model',row['model_name']),('drsb',row['drsb'])):
            if npc['graphics'][field]!=expected:raise ValueError('NPC graphics resource mismatch')
        for folder,name in (('actor',row['model_path']),('tailor',row['drsb'])):
            if name and (Path(name).name!=name or not any((base/'region_common'/folder/name).is_file() for base in (mod,clean))):
                raise ValueError('Missing or unsafe NPC visual resource')
        records.append(row)
    return records

def header(records):
    result='typedef struct {const char *text;unsigned long long length;} WorldVisualName;\n'
    result+='typedef struct {unsigned native,index,ordinal;WorldVisualName name;} WorldVisual;\n'
    result+=f'#define WORLD_VISUAL_COUNT {len(records)}u\n'
    result+='static const WorldVisual WORLD_VISUALS[]={'+','.join(
        '{'+f'{r["native_id"]},{r["index"]},{r["ordinal"]},'+'{'+json.dumps(r['npc_key'])+','+str(len(r['npc_key']))+'}}'
        for r in records)+'};\n'
    return result
