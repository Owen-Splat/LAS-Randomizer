"""Compile registered receipts from pinned LAS helpers and generated data sheets.

Unimplemented reward families stay explicitly unsupported. This table is an
implementation input; it makes no live correctness/capability declaration.
"""
import hashlib
import json
from pathlib import Path
import sys

BASIC = {'angler-key','bird-key','boomerang','boots','bow','face-key','feather',
         'flippers','hookshot','mushroom','ocarina','rod','shell-sensor','shovel',
         'slime-key','tail-key','song-ballad','song-mambo','song-soul'}
RUPEES = {'rupee-5':5,'rupee-20':20,'rupee-50':50,'rupee-100':100,'rupee-300':300}
PROGRESSIVE = {'sword':('SwordLv1','SwordLv2'),'shield':('Shield','MirrorShield'),
               'bracelet':('PowerBraceletLv1','PowerBraceletLv2')}
INSTRUMENTS = {'full-moon-cello','conch-horn','sea-lilys-bell','surf-harp',
               'wind-marimba','coral-triangle','evening-calm-organ','thunder-drum'}
TRADE = {'yoshi-doll','ribbon','dog-food','bananas','stick','honeycomb','pineapple',
         'hibiscus','letter','broom','fishing-hook','necklace','mermaid-scale'}
DUNGEON_PREFIXES=('key-D','nightmare-key-D','map-D','compass-D','stone-beak-D')
INDEXED = {
    'seashell':(22,0x5548,0,list(range(50))),
    'heart-piece':(58,0x5550,0,list(range(32))),
    'heart-container':(59,0x5558,0,list(range(9))),
    'golden-leaf':(23,0x5582,0,list(range(5))),
    'bottle':(113,0x5568,13,list(range(3))),
    'chamber-stone':(114,-1,0,[3,4,8,10,11,12,13,20,21,22,23,24,25,26]),
}
EVENTS={'zap-trap','drown-trap','squish-trap','deathball-trap','quake-trap','stalfos-note','zol-trap'}
CAPACITIES={'powder-capacity':(123,8,11,40,'GetMagicPowder'),
            'bomb-capacity':(124,16,4,60,'unused0424'),
            'arrow-capacity':(125,32,60,60,None)}


def reserve_vanilla_indexes(rewards,catalog,managed_locations):
    """Leave indexes belonging to unrandomized collectibles for their own actors."""
    reserved={name:set() for name in INDEXED}
    for location,node in catalog['logic_nodes'].items():
        if location in managed_locations or node.get('type')!='item':continue
        name=node.get('content')
        if name in reserved and 'index' in node:reserved[name].add(node['index'])
    for row in rewards['supported']:
        if row['kind']=='indexed':row['indexes']=[i for i in row['indexes'] if i not in reserved[row['name']]]
    return {name:sorted(indexes) for name,indexes in reserved.items()}


def compile_catalog(source, core, romfs):
    import oead
    source,core,romfs=map(Path,(source,core,romfs))
    catalog=json.loads((core/'catalog.json').read_text())
    registry=json.loads((core/'ids.json').read_text())['items']
    for name,expected in catalog['fingerprints'].items():
        if hashlib.sha256((source/name).read_bytes()).hexdigest()!=expected:
            raise ValueError('Reward compiler source differs from pinned LAS: '+name)
    sys.path.insert(0,str(source.resolve()))
    from RandomizerCore.Randomizers.item_get import insertItemWithoutAnimation
    def sheet(name):return oead.gsheet.parse(oead.Bytes((romfs/'region_common/datasheets'/name).read_bytes())).values
    items={r['symbol']:r for r in sheet('Items.gsheet')}
    flags={r['symbol']:int(r['index']) for r in sheet('GlobalFlags.gsheet')}
    supported=[];unsupported=[]
    for name,ap_id in sorted(registry.items(),key=lambda row:row[1]):
        key=catalog['items'][name]['definition']['item-key']
        dungeon=int(name[-1]) if name.startswith(DUNGEON_PREFIXES) else -1
        if dungeon<0 and name not in BASIC|RUPEES.keys()|PROGRESSIVE.keys()|INSTRUMENTS|TRADE|INDEXED.keys()|CAPACITIES.keys()|EVENTS|{'red-tunic','blue-tunic','bomb','powder','medicine','magnifying-lens'}:
            unsupported.append(name);continue
        row={'item_id':ap_id,'name':name,'key':key,'kind':'plain','native_ids':[],
             'count':1,'flags':[],'progressive_flag':-1,'rupees':RUPEES.get(name,0),'dungeon':dungeon,
             'storage_offset':0,'storage_shift':0,'indexes':[],'bottle_flag':-1,
             'extra_native':-1,'extra_count':0,'extra_flag':-1,'heal':0,'capacity_mask':0}
        if name in EVENTS:
            row.update(kind='spawn' if name=='zol-trap' else 'event',getting_flag=-1)
            supported.append(row);continue
        for actor,action,params in insertItemWithoutAnimation(key,-1):
            if (actor,action)==('EventFlags','SetFlag'):
                flag=flags[params['symbol']]
                if not 0<=flag<1360:raise ValueError('Reward flag overlaps native state')
                row['flags'].append([flag,int(params['value'])])
            elif (actor,action)==('Inventory','AddItemByKey'):
                if params['itemKey']!=key or params['index']!=-1:raise ValueError('Unexpected LAS grant template')
                row['native_ids'].append(int(items[key]['itemID']))
                row['count']=params['count']
            elif (actor,action)==('Link','Heal') and name=='medicine' and params=={'amount':99}:
                row['heal']=1
            elif (actor,action)==('Inventory','SetWarashibeItem') and name=='magnifying-lens' and params=={'itemType':15}:
                # The inspected native MagnifyingLens add stores the final trade slot.
                row['native_ids']=[int(items[key]['itemID'])]
                if row['native_ids']!=[43]:raise ValueError('Magnifying lens native ID mismatch')
            else:raise ValueError('Unsupported operation in selected LAS reward template')
        if name in PROGRESSIVE:
            row['kind']='progressive';row['progressive_flag']=row['flags'][0][0]
            row['native_ids']=[int(items[k]['itemID']) for k in PROGRESSIVE[name]]
        if name in {'red-tunic','blue-tunic'}:row['native_ids']=[int(items[key]['itemID'])]
        if name=='bomb':row['count']=60
        if name=='powder':row['count']=40
        if name in RUPEES:row['kind']='rupees'
        if dungeon>=0:
            row['kind']='dungeon'
            if row['native_ids'][0] not in (44,45,47,48,49) or not 0<=dungeon<=8:
                raise ValueError('Invalid dungeon item profile')
        if name in INDEXED:
            native,offset,shift,indexes=INDEXED[name]
            if row['native_ids']!=[native]:raise ValueError('Indexed native item ID mismatch')
            row.update(kind='indexed',storage_offset=offset,storage_shift=shift,indexes=indexes)
            if name=='bottle':row['bottle_flag']=flags['Bottle2Get']
        if name in CAPACITIES:
            native,mask,extra,count,condition=CAPACITIES[name]
            if row['native_ids']!=[native]:raise ValueError('Capacity native ID mismatch')
            row.update(kind='capacity',capacity_mask=mask,extra_native=extra,extra_count=count,
                       extra_flag=flags[condition] if condition else -1)
        getting=items[key]['gettingFlag']
        if getting:
            flag=flags[getting]
            if not 0<=flag<1360:raise ValueError('Getting flag overlaps native state')
            # The regular item-get sequence sets this after the inventory add.
            row['getting_flag']=flag
        else:row['getting_flag']=-1
        if len(row['flags'])>8 or len(row['native_ids'])>2 or any(not 0<=i<=126 for i in row['native_ids']):
            raise ValueError('Invalid native reward program')
        supported.append(row)
    return {'supported':supported,'unsupported':unsupported,'source_digest':catalog['source_digest']}


def header(table):
    lines=['typedef struct {unsigned id; const char *name,*key,*semantic; unsigned kind,native0,native1,count,rupees; int progressive_flag,getting_flag,dungeon; unsigned flag_count; int flags[8][2]; int storage_offset; unsigned storage_shift,index_count,indexes[50]; int bottle_flag,extra_native; unsigned extra_count; int extra_flag; unsigned heal,capacity_mask; const char *event_entry;} NativeReward;']
    lines.append('static const NativeReward NATIVE_REWARDS[]={')
    for r in table['supported']:
        ids=r['native_ids']+[0,0]
        kind=2 if r['kind']=='rupees' else 1 if r['kind']=='progressive' else 0
        if r['kind']=='dungeon':kind=4
        if r['kind']=='indexed':kind=5
        if r['kind']=='capacity':kind=6
        if not r['native_ids']:kind=3
        if r['kind']=='spawn':kind=7
        if r['kind']=='event':kind=8
        fields=[str(r['item_id'])+'u',json.dumps(r['name']),json.dumps(r['key']),
                json.dumps('progressive' if kind==1 else 'dungeon_item' if kind==4 else 'capacity_upgrade' if kind==6 else 'las_event_reward'),str(kind),
                str(ids[0]),str(ids[1]),str(r['count']),str(r['rupees']),
                str(r['progressive_flag']),str(r['getting_flag']),str(r['dungeon']),str(len(r['flags'])),
                '{'+','.join('{'+str(f)+','+str(v)+'}' for f,v in r['flags'])+'}',
                str(r['storage_offset']),str(r['storage_shift']),str(len(r['indexes'])),
                '{'+','.join(map(str,r['indexes']))+'}',str(r['bottle_flag']),
                str(r['extra_native']),str(r['extra_count']),str(r['extra_flag']),str(r['heal']),str(r['capacity_mask']),json.dumps('AP_Receive_'+r['name'].replace('-','_'))]
        lines.append('{'+','.join(fields)+'},')
    lines.append('};\n#define NATIVE_REWARD_COUNT (sizeof NATIVE_REWARDS/sizeof NATIVE_REWARDS[0])\n')
    return '\n'.join(lines)
