"""Standalone original-actor shell and dive pickups (LAS 1.0.0)."""
from pathlib import Path
from RandomizerCore.Tools import event_tools as e
from RandomizerCore.Randomizers import item_get

SUNKEN_HEARTS = frozenset(('bay-passage-sunken','river-crossing-cave','kanalet-moat-south','south-bay-sunken','taltal-east-drop'))
GRANT_TAG = 0x53470000

def locations(logic):
    return sorted(k for k,v in logic.items() if v.get('type')=='item' and
                  (v.get('subtype') in ('dig','hidden','bomb-hole') or k in SUNKEN_HEARTS or
                   (v.get('subtype')=='underwater' and v.get('content')=='seashell')))

def redirect(fc, old, new, originals):
    indexes=e.invertList(fc.events)
    refs=[ep.main_event for ep in fc.entry_points]
    for event in originals:
        data=event.data
        if hasattr(data,'nxt'):refs.append(data.nxt)
        if hasattr(data,'forks'):refs.extend(data.forks)
        if hasattr(data,'cases'):refs.extend(data.cases.values())
    for ref in refs:
        if ref.v is old:ref.v=new;ref.set_index(indexes)

class StandaloneRewards:
    def __init__(self, worker):
        self.worker=worker
        self.flags=worker.readFile('GlobalFlags.gsheet')
        self.used={int(r['index']) for r in self.flags['values']}
        self.sources=[]

    def flag(self, symbol):
        from RandomizerCore.Tools import oead_tools as o
        matches=[int(r['index']) for r in self.flags['values'] if r['symbol']==symbol]
        if matches:return matches[0]
        index=next((i for i in range(1248,2048) if i not in self.used),None)
        if index is None:raise ValueError('No free persistent source flags')
        self.used.add(index)
        self.flags['values'].append(o.dictToStruct({'symbol':symbol,'index':index}))
        return index

    def give(self, fc, location, after=None):
        key,index=self.worker.getItemInfo(location)
        return item_get.insertItemGetAnimation(fc,key,index,after=after)

    def shells(self, logic):
        w=self.worker
        flow=w.readFile('ItemCommon.bfevfl');fc=flow.flowchart
        old=e.findEvent(fc,'Event0');originals=list(fc.events)
        after=e.findEvent(fc,'Event1').data.nxt.v.name
        chains={'seashell':old.name,'heart-piece':old.name}
        for location in reversed(locations(logic)):
            node=logic[location];kind=node['content'];index=node['index']
            if kind not in chains:raise ValueError('Unsupported indexed pickup: '+location)
            flag='LASPickup_'+location
            bit=self.flag(flag)
            self.sources.append({'item':22 if kind=='seashell' else 58,'index':index,'flag':bit,'pending':-1})
            finish=e.createActionEvent(fc,'EventFlags','SetFlag',{'symbol':flag,'value':True},after)
            give=self.give(fc,location,finish)
            chains[kind]=e.createSwitchEvent(fc,'FlowControl','CompareInt',{'value1':'itemIndex','value2':index},{0:give,1:chains[kind]})
        chain=old.name
        for kind,key in (('seashell','Seashell'),('heart-piece','HeartPiece')):
            chain=e.createSwitchEvent(fc,'FlowControl','CompareString',{'value1':'itemKey','value2':key},{0:chains[kind],1:chain})
        redirect(fc,old,e.findEvent(fc,chain),originals)
        w.writeFile('ItemCommon.bfevfl',flow)

    def finish(self):
        w=self.worker
        w.writeFile('GlobalFlags.gsheet',self.flags)
        if not self.sources:return
        # Encode real collectible grants in every generated flow. The raw source
        # grants keep their ordinary indexes, so ownership stays independent.
        for path in Path(w.romfs_dir).rglob('*.bfevfl'):
            try:
                flow=e.readFlow(path)
            except Exception as exc:
                raise ValueError('Invalid generated event flow: '+str(path)) from exc
            changed=False
            for event in flow.flowchart.events:
                data=event.data
                if getattr(data,'params',None) is None:continue
                if not hasattr(data,'actor_action') or data.actor_action.v.v != 'AddItemByKey':continue
                p=data.params.data
                if p.get('itemKey') not in ('Seashell','HeartPiece'):continue
                index=p.get('index')
                if isinstance(index,int) and 0<=index<(50 if p['itemKey']=='Seashell' else 32):
                    p['index']=GRANT_TAG|index;changed=True
            if changed:e.writeFlow(path,flow)
        from RandomizerCore.Native.builder import build,validate_input
        target=Path(w.romfs_dir).parent/'exefs'
        build(validate_input(w.rom_path),target,self.sources,Path(w.romfs_dir).parent/'native-build')
