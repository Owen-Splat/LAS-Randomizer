# Adapter details derived in part from LASRecomp (MIT); see RandomizerCore/Tools/LASRecomp-LICENSE.txt.
"""One-time standalone goods in the vanilla shop's shovel/bow, stone and heart slots.

Vanilla consumable goods remain available. Purchased and stolen goods share the
persistent source flag, independently of receiving their original vanilla equipment.
"""
from copy import deepcopy
from pathlib import Path
import re
import struct


def stage(rewards):
    w=rewards.worker
    mod=Path(w.romfs_dir).parent;clean_romfs=Path(w.rom_path)
    order=['shop-slot3-1st','shop-slot3-2nd']+[f'shop-slot5-{n}' for n in ('1st','2nd','3rd','4th','5th','6th','7th')]+['shop-slot6']
    displays={};defs={}
    for name in order:
        key,index=w.getItemInfo(name)
        displays[name]={'location':name,'key':key,'marker':index,'message':w.placements[name].replace('-',' ').title()}
        defs[key]=w.item_defs[w.placements[name]]
    from RandomizerCore.Tools import event_tools as e,oead_tools as o
    from RandomizerCore.Tools.msbt import Msbt
    if not displays:return []
    base=Path(mod)/'romfs';clean=Path(clean_romfs)
    def read(rel):
        path=base/rel
        return path if path.is_file() else clean/rel
    def write(rel):
        path=base/rel;path.parent.mkdir(parents=True,exist_ok=True);return path
    order=['shop-slot3-1st','shop-slot3-2nd']+[f'shop-slot5-{n}' for n in ('1st','2nd','3rd','4th','5th','6th','7th')]+['shop-slot6']
    rows=[]
    for i,name in enumerate(order):
        if name not in displays:continue
        d=displays[name]
        rows.append(dict(d,flag='LASShop_'+name,dummy='LASShopGoods_'+str(i),pending='LASShopPending_'+str(i),
                         native_id=230+i,slot=2 if i<2 else 4 if i<9 else 5,
                         price=200 if i in (0,9) else 980 if i==1 else 999,
                         ordinal=i))
    for r in rows:
        bit=rewards.flag(r['flag']);pending=rewards.flag(r['pending'])
        rewards.sources.append({'item':r['native_id'],'index':-1,'flag':bit,'pending':pending})
    items=o.readSheet(read('region_common/datasheets/Items.gsheet'))
    template=next(o.parseStruct(r) for r in items['values'] if r['symbol']=='HookShot')
    for r in rows:
        row=deepcopy(template);row.update(symbol=r['dummy'],itemID=r['native_id'],gettingFlag='')
        items['values'].append(o.dictToStruct(row))
    o.writeSheet(write('region_common/datasheets/Items.gsheet'),items)
    conditions=o.readSheet(read('region_common/datasheets/Conditions.gsheet'))
    previous={}
    for r in rows:
        tests=[(1,'!'+r['flag'])]
        if r['slot'] in previous:tests.append((1,previous[r['slot']]))
        previous[r['slot']]=r['flag']
        conditions['values'].append(o.createCondition(r['dummy'],tests))
    o.writeSheet(write('region_common/datasheets/Conditions.gsheet'),conditions)
    sheet=o.readSheet(read('region_common/datasheets/ShopItem.gsheet'))
    for slot in sheet['values']:
        selected=[r for r in rows if r['slot']==slot['mIndex']]
        if not selected:continue
        goods=[]
        for r in selected:
            model=defs[r['key']]
            goods.append({'mItem':r['dummy'],'mIndex':r['marker'],'mCount':1,
                          'mModelPath':'actor/'+model['model-path'],'mModelName':model['model-name'],
                          'mLabel':'System:'+r['dummy']+'_Price','mCondition':r['dummy'],'mEntryPoint':r['dummy']})
        if slot['mIndex']==2:
            arrow=next(o.parseStruct(g) for g in slot['mGoods'] if g['mItem']=='Arrow')
            arrow['mCondition']='LASShopArrowRestock'
            goods.append(arrow)
            conditions['values'].append(o.createCondition('LASShopArrowRestock',[(1,selected[-1]['flag'])]))
        slot['mGoods']=o.listToSheetArray('mGoods',goods)
    o.writeSheet(write('region_common/datasheets/ShopItem.gsheet'),sheet)
    o.writeSheet(write('region_common/datasheets/Conditions.gsheet'),conditions)
    flow=e.readFlow(read('region_common/event/ToolShopkeeper.bfevfl'));fc=flow.flowchart
    talk=dict(e.findEvent(fc,'Event138').data.params.data)
    for r in rows:
        finish=e.createActionEvent(fc,'EventFlags','SetFlag',{'symbol':r['flag'],'value':True})
        give=rewards.give(fc,r['location'],finish)
        buy=e.createActionChain(fc,None,[('Link','AddRupee',{'amount':-r['price']}),
            ('ToolShopkeeper','RemoveGoods',{}),('ToolShopkeeper','Talk',{'message':'Npc:BuyToolShop'})],give)
        restore=e.createActionEvent(fc,'ToolShopkeeper','RestoreGoods',{})
        poor=e.createActionEvent(fc,'ToolShopkeeper','Talk',{'message':'Npc:NoneMoneyToolShop'},restore)
        money=e.createSwitchEvent(fc,'Link','CheckRupee',{'amount':r['price']},{0:poor,1:buy})
        answer=e.createSwitchEvent(fc,'Dialog','GetLastResult',{}, {0:money,1:restore})
        offer=e.createActionEvent(fc,'ToolShopkeeper','Talk',{'message':'System:'+r['dummy']+'_Buy'})
        turn=e.createActionEvent(fc,'ToolShopkeeper','GenericTalkSequence',talk)
        fork=e.createForkEvent(fc,None,[turn,offer],answer)[0]
        e.addEntryPoint(fc,r['dummy'])
        e.insertEventAfter(fc,r['dummy'],e.createActionEvent(fc,'Hud','ShowRupee',{'visible':True},fork))
    e.writeFlow(write('region_common/event/ToolShopkeeper.bfevfl'),flow)
    pink=b'\x0e\x00\x00\x03\x00\x04\x00\xd9Em\xff'
    for original in sorted(clean.rglob('System.msbt')):
        path=write(original.relative_to(clean))
        m=Msbt((path if path.is_file() else original).read_bytes());tag=m.texts['PriceTagScoop'];buy=m.texts['BuyHeartPeace']
        for r in rows:
            label=r['message'].split('\nFor ')[0].replace('\n',' ').encode()
            for suffix,template in (('_Price',tag),('_Buy',buy)):
                raw=label+b'\n'+template[template.index(pink):]
                start=raw.index(pink)+len(pink)
                # Preserve each locale's choice/button commands.
                match=re.match(rb'(?:[0-9,]|\xef\xbc[\x90-\x99]|\xef\xbc\x8c)+',raw[start:])
                if not match:raise ValueError('Unrecognized localized shop price')
                raw=raw[:start]+str(r['price']).encode()+raw[start+len(match[0]):]
                m.set(r['dummy']+suffix,raw)
                if m.atr is not None:
                    _,size=struct.unpack_from('<II',m.atr)
                    template_label='PriceTagScoop' if suffix=='_Price' else 'BuyHeartPeace'
                    source=8+m.labels[template_label]*size
                    target=8+m.labels[r['dummy']+suffix]*size
                    m.atr=m.atr[:target]+m.atr[source:source+size]+m.atr[target+size:]
        path.write_bytes(m.pack())
    # A stolen dummy cannot enter vanilla inventory. Its native pending flag is
    # consumed on the next PlayerStart, using the same upstream reward routine.
    flow=w.readFile('PlayerStart.bfevfl');fc=flow.flowchart
    before='Event57';after=e.findEvent(fc,before).data.nxt.v.name
    chain=after
    for r in reversed(rows):
        finish=e.createActionChain(fc,None,[
            ('EventFlags','SetFlag',{'symbol':r['flag'],'value':True}),
            ('EventFlags','SetFlag',{'symbol':r['pending'],'value':False})],chain)
        give=rewards.give(fc,r['location'],finish)
        # Never award again if a completed source has a stale pending bit.
        clear=e.createActionEvent(fc,'EventFlags','SetFlag',{'symbol':r['pending'],'value':False},chain)
        owned=e.createSwitchEvent(fc,'EventFlags','CheckFlag',{'symbol':r['flag']},{0:give,1:clear})
        chain=e.createSwitchEvent(fc,'EventFlags','CheckFlag',{'symbol':r['pending']},{0:chain,1:owned})
    e.insertEventAfter(fc,before,chain)
    w.writeFile('PlayerStart.bfevfl',flow)
    return [r['location'] for r in rows]
