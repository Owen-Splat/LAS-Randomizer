"""Precompiled hint dialogs; runtime selects an ordinal, never injects strings."""
from pathlib import Path
import textwrap

def stage(mod,clean_romfs,manifest):
    routes=manifest.get('hint_routes',[])
    if not routes:return 0
    from RandomizerCore.Tools import event_tools as e
    from vendor.msbt import Msbt
    from native_display import install_message
    root=Path(mod)/'romfs';clean=Path(clean_romfs)
    path=root/'region_common/event/Common.bfevfl'
    flow=e.readFlow(path if path.exists() else clean/'region_common/event/Common.bfevfl');fc=flow.flowchart
    messages={}
    for route in routes:
        entry='AP_Hint_'+str(route['index'])
        if e.findEntryPoint(fc,entry):raise ValueError('Duplicate native hint event')
        e.addEntryPoint(fc,entry)
        e.createActionChain(fc,entry,[
            ('Dialog','Show',{'message':'System:'+entry}),
            ('Inventory','AddItemByKey',{'itemKey':'HookShot','count':1,'index':0x4C420002,'autoEquip':False})])
        text=(route['item_name'].replace('-',' ')+' for '+route['recipient_name']+'\n'+
              route['location_name'].replace('-',' ')+'\nWorld: '+route['finding_name'])
        text=''.join(c if c=='\n' or ord(c)>=32 else ' ' for c in text)[:400]
        messages[entry]='\n'.join(line for paragraph in text.splitlines() for line in textwrap.wrap(paragraph,34))
    path.parent.mkdir(parents=True,exist_ok=True);e.writeFlow(path,flow)
    locales=0
    for original in sorted(clean.rglob('System.msbt')):
        target=root/original.relative_to(clean);target.parent.mkdir(parents=True,exist_ok=True)
        data=Msbt((target if target.is_file() else original).read_bytes())
        for key,text in messages.items():install_message(data,key,text)
        target.write_bytes(data.pack());locales+=1
        verify=Msbt(target.read_bytes())
        if not set(messages)<=set(verify.labels):raise ValueError('Native hint message serialization failed')
    if not locales:raise ValueError('No game message files available for in-game hints')
    return len(routes)
