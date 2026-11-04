"""Stage native-delivery event rewards using the pinned LAS event helpers."""
from pathlib import Path

COMPLETION_MARKER=0x4C420000
EVENT_REWARDS={
    'zap-trap':'ZapTrap', 'drown-trap':'DrownTrap',
    'squish-trap':'SquishTrap', 'deathball-trap':'DeathballTrap',
    'quake-trap':'QuakeTrap', 'stalfos-note':'$EXT:MasterStalfonLetter',
}


def stage(mod,clean_romfs):
    from RandomizerCore.Tools import event_tools as tools
    from RandomizerCore.Randomizers.item_get import insertDampeItemGet
    path=Path(mod)/'romfs/region_common/event/Common.bfevfl'
    flow=tools.readFlow(path if path.is_file() else Path(clean_romfs)/'region_common/event/Common.bfevfl')
    fc=flow.flowchart
    for name,key in EVENT_REWARDS.items():
        entry='AP_Receive_'+name.replace('-','_')
        if tools.findEntryPoint(fc,entry):raise ValueError('Duplicate native reward event')
        tools.addEntryPoint(fc,entry)
        complete=tools.createActionEvent(fc,'Inventory','AddItemByKey',
            {'itemKey':'HookShot','count':1,'index':COMPLETION_MARKER,'autoEquip':False})
        if name=='stalfos-note':
            root=tools.createActionEvent(fc,'Link','GenericItemGetSequenceByKey',
                {'itemKey':key,'keepCarry':False,'messageEntry':''},complete)
        else:
            root=insertDampeItemGet(fc,key,-1,complete)
        tools.insertEventAfter(fc,entry,root)
    tools.addEntryPoint(fc,'AP_DeathLink')
    tools.createActionChain(fc,'AP_DeathLink',[
        ('Hud','SetHeartUpdateEnable',{'enable':True}),
        ('Link','Damage',{'amount':999}),
        ('Inventory','AddItemByKey',{'itemKey':'HookShot','count':1,'index':COMPLETION_MARKER+1,'autoEquip':False})])
    path.parent.mkdir(parents=True,exist_ok=True)
    tools.writeFlow(path,flow)
    verify=tools.readFlow(path)
    for name in EVENT_REWARDS:
        ep=tools.findEntryPoint(verify.flowchart,'AP_Receive_'+name.replace('-','_'))
        if not ep or not ep.main_event.v:raise ValueError('Native reward event did not serialize')
    return list(EVENT_REWARDS)
