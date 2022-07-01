import Tools.event_tools as event_tools
from Randomizers import data



# Inserts an AddItemByKey and a GenericItemGetSequenceByKey, or a progressive item switch (depending on the item).
# It goes after 'before' and before 'after'. Return the name of the first event in the sequence.
def insertItemGetAnimation(flowchart, item, index, before=None, after=None, playExtraAnim=True, canHurtPlayer=True):
    if item == 'PowerBraceletLv1':
        return event_tools.createProgressiveItemSwitch(flowchart, 'PowerBraceletLv1', 'PowerBraceletLv2', data.BRACELET_FOUND_FLAG, before, after)

    if item == 'SwordLv1':
        if playExtraAnim:
            spinAnim = event_tools.createForkEvent(flowchart, before, [
                event_tools.createActionChain(flowchart, None, [
                    ('Link', 'RequestSwordRolling', {}),
                    ('Link', 'PlayAnimationEx', {'blendTime': 0.1, 'name': 'slash_hold_lp', 'time': 0.8})
                ], None),
            ], after)[0]
            return event_tools.createProgressiveItemSwitch(flowchart, 'SwordLv1', 'SwordLv2', data.SWORD_FOUND_FLAG, before, spinAnim)
        else:
            return event_tools.createProgressiveItemSwitch(flowchart, 'SwordLv1', 'SwordLv2', data.SWORD_FOUND_FLAG, before, after)

    if item == 'Shield':
        return event_tools.createProgressiveItemSwitch(flowchart, 'Shield', 'MirrorShield', data.SHIELD_FOUND_FLAG, before, after)
    
    ###############################################################################################################################################
    ### Capacity upgrades
    if item == 'MagicPowder_MaxUp':
        return event_tools.createActionChain(flowchart, before, [
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Inventory', 'AddItemByKey', {'itemKey': 'MagicPowder', 'count': 40, 'index': -1, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'MagicPowder', 'keepCarry': False, 'messageEntry': 'MagicPowder_MaxUp'})
        ], after)

    if item == 'Bomb_MaxUp':
        giveBombs = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
        {'itemKey': 'Bomb', 'count': 60, 'index': -1, 'autoEquip': False}, after)

        bombsCheck = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.BOMBS_FOUND_FLAG}, {0: after, 1: giveBombs})

        return event_tools.createActionChain(flowchart, before, [
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'Bomb', 'keepCarry': False, 'messageEntry': 'Bomb_MaxUp'})
        ], bombsCheck)

    if item == 'Arrow_MaxUp':
        return event_tools.createActionChain(flowchart, before, [
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Inventory', 'AddItemByKey', {'itemKey': 'Arrow', 'count': 60, 'index': -1, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'Arrow', 'keepCarry': False, 'messageEntry': 'Arrow_MaxUp'})
        ], after)

    ######################################################################################################################################
    ### traps
    if item == 'ZapTrap':
        stopEvent = event_tools.createActionEvent(flowchart, 'Link', 'StopTailorOtherChannel',
        {'channel': 'toolshopkeeper_dmg', 'index': 0}, after)

        if canHurtPlayer:
            return event_tools.createForkEvent(flowchart, before, [
                event_tools.createActionEvent(flowchart, 'Link', 'PlayAnimation', {'blendTime': 0.1, 'name': 'ev_dmg_elec_lp'}),
                event_tools.createActionEvent(flowchart, 'Link', 'PlayTailorOtherChannelEx', {'channel': 'toolshopkeeper_dmg', 'index': 0, 'restart': False, 'time': 1.0}),
                event_tools.createActionEvent(flowchart, 'Timer', 'Wait', {'time': 3}),
                event_tools.createActionEvent(flowchart, 'Link', 'Damage', {'amount': 6}),
                event_tools.createActionEvent(flowchart, 'Hud', 'SetHeartUpdateEnable', {'enable': True}),
            ], stopEvent)[0]
        else:
            return event_tools.createForkEvent(flowchart, before, [
                event_tools.createActionEvent(flowchart, 'Link', 'PlayAnimation', {'blendTime': 0.1, 'name': 'ev_dmg_elec_lp'}),
                event_tools.createActionEvent(flowchart, 'Link', 'PlayTailorOtherChannelEx', {'channel': 'toolshopkeeper_dmg', 'index': 0, 'restart': False, 'time': 1.0}),
                event_tools.createActionEvent(flowchart, 'Timer', 'Wait', {'time': 3}),
                event_tools.createActionEvent(flowchart, 'Hud', 'SetHeartUpdateEnable', {'enable': True}),
            ], stopEvent)[0]

    ############################################################################################################################################
    ### Instrument flags - just ghost flags when getting harp for now :)
    if item == 'SurfHarp':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': 'GhostClear1', 'value': True}), # set flags before giving harp, otherwise ghost requirements may be met during the itemget animation, leaving the player with a ghost that can only be rid of by getting another follower
            ('EventFlags', 'SetFlag', {'symbol': 'Ghost2_Clear', 'value': True}),
            ('EventFlags', 'SetFlag', {'symbol': 'Ghost3_Clear', 'value': True}),
            ('EventFlags', 'SetFlag', {'symbol': 'Ghost4_Clear', 'value': True}),
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)
    
    ############################################################################################################################################
    ### tunics
    if item == 'ClothesRed':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': data.RED_TUNIC_FOUND_FLAG, 'value': True}),
            ('Link', 'PlayTailorOtherChannelEx', {'channel': 'Change_Color_Red_00', 'index': 0, 'restart': False, 'time': 3.58}),
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'MagicPowder_MaxUp', 'keepCarry': False, 'messageEntry': 'ClothesRed'})
        ], after)
    
    if item == 'ClothesBlue':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': data.BLUE_TUNIC_FOUND_FLAG, 'value': True}),
            ('Link', 'PlayTailorOtherChannelEx', {'channel': 'Change_Color_Blue_00', 'index': 0, 'restart': False, 'time': 3.58}),
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'MagicPowder_MaxUp', 'keepCarry': False, 'messageEntry': 'ClothesBlue'})
        ], after)
    
    if item == 'ClothesGreen':
        return event_tools.createActionChain(flowchart, before, [
            ('Link', 'PlayTailorOtherChannelEx', {'channel': 'Change_Color_Green_00', 'index': 0, 'restart': False, 'time': 3.58}),
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'MagicPowder_MaxUp', 'keepCarry': False, 'messageEntry': 'ClothesGreen'})
        ], after)
    
    ######################################################################################################################################
    ### Medicine
    if item == 'SecretMedicine':
        return event_tools.createActionChain(flowchart, before, [
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''}),
            ('Link', 'Heal', {'amount': 99})
        ], after)

    ######################################################################################################################################
    ### Bomb for Shuffled Bombs
    if item == 'Bomb':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': data.BOMBS_FOUND_FLAG, 'value': True}),
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 20, 'index': index, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)
    
    ######################################################################################################################################
    ### Trade Quest items
    if item == 'YoshiDoll':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': 'TradeYoshiDollGet', 'value': True}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)

    if item == 'Ribbon':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': 'TradeRibbonGet', 'value': True}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)

    if item == 'DogFood':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': 'TradeDogFoodGet', 'value': True}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)

    if item == 'Bananas':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': 'TradeBananasGet', 'value': True}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)

    if item == 'Stick':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': 'TradeStickGet', 'value': True}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)

    if item == 'Honeycomb':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': 'TradeHoneycombGet', 'value': True}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)

    if item == 'Pineapple':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': 'TradePineappleGet', 'value': True}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)

    if item == 'Hibiscus':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': 'TradeHibiscusGet', 'value': True}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)

    if item == 'Letter':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': 'TradeLetterGet', 'value': True}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)

    if item == 'Broom':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': 'TradeBroomGet', 'value': True}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)

    if item == 'FishingHook':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': 'TradeFishingHookGet', 'value': True}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)

    if item == 'PinkBra':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': 'TradeNecklaceGet', 'value': True}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)

    if item == 'MermaidsScale':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': 'TradeMermaidsScaleGet', 'value': True}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)
        
    ######################################################################################################################################
    ### everything else
    return event_tools.createActionChain(flowchart, before, [
        ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
        ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
    ], after)
