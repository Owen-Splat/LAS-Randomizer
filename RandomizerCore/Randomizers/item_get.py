import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers import data


# Inserts an AddItemByKey and a GenericItemGetSequenceByKey, or a progressive item switch (depending on the item).
# It goes after 'before' and before 'after'. Return the name of the first event in the sequence.
def insertItemGetAnimation(flowchart, item, index, before=None, after=None, play_extra_anim=True, can_hurt_player=True):
    """Inserts the needed itemGet event into the flowchart and returns the name of the first event in the sequence
    
    Parameters
    ----------
    flowchart: dict[str, any]
        The flowchart of the eventflow file
    item : str
        The key of the item
    index : int
        The index of the item
    before : str | None
        The event that comes before the returned ItemGetAnimation
    after : str | None
        The event that comes after the returned ItemGetAnimation
    playExtraAnim : bool | True
        Determines if special item animations will play when getting the item
    canHurtPlayer : bool | True
        Determines if the item can hurt the player. Specifically used for traps"""

    # progressive items
    if item == 'PowerBraceletLv1':
        return event_tools.createProgressiveItemSwitch(flowchart, 'PowerBraceletLv1', 'PowerBraceletLv2',
            data.BRACELET_FOUND_FLAG, before, after)

    if item == 'SwordLv1':
        if play_extra_anim:
            spinAnim = event_tools.createForkEvent(flowchart, None, [
                event_tools.createActionChain(flowchart, None, [
                    ('Link', 'RequestSwordRolling', {}),
                    ('Link', 'PlayAnimationEx', {'blendTime': 0.1, 'name': 'slash_hold_lp', 'time': 0.8})
                ], None),
            ], after)[0]
            return event_tools.createProgressiveItemSwitch(flowchart, 'SwordLv1', 'SwordLv2',
                data.SWORD_FOUND_FLAG, before, spinAnim)
        else:
            return event_tools.createProgressiveItemSwitch(flowchart, 'SwordLv1', 'SwordLv2',
                data.SWORD_FOUND_FLAG, before, after)

    if item == 'Shield':
        return event_tools.createProgressiveItemSwitch(flowchart, 'Shield', 'MirrorShield',
            data.SHIELD_FOUND_FLAG, before, after)    

    # traps
    if item == 'ZapTrap':
        autosave_event = event_tools.createActionEvent(flowchart, 'GameControl', 'RequestAutoSave', {}, after)
        stop_event = event_tools.createActionEvent(flowchart, 'Link', 'StopTailorOtherChannel',
            {'channel': 'toolshopkeeper_dmg', 'index': 0}, autosave_event)
        forks = [
            event_tools.createActionEvent(flowchart, 'Link', 'PlayAnimation', {'blendTime': 0.1, 'name': 'ev_dmg_elec_lp'}),
            event_tools.createActionEvent(flowchart, 'Link', 'PlayTailorOtherChannelEx',
                {'channel': 'toolshopkeeper_dmg', 'index': 0, 'restart': False, 'time': 1.0}),
            event_tools.createActionEvent(flowchart, 'Hud', 'SetHeartUpdateEnable', {'enable': True}),
        ]
        if can_hurt_player:
            forks.append(event_tools.createActionEvent(flowchart, 'Link', 'Damage', {'amount': 6}))
        return event_tools.createForkEvent(flowchart, before, forks, stop_event)[0]

    if item == 'DrownTrap':
        autosave_event = event_tools.createActionEvent(flowchart, 'GameControl', 'RequestAutoSave', {}, after)
        forks = [
            event_tools.createActionEvent(flowchart, 'Link', 'PlayAnimation', {'blendTime': 0.1, 'name': 'fall_water'}),
            event_tools.createActionEvent(flowchart, 'Hud', 'SetHeartUpdateEnable', {'enable': True})
        ]
        if can_hurt_player:
            forks.append(event_tools.createActionChain(flowchart, None, [
                ('Timer', 'Wait', {'time': 1.5}),
                ('Link', 'Damage', {'amount': 2})
            ]))
        else:
            forks.append(event_tools.createActionEvent(flowchart, 'Timer', 'Wait', {'time': 1.5}))
        return event_tools.createForkEvent(flowchart, before, forks, autosave_event)[0]

    if item == 'SquishTrap':
        autosave_event = event_tools.createActionEvent(flowchart, 'GameControl', 'RequestAutoSave', {}, after)
        forks = [
            event_tools.createActionEvent(flowchart, 'Link', 'PlayAnimation', {'blendTime': 0.1, 'name': 'dmg_press'}),
            event_tools.createActionEvent(flowchart, 'Hud', 'SetHeartUpdateEnable', {'enable': True}),
            event_tools.createActionEvent(flowchart, 'Timer', 'Wait', {'time': 2.0})
        ]
        if can_hurt_player:
            forks.append(event_tools.createActionEvent(flowchart, 'Link', 'Damage', {'amount': 4}))
        return event_tools.createForkEvent(flowchart, before, forks, autosave_event)[0]

    if item == 'DeathballTrap':
        autosave_event = event_tools.createActionEvent(flowchart, 'GameControl', 'RequestAutoSave', {}, after)
        forks = [
            event_tools.createActionEvent(flowchart, 'Link', 'PlayTailorOtherChannelEx',
                {'channel': 'GreatFairy_Heal', 'index': 0, 'restart': False, 'time': 0.0}),
            event_tools.createActionChain(flowchart, None, [
                ('Timer', 'Wait', {'time': 0.1}),
                ('Link', 'PlayAnimation', {'blendTime': 0.1, 'name': 'fall_deathball'})
            ])
        ]
        if can_hurt_player:
            forks.append(event_tools.createActionChain(flowchart, None, [
                ('Hud', 'SetHeartUpdateEnable', {'enable': True}),
                ('Timer', 'Wait', {'time': 1.5}),
                ('Link', 'Damage', {'amount': 2})
            ]))
        else:
            forks.append(event_tools.createActionEvent(flowchart, 'Timer', 'Wait', {'time': 1.5}))
        return event_tools.createForkEvent(flowchart, before, forks, autosave_event)[0]

    if item == 'QuakeTrap':
        autosave_event = event_tools.createActionEvent(flowchart, 'GameControl', 'RequestAutoSave', {}, after)
        forks = [
            event_tools.createActionEvent(flowchart, 'Link', 'PlayAnimation', {'blendTime': 0.1, 'name': 'dmg_quake'}),
            event_tools.createActionEvent(flowchart, 'Timer', 'Wait', {'time': 1.5}),
            event_tools.createActionEvent(flowchart, 'Hud', 'SetHeartUpdateEnable', {'enable': True}),
            event_tools.createActionEvent(flowchart, 'Link', 'Damage', {'amount': 2})
        ]
        return event_tools.createForkEvent(flowchart, before, forks, autosave_event)[0]

    # tunics
    if item == 'ClothesRed':
        return event_tools.createActionChain(flowchart, before, [
            ('Link', 'PlayTailorOtherChannelEx', {'channel': 'Change_Color_Red_00', 'index': 0, 'restart': False, 'time': 3.58}),
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': 'ClothesRed'})
        ], after)

    if item == 'ClothesBlue':
        return event_tools.createActionChain(flowchart, before, [
            ('Link', 'PlayTailorOtherChannelEx', {'channel': 'Change_Color_Blue_00', 'index': 0, 'restart': False, 'time': 3.58}),
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': 'ClothesBlue'})
        ], after)

    if item == 'ClothesGreen':
        return event_tools.createActionChain(flowchart, before, [
            ('Link', 'PlayTailorOtherChannelEx', {'channel': 'Change_Color_Green_00', 'index': 0, 'restart': False, 'time': 3.58}),
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': 'ClothesGreen'})
        ], after)

    # EVERYTHING ELSE - play the get event before giving the item, otherwise it messes with index related messages
    # this is how the game normally does it, and so for the "you've collected them all" messages,
    # the game actually checks for 3 heart pieces and 4 golden leaves respectively
    return event_tools.createActionChain(flowchart, before, [
        ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': item}),
        ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False})
    ], after)


def insertItemWithoutAnimation(item, index):
    """Same as insertItemGetAnimation but without the Generic ItemGet animation"""

    return [('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False})]


def insertDampeItemGet(flowchart, item, index, after=None):
    # progressive items
    if item == 'PowerBraceletLv1':
        give_bracelet2 = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
            {'itemKey': 'PowerBraceletLv2', 'count': 1, 'index': -1, 'autoEquip': False}, after)
        give_bracelet1 = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
            {'itemKey': item, 'count': 1, 'index': -1, 'autoEquip': False}, after)
        return event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': data.BRACELET_FOUND_FLAG}, {0: give_bracelet1, 1: give_bracelet2})

    if item == 'SwordLv1':
        give_sword2 = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
            {'itemKey': 'SwordLv2', 'count': 1, 'index': -1, 'autoEquip': False}, after)
        give_sword1 = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
            {'itemKey': item, 'count': 1, 'index': -1, 'autoEquip': False}, after)
        return event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': data.SWORD_FOUND_FLAG}, {0: give_sword1, 1: give_sword2})

    if item == 'Shield':
        give_shield2 = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
            {'itemKey': 'MirrorShield', 'count': 1, 'index': -1, 'autoEquip': False}, after)
        give_shield1 = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
            {'itemKey': item, 'count': 1, 'index': -1, 'autoEquip': False}, after)
        return event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': data.SHIELD_FOUND_FLAG}, {0: give_shield1, 1: give_shield2})    

    # traps
    if item == 'ZapTrap':
        autosave_event = event_tools.createActionEvent(flowchart, 'GameControl', 'RequestAutoSave', {}, after)
        stop_event = event_tools.createActionEvent(flowchart, 'Link', 'StopTailorOtherChannel',
            {'channel': 'toolshopkeeper_dmg', 'index': 0}, autosave_event)
        forks = [
            event_tools.createActionEvent(flowchart, 'Link', 'PlayAnimation', {'blendTime': 0.1, 'name': 'ev_dmg_elec_lp'}),
            event_tools.createActionEvent(flowchart, 'Link', 'PlayTailorOtherChannelEx',
                {'channel': 'toolshopkeeper_dmg', 'index': 0, 'restart': False, 'time': 1.0}),
            event_tools.createActionEvent(flowchart, 'Hud', 'SetHeartUpdateEnable', {'enable': True}),
            event_tools.createActionEvent(flowchart, 'Link', 'Damage', {'amount': 6})
        ]
        return event_tools.createForkEvent(flowchart, None, forks, stop_event)[0]

    if item == 'DrownTrap':
        autosave_event = event_tools.createActionEvent(flowchart, 'GameControl', 'RequestAutoSave', {}, after)
        forks = [
            event_tools.createActionEvent(flowchart, 'Link', 'PlayAnimation', {'blendTime': 0.1, 'name': 'fall_water'}),
            event_tools.createActionEvent(flowchart, 'Hud', 'SetHeartUpdateEnable', {'enable': True}),
            event_tools.createActionChain(flowchart, None, [
                ('Timer', 'Wait', {'time': 1.5}),
                ('Link', 'Damage', {'amount': 2})
            ])
        ]
        return event_tools.createForkEvent(flowchart, None, forks, autosave_event)[0]

    if item == 'SquishTrap':
        autosave_event = event_tools.createActionEvent(flowchart, 'GameControl', 'RequestAutoSave', {}, after)
        forks = [
            event_tools.createActionEvent(flowchart, 'Link', 'PlayAnimation', {'blendTime': 0.1, 'name': 'dmg_press'}),
            event_tools.createActionEvent(flowchart, 'Hud', 'SetHeartUpdateEnable', {'enable': True}),
            event_tools.createActionEvent(flowchart, 'Timer', 'Wait', {'time': 2.0}),
            event_tools.createActionEvent(flowchart, 'Link', 'Damage', {'amount': 4})
        ]
        return event_tools.createForkEvent(flowchart, None, forks, autosave_event)[0]

    if item == 'DeathballTrap':
        autosave_event = event_tools.createActionEvent(flowchart, 'GameControl', 'RequestAutoSave', {}, after)
        forks = [
            event_tools.createActionEvent(flowchart, 'Link', 'PlayTailorOtherChannelEx',
                {'channel': 'GreatFairy_Heal', 'index': 0, 'restart': False, 'time': 0.0}),
            event_tools.createActionChain(flowchart, None, [
                ('Timer', 'Wait', {'time': 0.1}),
                ('Link', 'PlayAnimation', {'blendTime': 0.1, 'name': 'fall_deathball'})
            ]),
            event_tools.createActionChain(flowchart, None, [
                ('Hud', 'SetHeartUpdateEnable', {'enable': True}),
                ('Timer', 'Wait', {'time': 1.5}),
                ('Link', 'Damage', {'amount': 2})
            ])
        ]
        return event_tools.createForkEvent(flowchart, None, forks, autosave_event)[0]

    if item == 'QuakeTrap':
        autosave_event = event_tools.createActionEvent(flowchart, 'GameControl', 'RequestAutoSave', {}, after)
        forks = [
            event_tools.createActionEvent(flowchart, 'Link', 'PlayAnimation', {'blendTime': 0.1, 'name': 'dmg_quake'}),
            event_tools.createActionEvent(flowchart, 'Timer', 'Wait', {'time': 1.5}),
            event_tools.createActionEvent(flowchart, 'Hud', 'SetHeartUpdateEnable', {'enable': True}),
            event_tools.createActionEvent(flowchart, 'Link', 'Damage', {'amount': 6})
        ]
        return event_tools.createForkEvent(flowchart, None, forks, autosave_event)[0]    

    # tunics
    if item == 'ClothesRed':
        return event_tools.createActionChain(flowchart, None, [
            ('Link', 'PlayTailorOtherChannelEx', {'channel': 'Change_Color_Red_00', 'index': 0, 'restart': False, 'time': 3.58}),
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
        ], after)

    if item == 'ClothesBlue':
        return event_tools.createActionChain(flowchart, None, [
            ('Link', 'PlayTailorOtherChannelEx', {'channel': 'Change_Color_Blue_00', 'index': 0, 'restart': False, 'time': 3.58}),
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
        ], after)

    if item == 'ClothesGreen':
        return event_tools.createActionChain(flowchart, None, [
            ('Link', 'PlayTailorOtherChannelEx', {'channel': 'Change_Color_Green_00', 'index': 0, 'restart': False, 'time': 3.58}),
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
        ], after)    

    # everything else
    return event_tools.createActionChain(flowchart, None, [
        ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False})
    ], after)
