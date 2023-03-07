import Tools.event_tools as event_tools



# Ensure that the flowchart has the AddItemByKey and GenericItemGetSequenceByKey actions, and the EventFlags actor
# with the SetFlag and CheckFlag action/query.
def addNeededActors(flowchart, rom_path):
    """Ensures that the event flowchart has all the needed data by adding what is missing"""
    
    try:
        event_tools.findActor(flowchart, 'Inventory')
    except ValueError:
        inventory_actor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/Tarin.bfevfl').flowchart, 'Inventory')
        flowchart.actors.append(inventory_actor)

    try:
        event_tools.findActor(flowchart, 'Inventory').find_action('AddItemByKey')
    except ValueError:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Inventory'), 'AddItemByKey')
    
    try:
        event_tools.findActor(flowchart, 'Inventory').find_action('AddItem')
    except ValueError:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Inventory'), 'AddItem')

    try:
        event_tools.findActor(flowchart, 'Inventory').find_action('RemoveItem')
    except ValueError:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Inventory'), 'RemoveItem')

    try:
        event_tools.findActor(flowchart, 'Inventory').find_query('HasItem')
    except ValueError:
        event_tools.addActorQuery(event_tools.findActor(flowchart, 'Inventory'), 'HasItem')
    
    try:
        event_tools.findActor(flowchart, 'Inventory').find_action('SetWarashibeItem')
    except ValueError:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Inventory'), 'SetWarashibeItem')

    try:
        event_tools.findActor(flowchart, 'Link')
    except ValueError:
        link_actor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/PlayerStart.bfevfl').flowchart, 'Link')
        flowchart.actors.append(link_actor)

    try:
        event_tools.findActor(flowchart, 'Link').find_action('GenericItemGetSequenceByKey')
    except ValueError:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'GenericItemGetSequenceByKey')
    
    try:
        event_tools.findActor(flowchart, 'Link').find_action('PlayTailorOtherChannelNoWait')
    except:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'PlayTailorOtherChannelNoWait')

    try:
        event_tools.findActor(flowchart, 'Link').find_action('PlayTailorOtherChannelEx')
    except:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'PlayTailorOtherChannelEx')

    try:
        event_tools.findActor(flowchart, 'Link').find_action('StopTailorOtherChannel')
    except:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'StopTailorOtherChannel')

    try:
        event_tools.findActor(flowchart, 'Link').find_action('Heal')
    except:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'Heal')

    try:
        event_tools.findActor(flowchart, 'Link').find_action('Damage')
    except:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'Damage')

    try:
        event_tools.findActor(flowchart, 'Link').find_action('RequestSwordRolling')
    except:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'RequestSwordRolling')
    
    try:
        event_tools.findActor(flowchart, 'Link').find_action('PlayAnimation')
    except:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'PlayAnimation')

    try:
        event_tools.findActor(flowchart, 'Link').find_action('PlayAnimationEx')
    except:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'PlayAnimationEx')
    
    try:
        event_tools.findActor(flowchart, 'Link').find_action('SetFacialExpression')
    except:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'SetFacialExpression')
    
    try:
        event_tools.findActor(flowchart, 'EventFlags')
    except ValueError:
        event_flags_actor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/PlayerStart.bfevfl').flowchart, 'EventFlags')
        flowchart.actors.append(event_flags_actor)

    try:
        event_tools.findActor(flowchart, 'EventFlags').find_action('SetFlag')
    except ValueError:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'EventFlags'), 'SetFlag')

    try:
        event_tools.findActor(flowchart, 'EventFlags').find_query('CheckFlag')
    except ValueError:
        event_tools.addActorQuery(event_tools.findActor(flowchart, 'EventFlags'), 'CheckFlag')
            
    # hud event actors so the player's hearts update while getting zapped
    try:
        event_tools.findActor(flowchart, 'Hud')
    except ValueError:
        hud_actor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/ToolShopkeeper.bfevfl').flowchart, 'Hud')
        flowchart.actors.append(hud_actor)

    try:
        event_tools.findActor(flowchart, 'Hud').find_action('SetHeartUpdateEnable')
    except ValueError:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Hud'), 'SetHeartUpdateEnable')
    
    # instrument fade event actors
    try:
        event_tools.findActor(flowchart, 'Link').find_action('PlayInstrumentShineEffect')
    except ValueError:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'PlayInstrumentShineEffect')
    
    try:
        event_tools.findActor(flowchart, 'Audio')
    except ValueError:
        audio_actor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/MusicalInstrument.bfevfl').flowchart, 'Audio')
        flowchart.actors.append(audio_actor)

    try:
        event_tools.findActor(flowchart, 'Audio').find_action('StopOtherThanSystemSE')
    except ValueError:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Audio'), 'StopOtherThanSystemSE')

    try:
        event_tools.findActor(flowchart, 'Audio').find_action('PlayOneshotSystemSE')
    except ValueError:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Audio'), 'PlayOneshotSystemSE')

    try:
        event_tools.findActor(flowchart, 'Fade')
    except ValueError:
        fade_actor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/MusicalInstrument.bfevfl').flowchart, 'Fade')
        flowchart.actors.append(fade_actor)
    
    try:
        event_tools.findActor(flowchart, 'GameControl')
    except ValueError:
        control_actor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/MusicalInstrument.bfevfl').flowchart, 'GameControl')
        flowchart.actors.append(control_actor)

    try:
        event_tools.findActor(flowchart, 'GameControl').find_action('RequestLevelJump')
    except ValueError:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'GameControl'), 'RequestLevelJump')
    
    try:
        event_tools.findActor(flowchart, 'GameControl').find_action('RequestAutoSave')
    except ValueError:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'GameControl'), 'RequestAutoSave')
    
    try:
        event_tools.findActor(flowchart, 'Timer')
    except ValueError:
        time_actor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/MusicalInstrument.bfevfl').flowchart, 'Timer')
        flowchart.actors.append(time_actor)
    

# def addCompanionActors(flowchart, rom_path):
#     """Adds the missing data for companion related events"""

#     try:
#         event_tools.findActor(flowchart, 'FlyingCucco', 'FlyCocco')
#     except ValueError:
#         rooster_actor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/RoosterBones.bfevfl').flowchart, 'FlyingCucco', 'FlyCocco')
#         flowchart.actors.append(rooster_actor)
    
#     try:
#         event_tools.findActor(flowchart, 'Dialog')
#     except ValueError:
#         dialog_actor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/RoosterBones.bfevfl').flowchart, 'Dialog')
#         flowchart.actors.append(dialog_actor)
    
#     try:
#         event_tools.findActor(flowchart, 'Link').find_action('AimCompassPoint')
#     except ValueError:
#         event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'AimCompassPoint')
    
#     try:
#         event_tools.findActor(flowchart, 'Link').find_action('LookAtItemGettingPlayer')
#     except ValueError:
#         event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'LookAtItemGettingPlayer')
    
#     try:
#         event_tools.findActor(flowchart, 'Link').find_action('LeaveCompanion')
#     except ValueError:
#         event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'LeaveCompanion')
    
#     try:
#         event_tools.findActor(flowchart, 'FlyingCucco', 'companion')
#     except ValueError:
#         rooster_actor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/PlayerStart.bfevfl').flowchart, 'FlyingCucco', 'companion')
#         flowchart.actors.append(rooster_actor)
    
#     try:
#         event_tools.findActor(flowchart, 'BowWow', 'companion')
#     except ValueError:
#         bowwow_actor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/PlayerStart.bfevfl').flowchart, 'BowWow', 'companion')
#         flowchart.actors.append(bowwow_actor)
