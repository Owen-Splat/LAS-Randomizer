import Tools.event_tools as event_tools



# Ensure that the flowchart has the AddItemByKey and GenericItemGetSequenceByKey actions, and the EventFlags actor
# with the SetFlag and CheckFlag action/query.
def addNeededActors(flowchart, rom_path):
    try:
        event_tools.findActor(flowchart, 'Inventory')
    except ValueError:
        inventoryActor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/Tarin.bfevfl').flowchart, 'Inventory')
        flowchart.actors.append(inventoryActor)

    try:
        event_tools.findActor(flowchart, 'Inventory').find_action('AddItemByKey')
    except ValueError:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Inventory'), 'AddItemByKey')

    try:
        event_tools.findActor(flowchart, 'Link')
    except ValueError:
        linkActor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/PlayerStart.bfevfl').flowchart, 'Link')
        flowchart.actors.append(linkActor)

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
        eventFlagsActor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/PlayerStart.bfevfl').flowchart, 'EventFlags')
        flowchart.actors.append(eventFlagsActor)

    try:
        event_tools.findActor(flowchart, 'EventFlags').find_action('SetFlag')
    except ValueError:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'EventFlags'), 'SetFlag')

    try:
        event_tools.findActor(flowchart, 'EventFlags').find_query('CheckFlag')
    except ValueError:
        event_tools.addActorQuery(event_tools.findActor(flowchart, 'EventFlags'), 'CheckFlag')
    
    # extra needed actors for instrument level jump
    try:
        event_tools.findActor(flowchart, 'Link').find_action('PlayInstrumentShineEffect')
    except ValueError:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'PlayInstrumentShineEffect')
    
    try:
        event_tools.findActor(flowchart, 'Audio')
    except ValueError:
        audioActor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/MusicalInstrument.bfevfl').flowchart, 'Audio')
        flowchart.actors.append(audioActor)

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
        fadeActor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/MusicalInstrument.bfevfl').flowchart, 'Fade')
        flowchart.actors.append(fadeActor)
    
    try:
        event_tools.findActor(flowchart, 'GameControl')
    except ValueError:
        controlActor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/MusicalInstrument.bfevfl').flowchart, 'GameControl')
        flowchart.actors.append(controlActor)
    
    try:
        event_tools.findActor(flowchart, 'Timer')
    except ValueError:
        timeActor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/MusicalInstrument.bfevfl').flowchart, 'Timer')
        flowchart.actors.append(timeActor)
    
    try:
        event_tools.findActor(flowchart, 'Hud')
    except ValueError:
        hudActor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/ToolShopKeeper.bfevfl').flowchart, 'Hud')
        flowchart.actors.append(hudActor)

    try:
        event_tools.findActor(flowchart, 'Hud').find_action('SetHeartUpdateEnable')
    except ValueError:
        event_tools.addActorAction(event_tools.findActor(flowchart, 'Hud'), 'SetHeartUpdateEnable')
    
    # ####################################################################################################################################
    # # Shadow Link
    # try:
    #     event_tools.findActor(flowchart, 'ShadowLink')
    # except ValueError:
    #     shadowActor = event_tools.findActor(event_tools.readFlow(f'{rom_path}/region_common/event/ShadowLink.bfevfl').flowchart, 'ShadowLink')
    #     flowchart.actors.append(shadowActor)

    # try:
    #     event_tools.findActor(flowchart, 'ShadowLink').find_action('PopStart')
    # except ValueError:
    #     event_tools.addActorAction(event_tools.findActor(flowchart, 'ShadowLink'), 'PopStart')

    # try:
    #     event_tools.findActor(flowchart, 'ShadowLink').find_action('LookAtCharacter')
    # except ValueError:
    #     event_tools.addActorAction(event_tools.findActor(flowchart, 'ShadowLink'), 'LookAtCharacter')

    # try:
    #     event_tools.findActor(flowchart, 'ShadowLink').find_action('AimCompassPoint')
    # except ValueError:
    #     event_tools.addActorAction(event_tools.findActor(flowchart, 'ShadowLink'), 'AimCompassPoint')

    # try:
    #     event_tools.findActor(flowchart, 'ShadowLink').find_action('PlayAnimation')
    # except ValueError:
    #     event_tools.addActorAction(event_tools.findActor(flowchart, 'ShadowLink'), 'PlayAnimation')

    # try:
    #     event_tools.findActor(flowchart, 'ShadowLink').find_action('PlayTailorOtherChannelEx')
    # except ValueError:
    #     event_tools.addActorAction(event_tools.findActor(flowchart, 'ShadowLink'), 'PlayTailorOtherChannelEx')

    # try:
    #     event_tools.findActor(flowchart, 'ShadowLink').find_action('ModelVisibility')
    # except ValueError:
    #     event_tools.addActorAction(event_tools.findActor(flowchart, 'ShadowLink'), 'ModelVisibility')

    # try:
    #     event_tools.findActor(flowchart, 'ShadowLink').find_action('SetActorSwitch')
    # except ValueError:
    #     event_tools.addActorAction(event_tools.findActor(flowchart, 'ShadowLink'), 'SetActorSwitch')
