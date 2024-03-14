from RandomizerCore.Tools.exefs_editor.patcher import Patcher
import random



def writePatches(patcher: Patcher, settings: dict, rand_state: tuple):
    """Writes the necessary asm for the randomizer"""
    
    # carry over the internal random state
    random.setstate(rand_state)
    
    # Change the companion check for Color Dungeon from == 0 to != 5
    # 0=alone, 1=bowwow, 2=marin, 3=ghost, 4=rooster
    # 5 does not exist so the condition will always be met
    patcher.addPatch(0xc868d4, 'ccmp w9, #0, #5, ne')
    
    # Iron Ball Soldier checks both for GoldenLeaf[4] and for Actor Switch 0 (flag)
    # If the player does have it, jump to the code that checks for the actor switch
    patcher.addPatch(0x6a62f8, 'cbz w0, 0x6a6340')
    
    # Make Inventory.RemoveItem itemType 0 remove Bottle[1] instead of SwordLv1 since this case is unused
    # This is done by using bitwise AND to only change the Bottle[1] bit to 0
    # The reason for this is to add/remove the fishing bottle from the inventory to control if it shows in the pond or not
    patcher.addPatch(0x7e1f6c, """
    adrp x8, 0x14e0000;
    ldr x8, [x8, #0x368];
    ldr w9, [x8, #0xa8];
    and w9, w9, 0xFFFFBFFF;
    str w9, [x8, #0xa8];
    b -0x19C;
    """)
    
    # make songs, tunics, and capacity upgrades show the correct item model by making them go to the default case
    # default case means it will use the model in Items.gsheet rather than a hardcoded one
    patcher.addPatch(0xd798c4, 'b +0x134')
    patcher.addPatch(0xd79814, 'b +0x1e4')
    patcher.addPatch(0xd79804, 'b +0x1f4')
    
    # if enemizer is enabled, randomize the green zol chest trap into another enemy
    if settings['randomize-enemies']:
        from RandomizerCore.Data.randomizer_data import ENEMY_DATA
        enemy_id = random.choice(ENEMY_DATA['Chest_Enemies'])
        patcher.addPatch(0xca92c0, f'mov w9, #{enemy_id}')
    
    # # if keysanity is enabled, use the item index to determine which level it goes to
    # if settings['dungeon-items'] != 'standard':
    #     allowKeysanity(patcher, settings['dungeon-items'])
    
    optionalPatches(patcher, settings)



def optionalPatches(patcher: Patcher, settings: dict):
    """Adds the optional gameplay patches to the seed"""
    
    # if 1HKO mode is enabled, make all forms of damage substract 80 health to make Link always die in 1 hit
    if settings['1HKO']:
        patcher.addPatch(0xd4c754, 'sub w22, w8, #80')
        patcher.addPatch(0xdb1f74, 'sub w8, w21, #80')
    
    # beam slash with either sword
    if settings['lv1-beam']:
        patcher.addPatch(0xde1ba8, 'ldrb w9, [x8, #0xa8]')
    
    # change magic rod projectile instance limit from 3 to 16
    if settings['nice-rod']:
        patcher.addPatch(0xd51698, 'cmp x19, #0x10')



def allowKeysanity(patcher: Patcher, dungeon_items: str):
    """Overrides the current level value with the index to work outside of dungeons"""
    
    # Set the current level value to the index, this is fine since only the dungeon items use it
    # Because Dampe dungeons function outside of the randomizer loop, use the normal level value if it's 8

    # Compare count instead of current level just to skip over the "level can't be non dungeon" check
    # Will return if count == 0 instead of level == 0xff
    patcher.addPatch(0x8d0cf4, 'cmp w8, #-1') # SmallKey
    patcher.addPatch(0x8d0cf8, """
    b.eq +8;
    mov w8, #8;
    """)
    
    patcher.addPatch(0x8d0e58, 'cmp w8, #-1') # NightmareKey
    patcher.addPatch(0x8d0e5c, """
    b.eq +8;
    mov w8, #8;
    """)

    if dungeon_items == 'keys+mcb':
        patcher.addPatch(0x8d0e04, 'cmp w8, #-1') # Compass
        patcher.addPatch(0x8d0e08, """
        b.eq +8;
        mov w8, #8;
        """)

        patcher.addPatch(0x8d1278, 'cmp w8, #-1') # DungeonMap
        patcher.addPatch(0x8d127c, """
        b.eq +8;
        mov w8, #8;
        """)

        patcher.addPatch(0x8d1478, 'cmp w8, #-1') # StoneBeak
        patcher.addPatch(0x8d147c, """
        b.eq +8;
        mov w8, #8;
        """)



# def fixZoneMusic(patcher: Patcher):
#     """Allows event music to keep playing when transitioning into another zone"""
    
#     # Makes the randomized rapids music continue to play by changing the hardcoded field BGM
#     patcher.addPatch(0xae694, f'adrp x11, ')
#     patcher.addPatch(0xae698, f'add x11, x11, #')
#     patcher.addPatch(0xae6a0, f'adrp x13, ')
#     patcher.addPatch(0xae6a4, f'add x13, x13, #')



# def randomizeSoundEffects(patcher: Patcher):
#     pass
