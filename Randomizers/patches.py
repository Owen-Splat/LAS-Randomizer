from Tools.patcher import Patcher
# from Randomizers.data import BGM_ADDRESSES


def changeVanillaBehavior(patcher: Patcher):
    """Makes needed changes to hardcoded behavior"""
    
    # Ignore companions when trying to open Color Dungeon
    patcher.addPatch(0xc868d4, 'ccmp w9, #0, #4, ne')

    # Will eventually write a patch to make item actors load even if you have the item
    # Ball & Chain Solder fix will be among this



# def fixZoneMusic(patcher: Patcher):
#     """Allows event music to keep playing when transitioning into another zone"""
    
#     # Makes the randomized rapids music continue to play by changing the hardcoded field BGM
#     patcher.addPatch(0xae694, f'adrp x11, ')
#     patcher.addPatch(0xae698, f'add x11, x11, #')
#     patcher.addPatch(0xae6a0, f'adrp x13, ')
#     patcher.addPatch(0xae6a4, f'add x13, x13, #')