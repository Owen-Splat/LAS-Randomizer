from RandomizerCore.Tools.oead_tools import parseStruct, dictToStruct


class ItemsDatasheetFixes:
    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        sheet = self.parent.file_manager.readFile('Items.gsheet')
        self.makeItemChanges(sheet)
        self.parent.file_manager.writeFile('Items.gsheet', sheet)


    def makeItemChanges(self, sheet) -> None:
        dummy = None
        for item in sheet['values']:
            if not self.parent.thread_active:
                break

            # we automatically set the gettingFlag when obtaining items via exlaunch
            # this eliminates the need to put a bunch of stuff in our ItemGetManager
            if item['symbol'] in ITEM_GETTING_FLAGS:
                item['gettingFlag'] = ITEM_GETTING_FLAGS[item['symbol']]

            # Set new npcKeys for items to change how they appear when Link holds it up
            if item['symbol'] == 'SmallKey':
                item['npcKey'] = 'PatchSmallKey'
                dummy = parseStruct(item) # create copy to use as a base for custom entries
            if item['symbol'] == 'Honeycomb':
                item['npcKey'] = 'PatchHoneycomb'
            if item['symbol'] == 'Stick':
                item['npcKey'] = 'PatchStick'
            if item['symbol'] == 'SlimeKey':
                item['npcKey'] = 'PatchSlimeKey'
            if item['symbol'] == 'HeartPiece':
                item['npcKey'] = 'PatchHeartPiece'

            # songs and tunics are patched to use the model from the npcKey
            # capacity upgrades have the same patch, but we don't need to edit them here
            if item['symbol'] == 'Song_WindFish':
                item['npcKey'] = 'NpcMarin'
            if item['symbol'] == 'Song_Mambo':
                item['npcKey'] = 'NpcManboTamegoro'
            if item['symbol'] == 'Song_Soul':
                item['npcKey'] = 'NpcMamu'

            # set the tunic npcKeys to empty strings so that nothing gets held up
            if item['symbol'] == 'ClothesGreen':
                item['npcKey'] = ''
            if item['symbol'] == 'ClothesRed':
                item['npcKey'] = ''
            if item['symbol'] == 'ClothesBlue':
                item['npcKey'] = ''

        if dummy is None:
            raise KeyError('SmallKey was not found in Items.gsheet')

        # create new entries for Dampe, which we will use to set the gettingFlag
        # can likely use this same method for trendy and shop in the future
        dummy['symbol'] = 'Dampe1'
        dummy['itemID'] = 63
        dummy['gettingFlag'] = 'Dampe1'
        dummy['npcKey'] = self.parent.item_defs[self.parent.placements['dampe-page-1']]['npc-key']
        sheet['values'].append(dictToStruct(dummy))
        dummy['symbol'] = 'DampeHeart'
        dummy['itemID'] = 64
        dummy['gettingFlag'] = 'DampeHeart'
        dummy['npcKey'] = self.parent.item_defs[self.parent.placements['dampe-heart-challenge']]['npc-key']
        sheet['values'].append(dictToStruct(dummy))
        dummy['symbol'] = 'Dampe2'
        dummy['itemID'] = 65
        dummy['gettingFlag'] = 'Dampe2'
        dummy['npcKey'] = self.parent.item_defs[self.parent.placements['dampe-page-2']]['npc-key']
        sheet['values'].append(dictToStruct(dummy))
        dummy['symbol'] = 'DampeBottle'
        dummy['itemID'] = 66
        dummy['gettingFlag'] = 'DampeBottle'
        dummy['npcKey'] = self.parent.item_defs[self.parent.placements['dampe-bottle-challenge']]['npc-key']
        sheet['values'].append(dictToStruct(dummy))
        dummy['symbol'] = 'DampeFinal'
        dummy['itemID'] = 67
        dummy['gettingFlag'] = 'DampeFinal'
        dummy['npcKey'] = self.parent.item_defs[self.parent.placements['dampe-final']]['npc-key']
        sheet['values'].append(dictToStruct(dummy))

        # shop items
        dummy['symbol'] = 'ShopShovel'
        dummy['itemID'] = 68
        dummy['gettingFlag'] = 'ShopShovelSteal'
        sheet['values'].append(dictToStruct(dummy))
        dummy['symbol'] = 'ShopBow'
        dummy['itemID'] = 69
        dummy['gettingFlag'] = 'ShopBowSteal'
        sheet['values'].append(dictToStruct(dummy))
        dummy['symbol'] = 'ShopHeart'
        dummy['itemID'] = 70
        dummy['gettingFlag'] = 'ShopHeartSteal'
        sheet['values'].append(dictToStruct(dummy))

        # seashell mansion presents need traps to be items entries each with a unique ID, otherwise gives a GreenRupee
        # even though IDs >127 cause a crash when they get added to the inventory, traps never actually get added
        # instead of just passing the itemKey to the present event, it checks the ID and passes the first itemKey with that ID
        # so if all the traps had the same ID, every trap would act as the first one (ZapTrap)
        if self.parent.settings["Traps"] != "None":
            dummy['symbol'] = 'ZapTrap'
            dummy['itemID'] = 127
            # dummy['gettingFlag'] = ''
            dummy['npcKey'] = 'NpcToolShopkeeper'
            sheet['values'].append(dictToStruct(dummy))
            dummy['symbol'] = 'DrownTrap'
            dummy['itemID'] = 128
            sheet['values'].append(dictToStruct(dummy))
            dummy['symbol'] = 'SquishTrap'
            dummy['itemID'] = 129
            sheet['values'].append(dictToStruct(dummy))
            dummy['symbol'] = 'DeathballTrap'
            dummy['itemID'] = 130
            sheet['values'].append(dictToStruct(dummy))
            dummy['symbol'] = 'QuakeTrap'
            dummy['itemID'] = 131
            sheet['values'].append(dictToStruct(dummy))

        # item entries for NPCs to display the correct item model before the player obtains it
        dummy['symbol'] = 'FishNecklace'
        dummy['itemID'] = 200
        dummy['npcKey'] = 'FishNecklace'
        sheet['values'].append(dictToStruct(dummy))
        dummy['symbol'] = 'SyrupPowder'
        dummy['itemID'] = 201
        dummy['npcKey'] = 'SyrupPowder'
        sheet['values'].append(dictToStruct(dummy))
        dummy['symbol'] = 'WalrusShell'
        dummy['itemID'] = 202
        dummy['npcKey'] = 'WalrusShell'
        sheet['values'].append(dictToStruct(dummy))


# bomb and powder flags make sense to trigger drops, other progression item flags might not be needed?
ITEM_GETTING_FLAGS = {
    "SwordLv1":             "SwordFoundFlag",
    "Shield":               "ShieldFoundFlag",
    "Bomb":                 "BombsFoundFlag",
    "PowerBraceletLv1":     "BraceletFoundFlag",
    "Flippers":             "FlippersFound",
    "YoshiDoll":            "TradeYoshiDollGet",
    "Ribbon":               "TradeRibbonGet",
    "DogFood":              "TradeDogFoodGet",
    "Bananas":              "TradeBananasGet",
    "Stick":                "TradeStickGet",
    "Honeycomb":            "TradeHoneycombGet",
    "Pineapple":            "TradePineappleGet",
    "Hibiscus":             "TradeHibiscusGet",
    "Letter":               "TradeLetterGet",
    "Broom":                "TradeBroomGet",
    "FishingHook":          "TradeFishingHookGet",
    "PinkBra":              "TradeNecklaceGet",
    "MermaidsScale":        "TradeMermaidsScaleGet",
    "MagnifyingLens":       "LensFoundFlag",
}