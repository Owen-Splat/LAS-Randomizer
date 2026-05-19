# TODO: WE NEED TO FIX INSTRUMENTS AND DUNGEONS ITEMS AS BASE MODEL LIST AS WELL AS CHECKING
# IF A CHECK IS A DUNGEON OR NOT AND SETTINGS TO SEE IF IT SHOULD CONTAIN DUNGEON ITEMS

class ItemInfoManager:
    def __init__(self, mod_generator):
        self.parent = mod_generator
        self.createBaseModelList()

        # self.dungeon_trap_models = self.trap_models.copy()
        # self.dungeon_trap_models.update({
        #     'SmallKey': 'ItemSmallKey.bfres',
        #     'NightmareKey': 'ItemNightmareKey.bfres',
        #     'StoneBeak': 'ItemStoneBeak.bfres',
        #     'Compass': 'ItemCompass.bfres',
        #     'DungeonMap': 'ItemDungeonMap.bfres'
        # })

        # if self.settings['dungeon-items'] != 'standard':
        #     self.trap_models.update({
        #     'SmallKey': 'ItemSmallKey.bfres',
        #     'NightmareKey': 'ItemNightmareKey.bfres',
        # })

        # if self.settings['dungeon-items'] == 'keys+mcb':
        #     self.trap_models.update({
        #     'StoneBeak': 'ItemStoneBeak.bfres',
        #     'Compass': 'ItemCompass.bfres',
        #     'DungeonMap': 'ItemDungeonMap.bfres'
        # })


    def createBaseModelList(self) -> None:
        self.instruments = (
            'FullMoonCello',
            'ConchHorn',
            'SeaLilysBell',
            'SurfHarp',
            'WindMarimba',
            'CoralTriangle',
            'EveningCalmOrgan',
            'ThunderDrum'
        )

        self.trap_models = ITEM_MODELS.copy()

        for i in self.parent.placements['starting-items']:
            i = self.parent.item_defs[i]['item-key']
            if i == 'SwordLv1':
                i = 'SinkingSword'
            if i in ['SinkingSword', 'Shield', 'PowerBraceletLv1']:
                if self.parent.placements['starting-items'].count(i) < 2:
                    continue
            if i in self.trap_models:
                del self.trap_models[i]

        if self.parent.settings["Shuffle Instruments"] in ("Vanilla", "Dungeon Rewards"):
            for inst in self.instruments:
                if inst in self.trap_models:
                    del self.trap_models[inst]


    def getValidTrapModels(self, check: str) -> dict:
        return self.trap_models


    def getItemInfo(self, check: str) -> tuple[str, int]:
        item_key: str = self.parent.item_defs[self.parent.placements[check]]['item-key']
        item_index: int = self.parent.placements['indexes'][check] if check in self.parent.placements['indexes'] else -1
        return item_key, item_index


    def getItemInfoWithModel(self, check: str, model_list={}):
        item: str = self.parent.placements[check]
        item_key, item_index = self.getItemInfo(check)

        if item_key[-4:] != 'Trap':
            model_path: str = self.parent.item_defs[item]['model-path']
            model_name: str = self.parent.item_defs[item]['model-name']
        else:
            trap_models: dict = self.getValidTrapModels(check)
            model_name: str = self.parent.cosmetic_rng.choice(list(trap_models))
            model_path: str = trap_models[model_name]

        return item_key, item_index, model_path, model_name


# item models so that traps can be disguised as other items
ITEM_MODELS = {
    'SinkingSword': 'ObjSinkingSword.bfres',
    # 'SwordLv2': 'ItemSwordLv2.bfres',
    'Shield': 'ItemShield.bfres',
    # 'MirrorShield': 'ItemMirrorShield.bfres',
    'Bomb': 'ItemBomb.bfres',
    # 'Bow': 'ItemBow.bfres',
    'Arrow': 'ItemArrow.bfres',
    'HookShot': 'ItemHookShot.bfres',
    'Boomerang': 'ItemBoomerang.bfres',
    'MagicRod': 'ItemMagicRod.bfres',
    # 'Shovel': 'ItemShovel.bfres',
    'SleepyMushroom': 'ItemSleepyMushroom.bfres',
    'MagicPowder': 'ItemMagicPowder.bfres',
    'RocsFeather': 'ItemRocsFeather.bfres',
    'PowerBraceletLv1': 'ItemPowerBraceletLv1.bfres',
    # 'PowerBraceletLv2': 'ItemPowerBraceletLv2.bfres',
    'PegasusBoots': 'ItemPegasusBoots.bfres',
    'Ocarina': 'ItemOcarina.bfres',
    'Marin': 'NpcMarin.bfres',
    'ManboTamegoro': 'NpcManboTamegoro.bfres',
    'Mamu': 'NpcMamu.bfres',
    'Flippers': 'ItemFlippers.bfres',
    'SecretMedicine': 'ItemSecretMedicine.bfres',
    'SecretSeashell': 'ItemSecretSeashell.bfres',
    'TailKey': 'ItemTailKey.bfres',
    'SlimeKey': 'ItemSlimeKey.bfres',
    'AnglerKey': 'ItemAnglerKey.bfres',
    'FaceKey': 'ItemFaceKey.bfres',
    'BirdKey': 'ItemBirdKey.bfres',
    # 'YoshiDoll': 'ItemYoshiDoll.bfres',
    'Ribbon': 'ItemRibbon.bfres',
    'DogFood': 'ItemDogFood.bfres',
    'Bananas': 'ItemBananas.bfres',
    'Stick': 'ItemStick.bfres',
    'Honeycomb': 'ItemHoneycomb.bfres',
    'Pineapple': 'ItemPineapple.bfres',
    'Hibiscus': 'ItemHibiscus.bfres',
    'Letter': 'ItemLetter.bfres',
    'Broom': 'ItemBroom.bfres',
    'FishingHook': 'ItemFishingHook.bfres',
    'Necklace': 'ItemNecklace.bfres',
    'MermaidsScale': 'ItemMermaidsScale.bfres',
    'MagnifyingLens': 'ItemMagnifyingLens.bfres',
    'FullMoonCello': 'ItemFullMoonCello.bfres',
    'ConchHorn': 'ItemConchHorn.bfres',
    'SeaLilysBell': 'ItemSeaLilysBell.bfres',
    'SurfHarp': 'ItemSurfHarp.bfres',
    'WindMarimba': 'ItemWindMarimba.bfres',
    'CoralTriangle': 'ItemCoralTriangle.bfres',
    'EveningCalmOrgan': 'ItemEveningCalmOrgan.bfres',
    'ThunderDrum': 'ItemThunderDrum.bfres',
    'HeartPiece': 'ItemHeartPiece.bfres',
    'HeartContainer': 'ItemHeartContainer.bfres',
    'RupeeBlue': 'ItemRupeeBlue.bfres',
    'RupeeRed': 'ItemRupeeRed.bfres',
    'RupeePurple': 'ItemRupeePurple.bfres',
    'RupeeSilver': 'ItemRupeeSilver.bfres',
    'RupeeGold': 'ItemRupeeGold.bfres',
    'Bottle': 'ItemBottle.bfres',
    'ShellRader': 'ItemShellRader.bfres',
    'GoldenLeaf': 'ItemGoldenLeaf.bfres'
}

# CUSTOM_MODELS = {
#     'Bomb_MaxUp': 'ObjBombBag.bfres',
#     'Arrow_MaxUp': 'ObjArrowBag.bfres',
#     'MagicPowder_MaxUp': 'ObjPowderBag.bfres'
# }
