SWORD_FOUND_FLAG        = 'unused0357'
SHIELD_FOUND_FLAG       = 'unused0358'
BRACELET_FOUND_FLAG     = 'unused0359'
LENS_FOUND_FLAG         = 'unused0360'

RED_TUNIC_FOUND_FLAG    = 'unused0361'
BLUE_TUNIC_FOUND_FLAG   = 'unused0362'

GORIYA_FLAG             = 'unused0432'
MAMU_FLAG               = 'unused0433'
MANBO_FLAG              = 'unused0434'

ROOSTER_CAVE_FLAG       = 'unused0707'
DREAM_SHRINE_FLAG       = 'unused0708'
WOODS_LOOSE_FLAG        = 'unused0709'
MERMAID_CAVE_FLAG       = 'MermaidCaveItemGet'
POTHOLE_FLAG            = 'PotholeGet'

BOMBS_FOUND_FLAG        = 'BombsFound'
# BOMB_BAG_FOUND_FLAG     = 'BombBagFound'

ROOSTER_FOUND_FLAG      = 'RoosterFound'
BOWWOW_FOUND_FLAG       = 'BowWowFound'

INSTRUMENT_FLAGS = {
    'D1-instrument': 'TailCaveInstrumentGet',
    'D2-instrument': 'BottleGrottoInstrumentGet',
    'D3-instrument': 'KeyCavernInstrumentGet',
    'D4-instrument': 'AnglersTunnelInstrumentGet',
    'D5-instrument': 'CatfishsMawInstrumentGet',
    'D6-instrument': 'FaceShrineInstrumentGet',
    'D7-instrument': 'EaglesTowerInstrumentGet',
    'D8-instrument': 'TurtleRockInstrumentGet'
}

HEART_FLAGS = {
    'animal-village-northwest': 'AnimalVillageHeartGet',
    'animal-village-cave': 'AnimalVillageCaveHeartGet',
    'taltal-entrance-blocks': 'TaltalEntranceBlocksHeartGet',
    'north-wasteland': 'NorthWastelandHeartGet',
    'desert-cave': 'DesertCaveHeartGet',
    'graveyard-cave': 'GraveyardCaveHeartGet',
    'mabe-well': 'MabeWellHeartGet',
    'ukuku-cave-west-loose': 'UkukuCaveWestHeartGet',
    'ukuku-cave-east-loose': 'UkukuCaveEastHeartGet',
    'bay-passage-sunken': 'BayPassageHeartGet',
    'river-crossing-cave': 'RiverCrossingHeartGet',
    'rapids-west-island': 'RapidsWestHeartGet',
    'rapids-ascent-cave': 'RapidsAscentHeartGet',
    'kanalet-moat-south': 'KanaletMoatHeartGet',
    'south-bay-sunken': 'SouthBayHeartGet',
    'taltal-crossing-cave': 'TaltalCrossingHeartGet',
    'taltal-east-drop': 'TaltalEastHeartGet',
    'taltal-west-escape': 'TaltalWestHeartGet',
    'above-turtle-rock': 'TurtleRockHeartGet',
    'pothole-north': 'PotholeHeartGet',
    'woods-crossing-cave-loose': 'WoodsCrossingHeartGet',
    'woods-north-cave-loose': 'WoodsNorthCaveHeartGet',
    'diamond-island': 'DiamondIslandHeartGet'
}


# rooms
CHEST_ROOMS = {
 'beach-chest': 'Field_15F',
 'taltal-entrance-chest': 'Tamaranch04_02D',
 'taltal-east-left-chest': 'Field_02I',
 'dream-shrine-right': 'DreamShrine_01B',
 'armos-cave': 'ArmosShrineCave_01A',
 'goponga-cave-left': 'GopongaCave_01A',
 'goponga-cave-right': 'GopongaCave_01B',
 'ukuku-cave-west-chest': 'UkukuCave01_01A',
 'ukuku-cave-east-chest': 'UkukuCave02_02A',
 'kanalet-south-cave': 'KanaletCastleSouthCave_01A',
 'rapids-middle-island': 'Field_06N',
 'rapids-south-island': 'Field_07M',
 'swamp-chest': 'Field_04E',
 'taltal-left-ascent-cave': 'Tamaranch02_01B',
 'taltal-ledge-chest': 'Field_02N',
 'taltal-5-chest-puzzle': 'Tamaranch05_04A',
 'taltal-west-chest': 'Field_02E',
 'villa-cave': 'RichardCave_01A',
 'woods-crossing-cave-chest': 'MysteriousWoodsCave01_02B',
 'woods-north-cave-chest': 'MysteriousWoodsCave02_01A',
 'woods-south-chest': 'Field_08B',
 'woods-north-chest': 'Field_05B',
 'D1-west-hallway': 'Lv01TailCave_05A',
 'D1-middle-ledge': 'Lv01TailCave_05D',
 'D1-3-of-a-kind': 'Lv01TailCave_05F',
 'D1-bomb-room': 'Lv01TailCave_06B',
 'D1-middle-kill-chest': 'Lv01TailCave_06C',
 'D1-spark-chest': 'Lv01TailCave_06D',
 'D1-button-chest': 'Lv01TailCave_07D',
 'D1-stalfos-chest': 'Lv01TailCave_07E',
 'D1-4-zols-chest': 'Lv01TailCave_08B',
 'D2-boos': 'Lv02BottleGrotto_02B',
 'D2-long-room-west': 'Lv02BottleGrotto_02C',
 'D2-long-room-east': 'Lv02BottleGrotto_02D',
 'D2-vacuum-mouth-room': 'Lv02BottleGrotto_03C',
 'D2-kill-puzzle': 'Lv02BottleGrotto_03F',
 'D2-west-chest': 'Lv02BottleGrotto_06B',
 'D2-entrance-chest': 'Lv02BottleGrotto_08C',
 'D2-single-shy-guy': 'Lv02BottleGrotto_08D',
 'D2-peg-circle': 'Lv02BottleGrotto_08E',
 'D2-button-chest': 'Lv02BottleGrotto_08F',
 'D3-north-chest': 'Lv03KeyCavern_01C',
 'D3-central-ledge': 'Lv03KeyCavern_02A',
 'D3-central-chest': 'Lv03KeyCavern_02C',
 'D3-east-ledge': 'Lv03KeyCavern_02D',
 'D3-hallway-4': 'Lv03KeyCavern_04B',
 'D3-hallway-3': 'Lv03KeyCavern_05B',
 'D3-hallway-2': 'Lv03KeyCavern_06B',
 'D3-hallway-side-room': 'Lv03KeyCavern_06C',
 'D3-hallway-1': 'Lv03KeyCavern_07B',
 'D3-vacuum-mouth': 'Lv03KeyCavern_08C',
 'D4-north-chest': 'Lv04AnglersTunnel_02D',
 'D4-east-side-north': 'Lv04AnglersTunnel_03G',
 'D4-east-side-south': 'Lv04AnglersTunnel_05G',
 'D4-west-ledge': 'Lv04AnglersTunnel_07C',
 'D4-east-of-puzzle': 'Lv04AnglersTunnel_04D',
 'D4-south-of-puzzle': 'Lv04AnglersTunnel_05C',
 'D4-central-room': 'Lv04AnglersTunnel_05D',
 'D4-small-island': 'Lv04AnglersTunnel_06F',
 'D4-ledge-north': 'Lv04AnglersTunnel_04F',
 'D4-statues-chest': 'Lv04AnglersTunnel_07F',
 'D4-lobby': 'Lv04AnglersTunnel_07E',
 'D4-crystals': 'Lv04AnglersTunnel_08E',
 'D5-past-master-stalfos-3': 'Lv05CatfishsMaw_01E',
 'D5-water-tunnel': 'Lv05CatfishsMaw_02E',
 'D5-right-side-north': 'Lv05CatfishsMaw_02G',
 'D5-right-side-middle': 'Lv05CatfishsMaw_03G',
 'D5-right-side-east': 'Lv05CatfishsMaw_03H',
 'D5-past-master-stalfos-1': 'Lv05CatfishsMaw_05G',
 'D5-west-chest': 'Lv05CatfishsMaw_06C',
 'D5-helmasaurs': 'Lv05CatfishsMaw_07D',
 'D5-west-stairs-chest': 'Lv05CatfishsMaw_08E',
 'D5-near-entrance': 'Lv05CatfishsMaw_08G',
 'D6-far-northwest': 'Lv06FaceShrine_02A',
 'D6-far-northeast': 'Lv06FaceShrine_02H',
 'D6-statue-line-north': 'Lv06FaceShrine_03B',
 'D6-statue-line-south': 'Lv06FaceShrine_04B',
 'D6-pot-chest': 'Lv06FaceShrine_03G',
 'D6-canal': 'Lv06FaceShrine_04G',
 'D6-3-wizzrobes': 'Lv06FaceShrine_05A',
 'D6-gated-hallway-north': 'Lv06FaceShrine_06C',
 'D6-gated-hallway-south': 'Lv06FaceShrine_07C',
 'D6-southwest-chest': 'Lv06FaceShrine_07B',
 'D6-wizzrobes-ledge': 'Lv06FaceShrine_07G',
 'D7-1f-west': 'Lv07EagleTower_07A',
 'D7-west-ledge': 'Lv07EagleTower_05A',
 'D7-east-ledge': 'Lv07EagleTower_05D',
 'D7-3ofakind-north': 'Lv07EagleTower_01B',
 'D7-2f-horseheads': 'Lv07EagleTower_01C',
 'D7-3ofakind-south': 'Lv07EagleTower_04B',
 'D7-blue-pegs-chest': 'Lv07EagleTower_03D',
 'D7-3f-horseheads': 'Lv07EagleTower_01G',
 'D7-grim-creeper': 'Lv07EagleTower_02H',
 'D8-far-northwest': 'Lv08TurtleRock_02A',
 'D8-far-northeast': 'Lv08TurtleRock_02H',
 'D8-left-exit-chest': 'Lv08TurtleRock_03C',
 'D8-dodongos': 'Lv08TurtleRock_03F',
 'D8-northern-ledge': 'Lv08TurtleRock_02E',
 'D8-beamos-chest': 'Lv08TurtleRock_04B',
 'D8-torches': 'Lv08TurtleRock_05B',
 'D8-west-roomba': 'Lv08TurtleRock_06B',
 'D8-surrounded-by-blocks': 'Lv08TurtleRock_06D',
 'D8-sparks-chest': 'Lv08TurtleRock_07B',
 'D8-east-of-pots': 'Lv08TurtleRock_07F',
 'D8-far-southwest': 'Lv08TurtleRock_08A',
 'D8-far-southeast': 'Lv08TurtleRock_08H',
 'D0-northern-chest': 'Lv10ClothesDungeon_04F',
 'D0-zol-pots': 'Lv10ClothesDungeon_05D',
 'D0-south-orbs': 'Lv10ClothesDungeon_07F',
 'D0-west-color-puzzle': 'Lv10ClothesDungeon_07D',
 'D0-putters': 'Lv10ClothesDungeon_08E'}


SMALL_KEY_ROOMS = {
 'D1-beetles': 'Lv01TailCave_08C',
 'D2-double-stalfos': 'Lv02BottleGrotto_07D',
 'D2-double-shy-guys': 'Lv02BottleGrotto_07F',
 'D3-pre-boss': 'Lv03KeyCavern_08G',
 'D3-triple-bombites': 'Lv03KeyCavern_01B',
 'D3-pairodds': 'Lv03KeyCavern_03A',
 'D3-five-zols': 'Lv03KeyCavern_04C',
 'D3-basement-north': 'Lv03KeyCavern_03G',
 'D3-basement-west': 'Lv03KeyCavern_04F',
 'D3-basement-south': 'Lv03KeyCavern_05G',
 'D4-sunken-item': 'Lv04AnglersTunnel_04E', # Also Lv04AnglersTunnel_06A, but leave vanilla for now.
 'D5-crystal-blocks': 'Lv05CatfishsMaw_01C',
 'D6-wizzrobe-pegs': 'Lv06FaceShrine_03D',
 'D6-tile-room': 'Lv06FaceShrine_05D',
 'D7-like-likes': 'Lv07EagleTower_08D',
 'D7-hinox': 'Lv07EagleTower_04A',
 'D8-gibdos': 'Lv08TurtleRock_03G',
 'D8-statue': 'Lv08TurtleRock_04C',
 'D8-west-vire': 'Lv08TurtleRock_06A',
 'D8-east-roomba': 'Lv08TurtleRock_07G',
 'D0-north-orbs': 'Lv10ClothesDungeon_05E',
 'D0-east-color-puzzle': 'Lv10ClothesDungeon_05F',
 'pothole-final': 'Field_13G'
}


GOLDEN_LEAF_ROOMS = {
    'kanalet-crow': 'Field_06I',
    'kanalet-mad-bomber': 'Field_06K',
    'kanalet-kill-room': 'KanaletCastle_02A',
    'kanalet-bombed-guard': 'KanaletCastle_01C',
    'kanalet-final-guard': 'KanaletCastle_01D'
}


INSTRUMENT_ROOMS = {
    'D1-instrument': 'Lv01TailCave_03G',
    'D2-instrument': 'Lv02BottleGrotto_04F',
    'D3-instrument': 'Lv03KeyCavern_06G',
    'D4-instrument': 'Lv04AnglersTunnel_03B',
    'D5-instrument': 'Lv05CatfishsMaw_01D',
    'D6-instrument': 'Lv06FaceShrine_03E',
    'D7-instrument': 'Lv07EagleTower_02G',
    'D8-instrument': 'Lv08TurtleRock_01D'
}


HEART_ROOMS = {
    'animal-village-northwest': 'Field_13L',
    'animal-village-cave': 'AnimalVillageCave_01A',
    'taltal-entrance-blocks': 'Tamaranch04_03B',
    'north-wasteland': 'Field_05H',
    'desert-cave': 'LanmolaCave_01A',
    'graveyard-cave': 'UnderGrave_01B',
    'mabe-well': 'TownWell_01A',
    'ukuku-cave-west-loose': 'UkukuCave01_01A',
    'ukuku-cave-east-loose': 'UkukuCave02_01B',
    'bay-passage-sunken': 'MadBattersWellEnter_01B',
    'river-crossing-cave': 'AnimalVillageEnter_01B',
    'rapids-west-island': 'Field_06M',
    'rapids-ascent-cave': 'RapidsRideExit_01A',
    'kanalet-moat-south': 'Field_08J',
    'south-bay-sunken': 'Field_15J',
    'taltal-crossing-cave': 'Tamaranch04_02C',
    'taltal-east-drop': 'EagleTowerExit_01A',
    'taltal-west-escape': 'Field_03B',
    'above-turtle-rock': 'Field_01A',
    'pothole-north': 'Field_12H',
    'woods-crossing-cave-loose': 'MysteriousWoodsCave01_01A',
    'woods-north-cave-loose': 'MysteriousWoodsCave02_01A',
    'diamond-island': 'Field_05E'
}


# music files
MUSIC_FILES = (
    '03_NameInput',
    '04_House_First',
    '06_Field_First',
    '07_Owl.ry',
    '07_OwlLast',
    '09_Field_Normal_Intro',
    '10_Field_Normal',
    '11_Meve',
    '12_StrangeForest',
    '15_Shop',
    '15_Shop_Fast',
    '16_Fairy',
    '18_GameShop',
    '19_House',
    '20_MarineSing',
    '22_Cave',
    '23_Dangeon1_TailCave',
    '24_Dangeon_2DCave',
    '25_Dangeon_BossMiddle',
    '26_Dangeon_Boss',
    '30_Event_RescueBowwow',
    '31_Event_RescueBowwow_intro',
    '32_Wright',
    '34_Dangeon2_PotCave',
    '36_Richard',
    '38_Dangeon_Castle',
    '39_Dangeon_Key',
    '42_AnimalVillage',
    '43_GoatHouse',
    '44_DreamShrine_Entrance',
    '46_DreamShrine',
    '50_TaruTaru',
    '50_TaruTaru_AfterRescue',
    '52_Dangeon4_BasinAngler',
    '55_GhostHouse',
    '56_FishingMan',
    '57_Dangeon5_CatFish',
    '62_Dangeon6_TempleOfFace',
    '64_Dangeon_Clothes',
    '66_ChikenHut',
    '67_Dangeon7_TowerOfEagle',
    '72_Dangeon7_TurtleRock',
    '74_RapidsFallGameOfRaft',
    '76_Dangeon_HolyEgg',
    '77_LastBoss_DemoText',
    '78_LastBoss_Appear-Battle',
    '79_LastBossWin',
    '84_Title_NoIntro',
    '85_TotakekeSong',
    '86_ZeldaName',
    '87_Richard2.30',
    'crane_pond',
    'FishingHit',
    'Koakumakun',
    'LastBossFinal',
    'MarineName',
    'PanelDanjeonResult',
    'PanelDanjeonStrings_Wind_Timpani',
    'PanelDanjeonStrings5',
    'PanelDanjeonWind',
    'PanelDanpeiEdit',
    'PanelDanpeiHouse',
    'PanelShadowLink',
    'RapidTimeAttack',
    'RecorderField_FushigiNoMori',
    'RecorderField_Main',
    'RecorderField_MainNormal',
    'RecorderField_TaruTaru',
    'ShellHouse',
    'Title_OP'
)
MUSIC_SUFFIX = '.ry.48.dspadpcm.bfstm'


# item models so that zap traps can be disguised as other items
ITEM_MODELS = {
    'SinkingSword': 'ObjSinkingSword.bfres',
    # 'SwordLv2': 'ItemSwordLv2.bfres',
    'Shield': 'ItemShield.bfres',
    # 'MirrorShield': 'ItemMirrorShield.bfres',
    'Bomb': 'ItemBomb.bfres',
    # 'Bow': 'ItemBow.bfres',
    'HookShot': 'ItemHookShot.bfres',
    'Boomerang': 'ItemBoomerang.bfres',
    'MagicRod': 'ItemMagicRod.bfres',
    # 'Shovel': 'ItemShovel.bfres',
    'SleepyMushroom': 'ItemSleepyMushroom.bfres',
    # 'MagicPowder': 'ItemMagicPowder.bfres',
    'RocsFeather': 'ItemRocsFeather.bfres',
    'PowerBraceletLv1': 'ItemPowerBraceletLv1.bfres',
    # 'PowerBraceletLv2': 'ItemPowerBraceletLv2.bfres',
    'PegasusBoots': 'ItemPegasusBoots.bfres',
    'Ocarina': 'ItemOcarina.bfres',
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


CUSTOM_MODELS = (
    # 'ItemBallad',
    # 'ItemMambo',
    # 'ItemSoul',
    # 'ObjBombBag',
    # 'ObjArrowBag'
)
MODELS_SUFFIX = '.bfres'


ENTRANCE_ROOMS = {
    'Lv01TailCave': {
        '08D': {
            'Actor': 2,
            'Target': 'Field_14D'
        }
    },
    'Lv02BottleGrotto': {
        '08C': {
            'Actor': 3,
            'Target': 'Field_03E'
        }
    },
    'Lv03KeyCavern': {
        '08B': {
            'Actor': 2,
            'Target': 'Field_12F',
        }
    },
    'Lv04AnglersTunnel': {
        '08D': {
            'Actor': 2,
            'Target': 'Field_03L_a',
        }
    },
    'Field': {
        '03E': 0,
        '12F': 0,
        '14D': 0,
    }
}


CHEST_SIZES = {
    'important': 1.2,
    'seashell': 1.0,
    'good': 1.0,
    'junk': 0.8,
    'D1': 1.0,
    'D2': 1.0,
    'D3': 1.0,
    'D4': 1.0,
    'D5': 1.0,
    'D6': 1.0,
    'D7': 1.0,
    'D8': 1.0,
    'D0': 1.0
}


# BASE_BUILD_ID = 'AE16F71E002AF8CB059A9A74C4D90F34BA984892' # version 1.0.0
# UPD_BUILD_ID = '909E904AF78AC1B8DEEFE97AB2CCDB51968f0EC7' # version 1.0.1

# # instruction addr: [string addr, operand]
# BGM_OFFSETS = {
#     0x009e6b78: [0x016c9c83, 'x8'], # BGM_ANIMAL_VILLAGE
#     0x000ae578: [0x016e4733, 'x8'], # BGM_DUNGEON_2D_SIDEVIEW
#     0x00ce8d28: [0x016d5d3f, 'x8'], # BGM_DUNGEON_BOSS_MIDDLE
#     0x000ae858: [0x016d5d3f, 'x22'], # BGM_DUNGEON_BOSS_MIDDLE
#     0x000b2e04: [0x016bed50, 'x8'], # BGM_DUNGEON_LV8_ENT_BATTLE
#     0x000ae8e4: [0x016bed50, 'x21'], # BGM_DUNGEON_LV8_ENT_BATTLE
#     0x000afc44: [0x016dbcc3, 'x9'], # BGM_ENSEMBLE_ALL
#     0x000afc9c: [0x016b9845, 'x8'], # BGM_ENSEMBLE_DUET
#     0x000afe24: [0x016e7d02, 'x8'], # BGM_ENSEMBLE_INST
#     0x009f3b84: [0x016ba1ab, 'x8'], # BGM_EVENT_MARINE_IN_BEACH
#     0x009f35d4: [0x016ba1ab, 'x8'], # BGM_EVENT_MARINE_IN_BEACH
#     0x009e6bc8: [0x016d8e72, 'x8'], # BGM_EVENT_RESCUE_BOWBOW
#     0x000ae784: [0x016d8e72, 'x21'], # BGM_EVENT_RESCUE_BOWBOW
#     0x000a70d0: [0x016d8e72, 'x8'], # BGM_EVENT_RESCUE_BOWBOW
#     0x000a6544: [0x016d8e72, 'x8'], # BGM_EVENT_RESCUE_BOWBOW
#     0x009e6ba0: [0x016c296f, 'x8'], # BGM_EVENT_RESCUE_BOWBOW_INTRO
#     0x0009d734: [0x016ddb98, 'x9'], # BGM_FANFARE_BOSS_HEART_GET
#     0x000ae510: [0x016b7d98, 'x8'], # BGM_FIELD_FIRST
#     0x000ae87c: [0x016c5e26, 'x21'], # BGM_FIELD_MARINE
#     0x00df24a4: [0x016bf7f2, 'x8'], # BGM_FIELD_NORMAL
#     0x000ae694: [0x016bf7f2, 'x11'], # BGM_FIELD_NORMAL
#     0x000ae7e8: [0x016d6ba4, 'x22'], # BGM_FIELD_NORMAL_INTRO
#     0x00df286c: [0x016d43a0, 'x19'], # BGM_GAME_OF_RAFT
#     0x00dee7f4: [0x016d43a0, 'x8'], # BGM_GAME_OF_RAFT
#     0x000ae80c: [0x016d43a0, 'x22'], # BGM_GAME_OF_RAFT
#     0x000ae478: [0x016eb6a0, 'x10'], # BGM_HOUSE
#     0x0082e264: [0x016b9d8b, 'x8'], # BGM_NAME_INPUT
#     0x00b05804: [0x016c4ac9, 'x8'], # BGM_NAZOTOKI_SEIKAI
#     0x00a92664: [0x016c4ac9, 'x8'], # BGM_NAZOTOKI_SEIKAI
#     0x008f4504: [0x016c4ac9, 'x8'], # BGM_NAZOTOKI_SEIKAI
#     0x00ce9048: [0x016c0eb7, 'x20'], # BGM_PANEL_SHADOW_LINK
#     0x00ce8f34: [0x016c0eb7, 'x8'], # BGM_PANEL_SHADOW_LINK
#     0x00ce8d54: [0x016c0eb7, 'x8'], # BGM_PANEL_SHADOW_LINK
#     0x00dee860: [0x016c0f38, 'x8'], # BGM_RAFTING_TIMEATTACK
#     0x000ae830: [0x016c0f38, 'x8'], # BGM_RAFTING_TIMEATTACK
#     0x00a25dc0: [0x016b8579, 'x22'], # BGM_RICHARD_230
#     0x000ae6fc: [0x016d02e3, 'x11'], # BGM_STRANGE_FOREST
#     0x000aea38: [0x016caecb, 'x8'], # BGM_STRANGE_FOREST_MARINE
#     0x000ae6c8: [0x016c1ffa, 'x11'], # BGM_TARUTARU
#     0x000ae944: [0x016ddbb3, 'x8'], # BGM_TARUTARU2_AFTER_THE_RESCUE
#     0x000ae984: [0x016c78e4, 'x8'], # BGM_TARUTARU_MARINE
#     0x00eb06e4: [0x016bbe3e, 'x8'], # BGM_TOTAKEKE_SONG
#     0x00eb0644: [0x016e87f6, 'x8'], # BGM_ZELDA_NAME
# }

# # String addr: instruction addr
#     # 0x016b8548, # BGM_FAIRY
#     # 0x016d52f1, # BGM_FIELD_MARINE_NORMAL
#     # 0x016c041c, # BGM_GAMEOVER
#     # 0x016b9ce8, # BGM_INST_BELL
#     # 0x016df9dc, # BGM_INST_DRUM
#     # 0x016c45f9, # BGM_INST_HARP
#     # 0x016c08eb, # BGM_INST_HORN
#     # 0x016e802a, # BGM_INST_MARIMBA
#     # 0x016dc116, # BGM_INST_ORGAN
#     # 0x016c255d, # BGM_INST_TRIANGLE
#     # 0x016d20b7, # BGM_INST_VIOLIN
#     # 0x016d0608, # BGM_LASTBOSS_APPEAR
#     # 0x016e2f72, # BGM_LASTBOSS_BATTLE
#     # 0x016b8941, # BGM_MARINE_NAME
#     # 0x016ebe06, # BGM_MARINE_SING
#     # 0x016ba1a2, # BGM_MEVE
#     # 0x016e355f, # BGM_MINIGAME_FISHING
#     # 0x016caefd, # BGM_NUTS
#     # 0x016c40cb, # BGM_NUTS_INTRO
#     # 0x016caee5, # BGM_PANEL_DUNG_BEGINNER
#     # 0x016bb251, # BGM_PANEL_DUNG_DIFFICULT
#     # 0x016d6bbb, # BGM_PANEL_DUNG_MEDIUM
#     # 0x016e1439, # BGM_PANEL_EDIT_MODE
