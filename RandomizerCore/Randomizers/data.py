SWORD_FOUND_FLAG        = 'unused0151'
SHIELD_FOUND_FLAG       = 'unused0229'
BRACELET_FOUND_FLAG     = 'unused0230'
LENS_FOUND_FLAG         = 'unused0271'

RED_TUNIC_FOUND_FLAG    = 'unused0294'
BLUE_TUNIC_FOUND_FLAG   = 'unused0357'

GORIYA_FLAG             = 'unused0358'
MAMU_FLAG               = 'unused0359'
MANBO_FLAG              = 'unused0360'

BEACH_LOOSE_FLAG        = 'unused0361'
WOODS_LOOSE_FLAG        = 'unused0362'
POTHOLE_FLAG            = 'unused0363' #'PotholeGet'
DREAM_SHRINE_FLAG       = 'unused0390'
ROOSTER_CAVE_FLAG       = 'unused0391'
MERMAID_CAVE_FLAG       = 'unused0393' #'MermaidCaveItemGet'

BOMBS_FOUND_FLAG        = 'unused0424' # 'BombsFound'

ROOSTER_FOUND_FLAG      = 'unused0425' # 'RoosterFound'
BOWWOW_FOUND_FLAG       = 'unused0426' # 'BowWowFound'

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
 'D0-putters': 'Lv10ClothesDungeon_08E'
}
PANEL_CHEST_ROOMS = {
 'panel-D1-west-hallway': 'PanelLv01TailCave_05A',
 'panel-D1-3-of-a-kind': 'PanelLv01TailCave_05F',
 'panel-D1-bomb-room': 'PanelLv01TailCave_06B',
 'panel-D1-button-chest': 'PanelLv01TailCave_07D',
 'panel-D1-stalfos-chest': 'PanelLv01TailCave_07E',
 'panel-D1-4-zols-chest': 'PanelLv01TailCave_08B',
 'panel-D1-beetles': 'PanelLv01TailCave_08C',
 'panel-D2-boos': 'PanelLv02BottleGrotto_02B',
 'panel-D2-vacuum-mouth-room': 'PanelLv02BottleGrotto_03C',
 'panel-D2-kill-puzzle': 'PanelLv02BottleGrotto_03F',
 'panel-D2-west-chest': 'PanelLv02BottleGrotto_06B',
 'panel-D2-double-stalfos': 'PanelLv02BottleGrotto_07D',
 'panel-D2-single-shy-guy': 'PanelLv02BottleGrotto_08D',
 'panel-D2-button-chest': 'PanelLv02BottleGrotto_08F',
 'panel-D3-basement-north': 'PanelLv03KeyCavern_03G',
 'panel-D3-five-zols': 'PanelLv03KeyCavern_04C',
 'panel-D3-extra-1': 'PanelLv03KeyCavern_04D',
 'panel-D3-basement-west': 'PanelLv03KeyCavern_04F',
 'panel-D3-extra-2': 'PanelLv03KeyCavern_04H',
 'panel-D3-basement-south': 'PanelLv03KeyCavern_05G',
 'panel-D3-hallway-side-room': 'PanelLv03KeyCavern_06C',
 'panel-D3-vacuum-mouth': 'PanelLv03KeyCavern_08C',
 'panel-D3-pre-boss': 'PanelLv03KeyCavern_08G',
 'panel-D4-crystals': 'PanelLv04AnglersTunnel_08E',
 'panel-D4-north-chest': 'PanelLv04AnglersTunnel_02D',
 'panel-D4-east-side-north': 'PanelLv04AnglersTunnel_03G',
 'panel-D5-crystal-blocks': 'PanelLv05CatfishsMaw_01C',
 'panel-D5-past-master-stalfos-3': 'PanelLv05CatfishsMaw_01E',
 'panel-D5-past-master-stalfos-1': 'PanelLv05CatfishsMaw_05G',
 'panel-D5-helmasaurs': 'PanelLv05CatfishsMaw_07D',
 'panel-D5-west-stairs-chest': 'PanelLv05CatfishsMaw_08E',
 'panel-D6-far-northwest': 'PanelLv06FaceShrine_02A',
 'panel-D6-extra-1': 'PanelLv06FaceShrine_02D',
 'panel-D6-far-northeast': 'PanelLv06FaceShrine_02H',
 'panel-D6-3-wizzrobes': 'PanelLv06FaceShrine_05A',
 'panel-D6-extra-2': 'PanelLv06FaceShrine_05H',
 'panel-D6-southwest-chest': 'PanelLv06FaceShrine_07B',
 'panel-D7-3ofakind-north': 'PanelLv07EagleTower_01B',
 'panel-D7-2f-horseheads': 'PanelLv07EagleTower_01C',
 'panel-D7-extra-1': 'PanelLv07EagleTower_02D',
 'panel-D7-hinox': 'PanelLv07EagleTower_04A',
 'panel-D7-3f-horseheads': 'PanelLv07EagleTower_05G',
 'panel-D7-grim-creeper': 'PanelLv07EagleTower_06H',
 'panel-D8-far-northwest': 'PanelLv08TurtleRock_02A',
 'panel-D8-dodongos': 'PanelLv08TurtleRock_03F',
 'panel-D8-gibdos': 'PanelLv08TurtleRock_03G',
 'panel-D8-extra-1': 'PanelLv08TurtleRock_03H',
 'panel-D8-extra-2': 'PanelLv08TurtleRock_04A',
 'panel-D8-statue': 'PanelLv08TurtleRock_04C',
 'panel-D8-extra-3': 'PanelLv08TurtleRock_04H',
 'panel-D8-extra-4': 'PanelLv08TurtleRock_05H',
 'panel-D8-west-vire': 'PanelLv08TurtleRock_06A',
 'panel-D8-west-roomba': 'PanelLv08TurtleRock_06B',
 'panel-D8-sparks-chest': 'PanelLv08TurtleRock_07B',
 'panel-D8-east-of-pots': 'PanelLv08TurtleRock_07F',
 'panel-D8-east-roomba': 'PanelLv08TurtleRock_07G',
 'panel-D8-far-southwest': 'PanelLv08TurtleRock_08A',
 'panel-D8-far-southeast': 'PanelLv08TurtleRock_08H',
 'panel-D0-northern-chest': 'PanelLv10ClothesDungeon_04F',
 'panel-D0-zol-pots': 'PanelLv10ClothesDungeon_05D',
 'panel-D0-north-orbs': 'PanelLv10ClothesDungeon_05E',
 'panel-D0-east-color-puzzle': 'PanelLv10ClothesDungeon_05F',
 'panel-D0-west-color-puzzle': 'PanelLv10ClothesDungeon_07D',
 'panel-D0-south-orbs': 'PanelLv10ClothesDungeon_07F',
 'panel-D0-putters': 'PanelLv10ClothesDungeon_08E'
}


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


BGM_TRACKS = (
    'BGM_DUNGEON_LV6_FACE',
    'BGM_DUNGEON_LV4_ANGLER',
    'BGM_CHICKEN_HURT',
    'BGM_GHOST_HOUSE',
    'BGM_ANIMAL_VILLAGE',
    'BGM_DUNGEON_LV1_TAIL',
    'BGM_DUNGEON_2D_SIDEVIEW',
    'BGM_DUGEON_CASTLE',
    'BGM_DUNGEON_LV3_KEY',
    'BGM_CAVE',
    'BGM_TARUTARU',
    'BGM_HOUSE',
    'BGM_MEVE',
    'BGM_FISHINGMAN',
    'BGM_DUNGEON_LV2_POT',
    'BGM_STRANGE_FOREST',
    'BGM_DUNGEON_HOLY_EGG',
    'BGM_SEASHELL_HOUSE',
    'BGM_TELEPHONE',
    'BGM_DANPEI',
    'BGM_SHOP',
    # 'BGM_SHOP_FAST',
    'BGM_GAME_SHOP',
    'BGM_GOAT_HOUSE',
    'BGM_DREAMSHRINE',
    'BGM_WRIGHT',
    'BGM_GAME_SHOP_FOR_POND',
    'BGM_RICHARD',
    'BGM_EVENT_RESCUE_BOWBOW',
    'BGM_DUNGEON_LV10_CLOTH',
    # 'BGM_DREAMSHRINE_ENT',
    'BGM_PLACE_OF_FACE_KEY',
    'BGM_DUNGEON_LV5_CATFISH',
    'BGM_FAIRY',
    'BGM_DUNGEON_LV7_TOWER',
    'BGM_DUNGEON_LV8_TURTLE',
    'BGM_FIELD_NORMAL',
    'BGM_FIELD_MARINE_NORMAL',
    'BGM_LASTBOSS_APPEAR',
    'BGM_LASTBOSS_BATTLE',
    'BGM_MARINE_NAME',
    # 'BGM_MARINE_SING',
    'BGM_MINIGAME_FISHING',
    'BGM_PANEL_DUNG_BEGINNER',
    'BGM_PANEL_DUNG_DIFFICULT',
    'BGM_PANEL_DUNG_MEDIUM',
    'BGM_PANEL_EDIT_MODE',
    'BGM_NAME_INPUT',
    'BGM_DUNGEON_BOSS',
    'BGM_DUNGEON_BOSS_MIDDLE',
    'BGM_DUNGEON_LV8_ENT_BATTLE',
    'BGM_EVENT_MARINE_IN_BEACH',
    'BGM_EVENT_RESCUE_BOWBOW_INTRO',
    'BGM_FIELD_FIRST',
    'BGM_FIELD_NORMAL_INTRO',
    'BGM_GAME_OF_RAFT',
    # 'BGM_NAZOTOKI_SEIKAI',
    'BGM_PANEL_SHADOW_LINK',
    'BGM_RAFTING_TIMEATTACK',
    'BGM_RICHARD_230',
    'BGM_STRANGE_FOREST_MARINE',
    'BGM_TARUTARU2_AFTER_THE_RESCUE',
    'BGM_TARUTARU_MARINE',
    'BGM_TOTAKEKE_SONG',
    'BGM_ZELDA_NAME',
    # 'BGM_DEFEAT_LOOP',
    # 'BGM_FANFARE_BOSS_HEART_GET',
    'BGM_PANEL_RESULT',
    'BGM_DUNGEON_LV7_BOSS',
    'BGM_HOUSE_FIRST',
    # 'BGM_EVENT_BASIN_ANGLER_OPEN',
    # 'BGM_EVENT_MONKEY',
    'BGM_MADBATTER',
    'BGM_EVENT_DATE',
    # 'BGM_RESUSCITATION_OF_CHICKEN',
    # 'BGM_LASTBOSS_DEMO_TEXT',
    'BGM_LASTBOSS_WIN',
    'BGM_OWL',
    'BGM_OWL_LAST',
    # 'BGM_EVENT_BEE',
    # 'BGM_MARINE_SING_WALRUS',
    'BGM_DEMO_AFTER_LASTBOSS',
    # 'BGM_DEMO_AFTER_LASTBOSS_WIND_FISH'
)


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


CHEST_SIZES = {
    'important': 1.2,
    'important-health': 1.2,
    'trade': 1.2,
    'seashell': 1.2,
    'good': 0.8,
    'junk': 0.8,
    # 'D1': 1.0,
    # 'D2': 1.0,
    # 'D3': 1.0,
    # 'D4': 1.0,
    # 'D5': 1.0,
    # 'D6': 1.0,
    # 'D7': 1.0,
    # 'D8': 1.0,
    # 'D0': 1.0
}

CHEST_TEXTURES = {
    'default': 'ObjTreasureBox.bfres',
    'junk': "ObjTreasureBoxJunk.bfres",
    'life-upgrade': "ObjTreasureBoxLifeUpgrade.bfres",
    'key': "ObjTreasureBoxKey.bfres"
}

MODEL_SIZES = {
    'Marin': 0.65,
    'ManboTamegoro': 0.35,
    'Mamu': 0.25
}
MODEL_ROTATIONS = {
    'SinkingSword': 180.0
}


DUNGEON_ENTRANCES = {
    'tail-cave':        ('Lv01TailCave_08D',        '',     'Field_14D', '',     0),
    'bottle-grotto':    ('Lv02BottleGrotto_08C',    '',     'Field_03E', '',     0),
    'key-cavern':       ('Lv03KeyCavern_08B',       '',     'Field_12F', '',     0),
    'angler-tunnel':    ('Lv04AnglersTunnel_08D',   '',     'Field_03L', '_a',   1),
    'catfish-maw':      ('Lv05CatfishsMaw_08H',     '',     'Field_14J', '_b',   0),
    'face-shrine':      ('Lv06FaceShrine_08D',      '',     'Field_09M', '',     0),
    'eagle-tower':      ('Lv07EagleTower_08B',      '_b',   'Field_01O', '',     0),
    'turtle-rock':      ('Lv08TurtleRock_08D',      '_b',   'Field_02A', '',     0),
    'color-dungeon':    ('Lv10ClothesDungeon_08C',  '',     'Field_08H', '',     0)
}


DUNGEON_MAP_ICONS = {
    'tail-cave': ('Lv1Dungeon_map', 'UI_FieldMapIcon_Lv01Dungeon'),
    'bottle-grotto': ('Lv2Dungeon_map', 'UI_FieldMapIcon_Lv02Dungeon'),
    'key-cavern': ('Lv3Dungeon_map', 'UI_FieldMapIcon_Lv03Dungeon'),
    'angler-tunnel': ('Lv4Dungeon_map', 'UI_FieldMapIcon_Lv04Dungeon'),
    'catfish-maw': ('Lv5Dungeon_map', 'UI_FieldMapIcon_Lv05Dungeon'),
    'face-shrine': ('Lv6Dungeon_map', 'UI_FieldMapIcon_Lv06Dungeon'),
    'eagle-tower': ('Lv7Dungeon_map', 'UI_FieldMapIcon_Lv07Dungeon'),
    'turtle-rock': ('Lv8Dungeon_map', 'UI_FieldMapIcon_Lv08Dungeon'),
    'color-dungeon': ('ClothesDungeon_map', 'UI_FieldMapIcon_Lv10Dungeon')
}


WATER_LOADING_ZONES = {
    'Field_02O': [10],
    'Field_03K': [3],
    'Field_03O': [1],
    'Field_14J': [5, 6],
    'Field_15K': [1]
}


# CHEAT CODES
INFINITE_BOMBS = '01000000 01CC077E 0000001E'
INFINITE_ARROWS = '01000000 01CC077F 0000001E'
INFINITE_POWDER = '01000000 01CC0780 00000014'
HIGH_JUMP = """
80000100
580F0000 01CC8B50
580F1000 00001528
580F1000 00000928
580F1000 00000018
780F0000 000000C8
640F0000 00000000 C1800000
20000000
"""
# BGM_ADDRESSES = {}