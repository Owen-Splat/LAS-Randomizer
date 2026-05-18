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