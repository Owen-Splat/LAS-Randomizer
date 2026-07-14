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