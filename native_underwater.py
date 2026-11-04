"""Vanilla dive-source identities handled by the native indexed pickup adapter."""
SPOTS={
    'bay-passage-sunken':('MadBattersWellEnter','MadBattersWellEnter_01B',0xB0),
    'river-crossing-cave':('AnimalVillageEnter','AnimalVillageEnter_01B',0xB0),
    'kanalet-moat-south':('Field','Field_08J',0xB0),
    'south-bay-sunken':('Field','Field_15J',0xB0),
    'taltal-east-drop':('EagleTowerExit','EagleTowerExit_01A',0xB0),
    'kanalet-moat-north':('Field','Field_04I',0x87),
    'taltal-sunken':('Field','Field_02M',0x87),
}


def stage(mod,clean_romfs,contract):
    # Native actor pickup interception handles these seven sources. Keeping the
    # stock actors/NPCs preserves diving and sensor/resource initialization.
    return []
