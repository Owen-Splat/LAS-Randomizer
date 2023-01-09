import copy


def addCrowKey(room_data):
    crow = room_data.actors[0]
    crow.parameters[1] = b''
    crow.relationships.y = 1
    crow.relationships.section_3 = [8]

    leaf = room_data.actors[6]
    leaf.type = 0xa9 # small key
    leaf.posX = 131.25
    leaf.posZ = 60.75
    leaf.switches[0] = (1, 37) # FieldKanaletCrowlyDead
    leaf.switches[1] = (1, 1218) # KeyGetField06I

    checker = copy.deepcopy(room_data.actors[7])
    checker.key = int('A1002A105CF0F2E8', 16)
    checker.name = bytes('TagHolocaust-A1002A105CF0F2E8', 'utf-8')
    checker.type = 0xf0
    checker.parameters = [1, 0, 30, 0, 0, b'', b'', b'']
    checker.switches[0] = (1, 37)
    checker.switches[1] = (2, 1)
    checker.relationships.k = 1
    checker.relationships.x = 1
    checker.relationships.section_1 = [[[b'', b''], 0]]
    room_data.actors.append(checker)



def addBomberKey(room_data):
    bomber = room_data.actors[0]
    bomber.relationships.y = 1
    bomber.relationships.section_3 = [3]

    leaf = room_data.actors[2]
    leaf.type = 0xa9 # small key
    leaf.posX -= 4.5
    leaf.posY -= 0.5
    leaf.posZ -= 6.0
    leaf.switches[0] = (1, 36) # FieldKanaletBombKnuckleDead
    leaf.switches[1] = (1, 1219) # KeyGetField06K

    checker = copy.deepcopy(leaf)
    checker.key = int('A1002A205CF0F2E8', 16)
    checker.name = bytes('TagHolocaust-A1002A205CF0F2E8', 'utf-8')
    checker.type = 0xf0
    checker.parameters = [1, 0, 30, 0, 0, b'', b'', b'']
    checker.switches[0] = (1, 36)
    checker.switches[1] = (2, 1)
    checker.relationships.k = 1
    checker.relationships.x = 1
    checker.relationships.section_1 = [[[b'', b''], 0]]
    room_data.actors.append(checker)



def addKillRoomKey(room_data):
    leaf = room_data.actors[5]
    leaf.type = 0xa9 # small key
    leaf.switches[1] = (1, 1220) # KeyGetKanalet02A



def addCrackedWallKey(room_data):
    enemy = room_data.actors[0]
    enemy.parameters[0] = b'' # makes it so it does not drop a golden leaf at all
    enemy.relationships.y = 1
    enemy.relationships.section_3 = [14]

    leaf = room_data.actors[5]
    leaf.type = 0xa9 # small key
    leaf.posX = 71.25
    leaf.posY = 1.5
    leaf.posZ = 1.75
    leaf.switches[1] = (1, 1221) # KeyGetKanalet01C

    checker = copy.deepcopy(leaf)
    checker.key = int('A1002A305CF0F2E8', 16)
    checker.name = bytes('TagHolocaust-A1002A305CF0F2E8', 'utf-8')
    checker.type = 0xf0
    checker.parameters = [1, 0, 30, 0, 0, b'', b'', b'']
    checker.switches[0] = (1, 649) # GoldenLeafPop_Btl_KanaletCastle_01C
    checker.switches[1] = (2, 1)
    checker.relationships.k = 1
    checker.relationships.x = 1
    checker.relationships.section_1 = [[[b'', b''], 0]]
    room_data.actors.append(checker)



def addBallChainKey(room_data):
    key = copy.deepcopy(room_data.actors[0])
    key.key = int('A1002A405CF0F2E8', 16)
    key.name = bytes('ItemSmallKey-A1002A405CF0F2E8', 'utf-8')
    key.type = 0xa9 # small key
    key.posX -= 1.5
    key.posZ -= 1.5
    key.switches[0] = (1, 650) # GoldenLeafPop_Btl_KanaletCastle_01D
    key.switches[1] = (1, 1222) # KeyGetKanalet01D
    room_data.actors.append(key)



def createRoomKey(room, room_data):
    funcs[room](room_data)



funcs = {
    'kanalet-crow': addCrowKey,
    'kanalet-mad-bomber': addBomberKey,
    'kanalet-kill-room': addKillRoomKey,
    'kanalet-bombed-guard': addCrackedWallKey,
    'kanalet-final-guard': addBallChainKey
}
