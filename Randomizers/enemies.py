import random
from randomizer_data import ENEMY_DATA



def shuffleEnemyActors(room_data, folder: str, file: str, enemy_ids: dict, rand_state: tuple):
    """"""

    random.setstate(rand_state)

    edited_room = False

    excluded_actors = []
    if file[:-4] in list(ENEMY_DATA['Excluded_Actors'].keys()):
        excluded_actors = ENEMY_DATA['Excluded_Actors'][file[:-4]]
    
    restr = list(*enemy_ids['restr'])

    total_ids = (
        *enemy_ids['land'],
        *enemy_ids['air'],
        *enemy_ids['water'],
        *enemy_ids['water2D'],
        *enemy_ids['water_shallow'],
        *enemy_ids['tree'],
        *enemy_ids['hole']
    )

    # iterate through each actor
    for e, act in enumerate(room_data.actors):
        if act.type in total_ids and e not in excluded_actors: # check for enemy actors

            enemy_type = [v for k,v in ENEMY_DATA['Actors'].items() if v['id'] == act.type][0]['type']
            new_enemy = -1
            
            if act.type in restr:
                restr.remove(act.type)
            
            # keep shuffling each actor until it is a valid enemy
            while new_enemy in restr:
                if enemy_type == 'land':
                    new_enemy = random.choice(enemy_ids['land'])
                elif enemy_type == 'air':
                    if folder == 'Field':
                        new_enemy = random.choice(enemy_ids['no_vire']) # remove vires from overworld
                    else:
                        new_enemy = random.choice(enemy_ids['air'])
                elif enemy_type == 'water':
                    waters = (*enemy_ids['water'], *enemy_ids['water_shallow'])
                    new_enemy = random.choice(waters)
                elif enemy_type == 'water2D':
                    new_enemy = random.choice(enemy_ids['water2D'])
                elif enemy_type == 'water-shallow':
                    new_enemy = random.choice(enemy_ids['water_shallow'])
                elif enemy_type == 'tree':
                    new_enemy = random.choice(enemy_ids['tree'])
                elif enemy_type == 'hole':
                    new_enemy = random.choice(enemy_ids['hole'])
            
            ### restrict enemy groups to one per room
            fly_bombs = (0x26, 0x3E, 0x48) # vires, zirros, bone-putters
            if new_enemy in fly_bombs:
                restr.extend(fly_bombs)
            
            blocking = (0x8, 0x9, 0x13, 0x14, 0x2E, 0x2F, 0x35, 0x36, 0x4D) # shield/spear and color dungeon orbs
            if new_enemy in blocking:
                restr.extend(blocking)
            
            # change the enemy data into the new enemy
            if act.type != new_enemy:
                act.type = new_enemy
                try:
                    params = [v for k,v in ENEMY_DATA['Actors'].items() if v['id'] == act.type][0]['parameters']
                    for i in range(8):
                        try:
                            if isinstance(params[i], list):
                                param = random.choice(params[i])
                            else:
                                param = params[i]
                            if isinstance(param, str):
                                param = bytes(param, 'utf-8')
                            act.parameters[i] = param
                        except IndexError:
                            act.parameters[i] = b''
                except KeyError:
                    act.parameters = [b'', b'', b'', b'', b'', b'', b'', b'']

                act.relationships.e = int([v for k,v in ENEMY_DATA['Actors'].items() if v['id'] == act.type][0]['enemy'])

                if act.type == 0x1E2: # EnemyZoroZoro spawner
                    act.scaleX = 4.5
                    act.scaleY = 3.0
                    act.scaleZ = 4.5
                else:
                    act.scaleX = 1.0
                    act.scaleY = 1.0
                    act.scaleZ = 1.0

                    if act.type == 0x4A: # StretchyGhosts - only includes one color in pool so it will be 1/3 likely now
                        act.type = random.choice((0x4A, 0x4B, 0x4C)) # decide color
                    elif act.type == 0x4D: # ColorDungeon Orbs - same thing as above
                        act.type = random.choice((0x4D, 0x4E, 0x4F))
                
                act.rotY = 0 # change each enemy to be facing the screen, some will stay sideways if we don't

                edited_room = True
    
    return random.getstate(), edited_room
