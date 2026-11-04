"""Canonical player settings shared by generation, logic and the LAS adapter."""
from collections import Counter
from .data import ITEMS, NODES, content, active_locations, category_flags

DUNGEONS=('tail-cave','bottle-grotto','key-cavern','angler-tunnel','catfish-maw',
          'face-shrine','eagle-tower','turtle-rock','color-dungeon')
TOGGLES={
    'randomize_enemies':False,'randomize_enemy_sizes':False,'open_kanalet':True,
    'open_mabe':False,'open_mamu':True,'completed_bridge':True,'classic_d2':False,
    'extra_consumable_drop':True,'bad_pets':False,'free_book':True,'fast_fishing':False,
    'fast_stalfos':False,'unlocked_bombs':True,'shuffled_bombs':False,'shuffled_powder':False,
    'blur_removal':False,'randomize_music':False,'nice_bombs':False,'nice_magic_rod':False,
    'sword_beam_with_lv1':False,'fast_boss_cutscenes':False,'fast_song_cutscenes':False,
    'fast_chest_animations':False,'fast_key_animations':False,'one_hit_ko':False,
    'fast_stealing':False,'death_link':False,'shuffled_dungeons':False,
}
CHOICES={'chest_appearance':('default','size','texture_and_size'),
         'stealing':('normal','always','never'),'traps':('none','few','several','many','insanity')}
MAP={
    'randomize_enemies':'randomize-enemies','randomize_enemy_sizes':'randomize-enemy-sizes',
    'open_kanalet':'open-kanalet','open_mabe':'open-mabe','open_mamu':'open-mamu',
    'completed_bridge':'open-bridge','classic_d2':'classic-d2','extra_consumable_drop':'extended-consumable-drop',
    'bad_pets':'bad-pets','free_book':'free-book','fast_fishing':'fast-fishing','fast_stalfos':'fast-stalfos',
    'unlocked_bombs':'unlocked-bombs','shuffled_bombs':'shuffle-bombs','shuffled_powder':'shuffle-powder',
    'blur_removal':'blur-removal','randomize_music':'randomize-music','nice_bombs':'nice-bombs',
    'nice_magic_rod':'nice-rod','sword_beam_with_lv1':'lv1-beam','fast_boss_cutscenes':'boss-cutscenes',
    'fast_song_cutscenes':'fast-songs','fast_chest_animations':'fast-chests','fast_key_animations':'fast-keys',
    'one_hit_ko':'OHKO','fast_stealing':'fast-stealing','shuffled_dungeons':'shuffle-dungeons',
}

def defaults():
    return {**TOGGLES,'chest_appearance':'default','stealing':'normal','traps':'none',
            'seashell_mansion':50,'owl_gifts':'none','starting_items':{},
            'randomized_items':sorted(ITEMS)}

def validate(settings):
    if not isinstance(settings,dict) or set(settings)!=set(defaults()):
        raise ValueError('Incomplete or unknown LAS player settings')
    for key in TOGGLES:
        if type(settings[key]) is not bool:raise ValueError('Expected boolean for '+key)
    for key,values in CHOICES.items():
        if settings[key] not in values:raise ValueError('Invalid '+key)
    if type(settings['seashell_mansion']) is not int or settings['seashell_mansion'] not in (0,5,15,30,40,50):
        raise ValueError('Seashell Mansion must be 0, 5, 15, 30, 40 or 50')
    if settings['owl_gifts'] not in ('none','overworld','dungeons','all'):raise ValueError('Invalid owl gifts')
    names=settings['randomized_items'];starts=settings['starting_items']
    if not isinstance(names,list) or names!=sorted(set(names)) or not set(names)<=set(ITEMS):
        raise ValueError('randomized_items must contain known, distinct LAS item names')
    if not isinstance(starts,dict) or not set(starts)<=set(ITEMS):raise ValueError('Unknown starting item')
    for key,count in starts.items():
        if type(count) is not int or count<1 or count>50:raise ValueError('Starting-item quantities must be 1–50')
        if key not in names:raise ValueError('Starting item must be included in randomized_items: '+key)
    return settings

def selected_locations(profile,categories,settings):
    names=active_locations(profile,categories)
    if settings is None:return names
    limit=settings['seashell_mansion'];owls=settings['owl_gifts']
    result=[]
    for name in names:
        node=NODES[name]
        if content(name) not in settings['randomized_items']:continue
        if name.endswith('-seashell-reward') and int(name.split('-')[0])>limit:continue
        if node['subtype']=='overworld-statue' and owls not in ('overworld','all'):continue
        if node['subtype']=='dungeon-statue' and owls not in ('dungeons','all'):continue
        result.append(name)
    return tuple(result)

def las_settings(categories,settings):
    result=category_flags(categories or ())
    result.update({target:settings[key] for key,target in MAP.items()})
    result.update({'fast-master-stalfos':settings['fast_stalfos'],
                   'owl-overworld-gifts':settings['owl_gifts'] in ('overworld','all'),
                   'owl-dungeon-gifts':settings['owl_gifts'] in ('dungeons','all'),
                   'chest-aspect':{'default':'default','size':'csmc','texture_and_size':'camc'}[settings['chest_appearance']],
                   'stealing':settings['stealing'],
                   'traps':'trapsanity' if settings['traps']=='insanity' else settings['traps']})
    return result

def item_pool(names,settings,rng):
    """Preserve pool size; vanilla-locked items are kept out of this pool."""
    whitelist=set(settings['randomized_items'])
    locked={name:content(name) for name in names if content(name) not in whitelist}
    pool=[content(name) for name in names if name not in locked]
    starts=Counter(settings['starting_items'])
    available=Counter(pool)
    for item,count in starts.items():
        if available[item]<count:
            raise ValueError(f'Starting {item}: requested {count}, only {available[item]} in selected randomized checks')
        for _ in range(count):pool.remove(item)
    # Starting items replace their original pool entries with harmless rupees.
    pool.extend(['rupee-20']*sum(starts.values()))
    level=settings['traps']
    if level!='none':
        traps=sorted(name for name in ITEMS if name.endswith('-trap') and name!='zol-trap' and name in whitelist)
        if not traps:raise ValueError('Trap setting requires an animated trap type in randomized_items')
        eligible=[i for i,item in enumerate(pool) if item=='rupee-50']
        rng.shuffle(eligible)
        if level=='insanity':eligible=[i for i,item in enumerate(pool) if item in ('rupee-5','rupee-20','rupee-50','medicine')]
        else:eligible=eligible[:{'few':3,'several':9,'many':17}[level]]
        for i in eligible:pool[i]=rng.choice(traps)
    return pool,locked
