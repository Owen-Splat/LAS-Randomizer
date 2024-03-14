import Tools.leb as leb



def shuffleLevelBGMS(f_data: bytes, songs_dict: dict) -> bytes:
    '''Parses the level binary files and shuffles the BGMs in each'''

    # Although we do not yet understand how to properly repack LVB files, we can still parse and edit the raw data
    level = leb.Level(f_data)

    for entry in level.fixed_hash.entries:
        if entry.name == b'zone':
            for e in entry.data.entries:

                bgm = leb.readString(e.data, 0x3C)

                if bgm.startswith(b'BGM_'): # only make changes if it is a valid BGM or else we might edit some other data
                    if str(bgm, 'utf-8') in songs_dict:
                        
                        new_bgm = bytes(songs_dict[str(bgm, 'utf-8')], 'utf-8') # get the new track to replace the old one with

                        # the bgms are aligned to 32 bytes, and as such will need padding to fit
                        for b in range(32-len(bgm)):
                            bgm += b'\x00'
                        
                        for b in range(32-len(new_bgm)):
                            new_bgm += b'\x00'
                        
                        ent_data = e.data.replace(bgm, new_bgm) # store the entry data with the song replaced
                        f_data = f_data.replace(e.data, ent_data) # now we replace all instances of the data with the new data
    
    return f_data
