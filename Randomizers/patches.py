from Tools.patcher import Patcher


def shuffleBGM(patcher=Patcher, seed=str):
    """Changes each address pointer for BGMs into another BGM address"""

    from Randomizers.data import BGM_OFFSETS
    import random, copy

    bgms = copy.deepcopy(BGM_OFFSETS)
    str_addrs = [v[0] for v in bgms.values()]

    random.seed(seed)
    random.shuffle(str_addrs)

    for v in bgms.values():
        addr = random.choice(str_addrs)
        del str_addrs[str_addrs.index(addr)]
        v[0] = addr
    
    for k,v in bgms.items():
        addr_page = (k+0x100) - int(f'0x{hex(k+0x100)[-3:]}', 16)
        str_suffix = hex(v[0]+0x100)[-3:]
        str_page = (v[0]+0x100) - int(f'0x{str_suffix}', 16)
        page_offset = hex(str_page - addr_page)
        patcher.addPatch(k, f'adrp {v[1]}, {page_offset}')
        patcher.addPatch(k+4, f'add {v[1]}, {v[1]}, #0x{str_suffix}')
