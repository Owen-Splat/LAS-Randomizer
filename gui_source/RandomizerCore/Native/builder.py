"""Build standalone indexed-source hooks from a user's clean LAS 1.0.0 main."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from .nso import NSO, align, gate, branch, make_elf_nso

MAIN_SHA256 = '20965546519a8e08cc01e6f138982390546d56520703684967425b09230e9b6d'
ADD, HAS = 0x8D08E0, 0x8D1A30
PROLOGUES = {ADD: bytes.fromhex('ff4301d1f70b00f9f65702a9f44f03a9'),
             HAS: bytes.fromhex('ffc300d1f44f01a9fd7b02a9fd830091')}

def validate_input(romfs):
    main = Path(romfs).resolve().parent / 'exefs/main'
    if not main.is_file() or hashlib.sha256(main.read_bytes()).hexdigest() != MAIN_SHA256:
        raise ValueError('Randomized shell pickups and shop require clean LAS 1.0.0 ExeFS alongside RomFS (exefs/main).')
    return main

def build(main, output, rows, builddir):
    rows = list(rows)
    if not rows:return
    if len({(r['item'],r['index']) for r in rows}) != len(rows):raise ValueError('Duplicate indexed source')
    allocated=[]
    for r in rows:
        if not 1248 <= r['flag'] < 2048 or not (r['pending']==-1 or 1248<=r['pending']<2048):raise ValueError('Invalid source flag')
        if not ((r['item']==22 and 0<=r['index']<50) or (r['item']==58 and 0<=r['index']<32) or (230<=r['item']<240 and r['index']==-1)):raise ValueError('Unsupported source identity')
        allocated.append(r['flag'])
        if r['pending']>=0:allocated.append(r['pending'])
    if len(set(allocated))!=len(allocated):raise ValueError('Duplicate source flag')
    raw=Path(main).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=MAIN_SHA256:raise ValueError('Unsupported or modified LAS executable')
    game=NSO(raw)
    for offset,expected in PROLOGUES.items():
        if game.read(offset,16)!=expected:raise ValueError('Unexpected hook instructions')
    mailbox=align(game.segments[2][0]+len(game.segments[2][1])+game.bss)
    game.bss=mailbox+0x1000-game.segments[2][0]-len(game.segments[2][1])
    mod0=struct.unpack('<I',game.read(4,4))[0]
    game.write(mod0+12,struct.pack('<I',mailbox+0x1000-mod0))
    cave=align(len(game.segments[0][1]),16)
    appended=bytearray(cave-len(game.segments[0][1]));gates={}
    for i,address in enumerate((ADD,HAS)):
        target=cave+i*36
        appended.extend(gate(target,mailbox+i*8,address+16,PROLOGUES[address]))
        gates[address]=struct.pack('<4I',branch(address,target),0xD503201F,0xD503201F,0xD503201F)
        game.write(address,gates[address])
    if len(game.segments[0][1])+len(appended)>game.segments[1][0]:raise ValueError('No text gate space')
    game.segments[0][1].extend(appended)
    def array(name,data):return 'static const unsigned char '+name+'[]={'+','.join(map(str,data))+'};\n'
    profile=f'#define TEXT_SIZE {len(game.segments[0][1])}ull\n#define MAILBOX {mailbox}ull\n#define ADD_OFFSET {ADD}ull\n#define HAS_OFFSET {HAS}ull\n'
    profile+=array('MAIN_SIGNATURE',game.read(0,32))+array('ADD_GATE',gates[ADD])+array('HAS_GATE',gates[HAS])
    profile+='typedef struct {unsigned item;int index;unsigned flag;int pending;} Source;\n'
    profile+=f'#define SOURCE_COUNT {len(rows)}u\nstatic const Source SOURCES[]={{'
    profile+=','.join('{'+','.join(str(r[k]) for k in ('item','index','flag','pending'))+'}' for r in rows)+'};\n'
    builddir=Path(builddir);builddir.mkdir(parents=True,exist_ok=True)
    (builddir/'profile.h').write_text(profile)
    source=Path(__file__).parent
    if getattr(sys,'frozen',False):source=Path(sys.executable).parent/'NativeSources'
    import ziglang
    zig=Path(ziglang.__file__).parent/('zig.exe' if os.name=='nt' else 'zig')
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(builddir/'zig-cache'))
    elf=builddir/'standalone.elf'
    subprocess.run([str(zig),'cc','-target','aarch64-linux-musl','-O2','-fPIC','-ffreestanding','-fno-stack-protector','-fno-builtin','-nostdlib','-shared','-Wl,-Bsymbolic,--hash-style=sysv,--build-id=sha1','-Wl,-T,'+str(source/'link.ld'),'-I'+str(builddir),str(source/'runtime.c'),str(source/'entry.S'),'-o',str(elf)],env=env,check=True)
    module=make_elf_nso(elf);patched=game.encode()
    NSO(module);NSO(patched)
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    if (output/'subsdk9').exists():raise ValueError('Refusing to overwrite an existing subsdk9')
    (output/'main').write_bytes(patched);(output/'subsdk9').write_bytes(module)
    (builddir/'sources.json').write_text(json.dumps(rows,indent=2))
