"""Build the native LAS 1.0.0 runtime from the user's own clean ExeFS.

No downloaded game executable, generated main, or game assets may be packaged.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import lz4.block
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parent
BUILD_ID = "AE16F71E002AF8CB059A9A74C4D90F34BA984892"
MAIN_SHA256 = "20965546519a8e08cc01e6f138982390546d56520703684967425b09230e9b6d"
ADD, FRAME = 0x8D08E0, 0xC910
HAS, FACTORY = 0x8D1A30, 0x8F5EA0
WORLD_NPC = 0x8C3F10
WORLD_NPC_PROLOGUE = bytes.fromhex('ff0301d1ffd700a9f44f02a9fd7b03a9')
PROLOGUES = {ADD: bytes.fromhex("ff4301d1f70b00f9f65702a9f44f03a9"),
             FRAME: bytes.fromhex("ffc301d1e80b00fdfb0f00f9fa6702a9"),
             HAS:bytes.fromhex("ffc300d1f44f01a9fd7b02a9fd830091"),
             FACTORY:bytes.fromhex("fc6fbaa9fa6701a9f85f02a9f65703a9")}

def align(value, boundary=0x1000): return (value + boundary - 1) & -boundary

class NSO:
    def __init__(self, raw):
        if raw[:4] != b"NSO0" or len(raw) < 0x100:
            raise ValueError("Invalid NSO file")
        self.header = bytearray(raw[:0x100])
        flags = struct.unpack_from("<I", raw, 12)[0]
        self.segments = []
        for i in range(3):
            fileoff, memoff, size = struct.unpack_from("<III", raw, 0x10 + i*16)
            stored = struct.unpack_from("<I", raw, 0x60 + 4*i)[0]
            data = raw[fileoff:fileoff+stored]
            if flags & (1<<i): data = lz4.block.decompress(data, uncompressed_size=size)
            if len(data) != size: raise ValueError("NSO segment size mismatch")
            if flags & (1<<(i+3)) and hashlib.sha256(data).digest() != raw[0xA0+i*32:0xC0+i*32]:
                raise ValueError("NSO segment hash mismatch")
            self.segments.append([memoff, bytearray(data)])
        self.bss = struct.unpack_from("<I", raw, 0x3C)[0]

    def read(self, address, count):
        for offset, data in self.segments:
            if offset <= address and address+count <= offset+len(data):
                return bytes(data[address-offset:address-offset+count])
        raise ValueError(f"Address outside NSO segments: {address:x}")

    def write(self, address, raw):
        for offset, data in self.segments:
            if offset <= address and address+len(raw) <= offset+len(data):
                data[address-offset:address-offset+len(raw)] = raw
                return
        raise ValueError("Write outside NSO segments")

    def encode(self):
        header=bytearray(self.header)
        struct.pack_into("<I",header,12,0x3F)
        struct.pack_into("<I",header,0x3C,self.bss)
        # No file-local module name is used by this builder.
        struct.pack_into("<I",header,0x1C,0)
        struct.pack_into("<I",header,0x2C,0)
        body=bytearray()
        for i,(memoff,data) in enumerate(self.segments):
            stored=lz4.block.compress(bytes(data),store_size=False)
            struct.pack_into("<III",header,0x10+i*16,0x100+len(body),memoff,len(data))
            struct.pack_into("<I",header,0x60+i*4,len(stored))
            header[0xA0+i*32:0xC0+i*32]=hashlib.sha256(data).digest()
            body.extend(stored)
        return bytes(header+body)

def branch(at, target):
    delta=target-at
    if delta%4 or not -(1<<27)<=delta<(1<<27): raise ValueError("Branch out of range")
    return 0x14000000 | ((delta>>2)&0x3FFFFFF)

def gate(at, slot, resume, prologue):
    pages=(slot>>12)-(at>>12)
    if not -(1<<20)<=pages<(1<<20) or slot%8: raise ValueError("Invalid dispatch slot")
    adrp=0x90000010|((pages&3)<<29)|(((pages>>2)&0x7FFFF)<<5)
    ldr=0xF9400210|(((slot&0xFFF)//8)<<10)
    # Null callback safely executes the original function while module setup is pending.
    return struct.pack("<4I",adrp,ldr,0xB4000050,0xD61F0200)+prologue+struct.pack("<I",branch(at+32,resume))

def copy_import_slots(game):
    mod0=struct.unpack("<I",game.read(4,4))[0]
    dynamic=mod0+struct.unpack("<i",game.read(mod0+4,4))[0]
    tags={}
    for i in range(1024):
        tag,value=struct.unpack("<QQ",game.read(dynamic+i*16,16))
        if not tag:break
        tags[tag]=value
    else:raise ValueError("Unterminated dynamic table")
    found={}
    expected={"memcpy":"memcpy","memmove":"memmove",
              "_ZN2nn2fs9WriteFileENS0_10FileHandleElPKvmRKNS0_11WriteOptionE":"write_file"}
    for address_tag,size_tag in ((7,8),(23,2)):
        if address_tag not in tags:continue
        if tags[size_tag]>0x1000000:raise ValueError("Relocation table too large")
        for off in range(0,tags[size_tag],24):
            slot,info,add=struct.unpack("<QQq",game.read(tags[address_tag]+off,24))
            if (info&0xFFFFFFFF) not in (1025,1026):continue
            nameoff=struct.unpack("<I",game.read(tags[6]+(info>>32)*24,4))[0]
            text=bytearray()
            for i in range(128):
                b=game.read(tags[5]+nameoff+i,1)
                if b==b"\0":break
                text.extend(b)
            name=text.decode("ascii",errors="replace")
            if name in expected:
                key=expected[name]
                if key in found:raise ValueError("Ambiguous save-observation import")
                found[key]=slot
    if set(found)!={"memcpy","memmove","write_file"}:raise ValueError("Expected save-observation imports are missing")
    return found

def make_elf_nso(path, network_probe=False):
    with path.open("rb") as stream:
        elf=ELFFile(stream)
        loads=[p for p in elf.iter_segments() if p["p_type"]=="PT_LOAD"]
        if len(loads)!=3: raise ValueError("Expected RX/R/RW module layout")
        undefined=[s.name for s in elf.get_section_by_name(".dynsym").iter_symbols()
                   if s.name and s["st_shndx"]=="SHN_UNDEF"]
        allowed={"_ZN2nn6socket10InitializeEPvmmi","nnsocketSocket","nnsocketConnect","nnsocketClose",
                 "nnsocketFcntl","nnsocketPoll","nnsocketSend","nnsocketRecv","nnsocketGetLastErrno"} if network_probe else set()
        if set(undefined)-allowed: raise ValueError(f"Unresolved native imports: {undefined}")
        header=bytearray(0x100);header[:4]=b"NSO0"
        header[0x40:0x54]=hashlib.sha256(path.read_bytes()).digest()[:20]
        module=object.__new__(NSO);module.header=header
        module.segments=[[p["p_vaddr"],bytearray(p.data())] for p in loads]
        module.bss=loads[-1]["p_memsz"]-loads[-1]["p_filesz"]
        ro=loads[1]["p_vaddr"]
        for name,field in ((".dynstr",0x88),(".dynsym",0x90)):
            sec=elf.get_section_by_name(name)
            struct.pack_into("<II",header,field,sec["sh_addr"]-ro,sec["sh_size"])
        return module.encode()

def build(exefs, output, reward_test=False, check_test=False, network_probe=False, save_probe=False, check_label="woods-south-chest", receipt_test=False,
          managed_plan=None, mod_romfs=None, save_id=None, bridge_manifest=None, expanded_state=False, clean_romfs=None, las_source=None, validation_candidate=False, world_visuals=False):
    if validation_candidate and not bridge_manifest:raise ValueError('A validation candidate requires the full native bridge')
    from validation import CAPABILITIES
    if world_visuals and (not managed_plan or not mod_romfs or not clean_romfs or validation_candidate):
        raise ValueError('Experimental world visuals require an isolated managed build and clean RomFS; normal release mode remains stock')
    advertised=list(CAPABILITIES) if validation_candidate else []
    plan = None
    if managed_plan:
        if reward_test or check_test or receipt_test or not save_probe:
            raise ValueError('Managed checks require save observation and cannot mix diagnostic rewards')
        plan = json.loads(managed_plan.read_text())
        declared = plan.pop('digest', None)
        actual = hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        plan['digest'] = declared
        if declared != actual or plan.get('schema_version') != 1 or plan.get('marker_base') != 0x4C410000:
            raise ValueError('Invalid native marker plan digest/version')
        checks = plan.get('checks', [])
        if not checks or len(checks)>352 or not save_id or not save_id.strip() or not mod_romfs:
            raise ValueError('Managed plan requires checks, generated RomFS and a save identity')
        if len(bytes.fromhex(plan['manifest_digest'])) != 32:
            raise ValueError('Invalid manifest digest')
        if len({r['location_id'] for r in checks}) != len(checks):
            raise ValueError('Duplicate managed location ID')
        for i,row in enumerate(checks):
            if row['ordinal']!=i or row['marker']!=0x4C410000+i:
                raise ValueError('Invalid native marker ordinal')
        import oead
        flags=oead.gsheet.parse(oead.Bytes((mod_romfs/'region_common/datasheets/GlobalFlags.gsheet').read_bytes()))
        flag_limit=1248 if expanded_state or len(checks)>228 else 1360
        bit_base=1696 if flag_limit==1248 else 1808
        aliases={'AP_CheckFlag_'+str(r['location_id']):bit_base+r['ordinal'] for r in checks}
        if any(int(row['index'])>=flag_limit and aliases.get(str(row['symbol']))!=int(row['index']) for row in flags.values):
            raise ValueError('Generated flags overlap native saved state reservation')
        item_rows=oead.gsheet.parse(oead.Bytes((mod_romfs/'region_common/datasheets/Items.gsheet').read_bytes())).values
        check_ordinals={str(r['location_id']):r['ordinal'] for r in checks}
        direct_items=[]
        for row in item_rows:
            symbol=str(row['symbol'])
            if symbol.startswith('AP_Shop_'):
                identity=symbol.removeprefix('AP_Shop_')
                if identity not in check_ordinals or not 230<=int(row['itemID'])<240:
                    raise ValueError('Unknown direct shop check')
                direct_items.append((int(row['itemID']),check_ordinals[identity]))
        if len({i for i,o in direct_items})!=len(direct_items):raise ValueError('Duplicate direct item ID')
        visual_ids=sorted({int(row['itemID']) for row in item_rows
                           if row['symbol'].startswith('AP_Check_') and int(row['itemID'])>=128})
        if any(i>253 or i in (200,201,202) for i in visual_ids):raise ValueError('Invalid display-only item ID')
    if bridge_manifest and (not plan or network_probe):
        raise ValueError('Native bridge testing requires a managed check plan and no PING/PONG probe')
    if receipt_test and (not save_probe or reward_test or check_label!="tarin"):
        raise ValueError("Receipt diagnostic requires --save-probe --check-label tarin and no --reward-test")
    if output.exists(): raise ValueError("Choose a new probe output folder")
    raw=(exefs/"main").read_bytes(); game=NSO(raw)
    if game.header[0x40:0x54].hex().upper()!=BUILD_ID: raise ValueError("Only exact LAS 1.0.0 build is supported")
    if hashlib.sha256(raw).hexdigest()!=MAIN_SHA256:
        raise ValueError("The main executable differs from the inspected clean input; refusing to patch it")
    for address,expected in PROLOGUES.items():
        if game.read(address,16)!=expected: raise ValueError(f"Unexpected original instructions at {address:x}")
    if world_visuals and game.read(WORLD_NPC,16)!=WORLD_NPC_PROLOGUE:
        raise ValueError('Unexpected NPC visual component constructor instructions')
    static_patches=[]
    underwater_plan=mod_romfs.parent/'native-underwater-plan.json' if mod_romfs else None
    if underwater_plan and underwater_plan.is_file():
        raise ValueError('Regenerate obsolete underwater rendering assets using the original-actor pickup adapter')
    imports=copy_import_slots(game) if save_probe else {}
    output.mkdir(parents=True)
    builddir=output/"build";builddir.mkdir()
    mailbox=align(game.segments[2][0]+len(game.segments[2][1])+game.bss)
    game.bss=mailbox+0x1000-game.segments[2][0]-len(game.segments[2][1])
    mod0=struct.unpack("<I",game.read(4,4))[0]
    game.write(mod0+12,struct.pack("<I",mailbox+0x1000-mod0))
    cave=align(len(game.segments[0][1]),16)
    appended=bytearray(cave-len(game.segments[0][1]))
    gates={}
    for i,address in enumerate((ADD,FRAME,HAS,FACTORY)+((WORLD_NPC,) if world_visuals else ())):
        # Dispatch gates occupy the verified text-alignment padding.
        target=cave+i*36
        appended.extend(gate(target,mailbox+i*8,address+16,WORLD_NPC_PROLOGUE if address==WORLD_NPC else PROLOGUES[address]))
        gates[address]=struct.pack("<4I",branch(address,target),0xD503201F,0xD503201F,0xD503201F)
        game.write(address,gates[address])
    if len(game.segments[0][1])+len(appended)>game.segments[1][0]:
        raise ValueError("No room for dispatch gates in existing text alignment padding")
    game.segments[0][1].extend(appended)
    def array(name,data): return "static const unsigned char "+name+"[]={"+",".join(str(b) for b in data)+"};\n"
    profile=(f"#define PROBE_BRIDGE {int(bridge_manifest is not None)}\n#define PROBE_MANAGED {int(plan is not None)}\n"
             f"#define PROBE_RECEIPT {int(receipt_test)}\n#define PROBE_CHECK_LABEL {json.dumps(check_label)}\n"
             f"#define WRITE_FILE_GOT {imports.get('write_file',0)}ull\n"
             f"#define PROBE_SAVE {int(save_probe)}\n#define MEMCPY_GOT {imports.get('memcpy',0)}ull\n"
             f"#define MEMMOVE_GOT {imports.get('memmove',0)}ull\n#define PROBE_NETWORK {int(network_probe)}\n"
             f"#define PROBE_REWARD_TEST {3 if reward_test else 2 if check_test else 0}\n"
             f"#define TEXT_SIZE {len(game.segments[0][1])}ull\n#define MAILBOX {mailbox}ull\n"
             f"#define ADD_OFFSET {ADD}ull\n#define FRAME_OFFSET {FRAME}ull\n"
             "#define GAME_MANAGER 0x1C97188ull\n#define LIVE_SAVE 0x1CBB220ull\n")
    profile+=f'#define HAS_OFFSET {HAS}ull\n#define FACTORY_OFFSET {FACTORY}ull\n#define PROBE_UNDERWATER {int(bool(underwater_plan and underwater_plan.is_file()))}\n'
    profile+=f'#define NATIVE_WORLD_VISUALS {int(world_visuals)}\n#define WORLD_NPC_OFFSET {WORLD_NPC}ull\n'
    profile+=array("MAIN_SIGNATURE",game.read(0,32))+array("ADD_GATE",gates[ADD])+array("FRAME_GATE",gates[FRAME])+array("HAS_GATE",gates[HAS])+array("FACTORY_GATE",gates[FACTORY])
    if world_visuals:profile+=array('WORLD_NPC_GATE',gates[WORLD_NPC])
    death_link=False
    hint_routes=[]
    if bridge_manifest:
        bridge_config=json.loads(bridge_manifest.read_text(encoding='utf-8-sig'))
        death_link=bridge_config.get('player_settings',{}).get('death_link',False)
        hint_routes=bridge_config.get('hint_routes',[])
        if len(hint_routes)>1024 or any(r.get('index')!=i for i,r in enumerate(hint_routes)):raise ValueError('Invalid native hint route table')
    profile+=f'#define NATIVE_DEATHLINK {int(death_link)}\n'
    profile+=f'#define NATIVE_HINT_COUNT {len(hint_routes)}u\n'
    profile+='static const char *NATIVE_HINT_ENTRIES[]={'+','.join(json.dumps('AP_Hint_'+str(r['index'])) for r in hint_routes)+'};\n'
    profile+=array("DIAGNOSTIC_FP",hashlib.sha256(b"LAS_NATIVE_RECEIPT_DIAGNOSTIC_V1").digest()[:16])
    profile+=array("DIAGNOSTIC_NEXT",hashlib.sha256(b"[[105,-1,0]]").digest())
    visual_records=[]
    if plan:
        shell_file=mod_romfs.parent/'native-shell-plan.json'
        shell_rows=[]
        if shell_file.is_file():
            shell=json.loads(shell_file.read_text())
            if shell.get('plan_digest')!=plan['digest']:raise ValueError('Shell adapter plan mismatch')
            shell_rows=shell['checks']
            if shell.get('physical_model_mode')!='vanilla_indexed_actors':
                raise ValueError('Regenerate obsolete shell rendering assets using the original-actor pickup adapter')
            if len({(r.get('native_id',22),r['index']) for r in shell_rows})!=len(shell_rows):raise ValueError('Duplicate shell index')
            for r in shell_rows:
                if r.get('native_id',22) not in (22,58) or not 0<=r['index']<(50 if r.get('native_id',22)==22 else 32) or not 0<=r['ordinal']<len(checks) or checks[r['ordinal']]['location']!=r['location']:
                    raise ValueError('Invalid shell mapping')
        profile+='#define MANAGED_SHELL_MODELS 0\n'
        if world_visuals:
            from world_visuals import validate,header
            visual_records=validate(mod_romfs,clean_romfs,plan,shell_rows)
            if not visual_records:raise ValueError('This seed has no supported managed shell visuals to test')
            profile+=header(visual_records)
        profile+=f'#define MANAGED_SHELL_COUNT {len(shell_rows)}u\n'
        profile+='typedef struct {unsigned native,index,ordinal; const char *path,*model;} ShellCheck;\n'
        profile+='static const ShellCheck MANAGED_SHELLS[]={'+','.join('{'+str(r.get('native_id',22))+','+str(r['index'])+','+str(r['ordinal'])+','+json.dumps(r['model_path'])+','+json.dumps(r['model_name'])+'}' for r in shell_rows)+'};\n'
        binding={'manifest_digest':plan['manifest_digest'],'plan_digest':plan['digest'],'save_id':save_id}
        fingerprint=hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).digest()[:16]
        profile+=array('MANAGED_FP',fingerprint)
        profile+=f"#define MANAGED_COUNT {len(plan['checks'])}u\n"
        profile+='static const unsigned int MANAGED_IDS[]={'+','.join(str(r['location_id'])+'u' for r in plan['checks'])+'};\n'
        profile+=f'#define MANAGED_DIRECT_COUNT {len(direct_items)}u\n'
        profile+='static const unsigned int MANAGED_DIRECT[][2]={'+','.join('{'+str(i)+','+str(o)+'}' for i,o in direct_items or [(0,0)])+'};\n'
        profile+=f'#define MANAGED_VISUAL_COUNT {len(visual_ids)}u\n'
        profile+='static const unsigned int MANAGED_VISUAL_IDS[]={'+','.join(map(str,visual_ids or [0]))+'};\n'
    if bridge_manifest:
        manifest=json.loads(bridge_manifest.read_text(encoding='utf-8-sig'))
        canonical=dict(manifest);canonical.pop('manifest_digest',None)
        digest=hashlib.sha256(json.dumps(canonical,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if digest!=manifest.get('manifest_digest') or digest!=plan['manifest_digest']:
            raise ValueError('Bridge manifest does not match the compiled marker plan')
        hello={'t':'hello','protocol':1,'implementation':'native','identity':manifest['identity'],
               'manifest_digest':digest,'build_id':BUILD_ID,'save_id':save_id,'team':0,'capabilities':advertised,'supports_check_sync':True,
               'supports_deathlink':death_link,'supports_hints':bool(hint_routes)}
        encoded=json.dumps(hello,separators=(',',':'))+'\n'
        if len(encoded.encode())>65535:raise ValueError('Bridge hello exceeds protocol limit')
        profile+='static const char BRIDGE_HELLO[]='+json.dumps(encoded)+';\n'
        candidates=[ROOT.parent/'apworld/las_switch/core/ids.json',ROOT.parent/'las_archipelago_prototype/apworld/las_switch/core/ids.json',ROOT/'core/ids.json']
        registry_path=next((p for p in candidates if p.is_file()),None)
        if registry_path is None:raise ValueError('Native builder needs the matching LAS world core data')
        registry=json.loads(registry_path.read_text())
        profile+=f"#define BRIDGE_RUPEE50_ID {registry['items']['rupee-50']}u\n"
        profile+=f"#define BRIDGE_OCARINA_ID {registry['items']['ocarina']}u\n"
        from reward_catalog import compile_catalog, header as reward_header
        rewards=compile_catalog(las_source or ROOT.parent/'reference_sources/LAS-Randomizer-0.41',registry_path.parent,mod_romfs)
        if manifest.get('schema_version')==4:
            from reward_catalog import reserve_vanilla_indexes
            catalog=json.loads((registry_path.parent/'catalog.json').read_text())
            rewards['reserved_vanilla_indexes']=reserve_vanilla_indexes(rewards,catalog,{r['location'] for r in manifest['placements']})
        (builddir/'generated_rewards.h').write_text(reward_header(rewards))
        ending=(clean_romfs or exefs.parent/'romfs')/'region_common/event/WindFish.bfevfl'
        if hashlib.sha256(ending.read_bytes()).hexdigest()!='c787c3f4bee0d29fd7b84b867b8b6c76264696b4029b71b9661eef99bef9e8e4':
            raise ValueError('Ending flow differs from the inspected victory signal')
        # WindFish ending Event134 sets ShadowClear; the original sheet maps it
        # to flag 240. It is a game ending signal, not an AP logic predicate.
        flag_rows=oead.gsheet.parse(oead.Bytes((mod_romfs/'region_common/datasheets/GlobalFlags.gsheet').read_bytes())).values
        victory=[int(row['index']) for row in flag_rows if row['symbol']=='ShadowClear']
        if victory!=[240]:raise ValueError('Victory flag mapping differs from inspected game data')
        profile+='#define NATIVE_VICTORY_FLAG 240u\n'
    expanded_state=expanded_state or bool(plan and len(plan['checks'])>228)
    state_layout={'version':2 if expanded_state else 1,'size':100 if expanded_state else 86,
                  'offset':0x5E5C if expanded_state else 0x5E6A,'check_limit':352 if expanded_state else 228}
    for key,value in state_layout.items():
        macro='NATIVE_CHECK_LIMIT' if key=='check_limit' else 'NATIVE_STATE_'+key.upper()
        profile+=f'#define {macro} {value}u\n'
    (builddir/"generated_profile.h").write_text(profile)
    import ziglang
    zig=Path(ziglang.__file__).parent/"zig.exe"
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(builddir/"zig-cache"))
    extra=[str(ROOT/"network_probe.c")] if network_probe else []
    if bridge_manifest:extra.extend([str(ROOT/'bridge_transport.c'),str(ROOT/'event_runtime.c')])
    subprocess.run([str(zig),"cc","-target","aarch64-linux-musl","-O2","-fPIC","-ffreestanding",
        "-fno-stack-protector","-fno-builtin","-nostdlib","-shared","-Wl,-Bsymbolic,--hash-style=sysv,--build-id=sha1",
        "-Wl,-T,"+str(ROOT/"link.ld"),"-I"+str(builddir),str(ROOT/"module.c"),
        str(ROOT/"entry.S"),str(ROOT/"receipt_state.c"),str(ROOT/'wire_json.c'),str(ROOT/'save_image.c'),str(ROOT/'pickup_runtime.c'),*extra,"-o",str(builddir/"probe.elf")],env=env,check=True)
    module=make_elf_nso(builddir/"probe.elf",network_probe or bool(bridge_manifest))
    patched=game.encode()
    NSO(module);NSO(patched)  # Reparse and verify every segment hash before staging.
    mod=output/"mod/exefs";mod.mkdir(parents=True)
    (mod/"main").write_bytes(patched);(mod/"subsdk9").write_bytes(module)
    report=dict(kind="native_hook_diagnostic" if reward_test or check_test else "read_only_native_hook_probe",build_id=BUILD_ID,
        original_main_sha256=hashlib.sha256(raw).hexdigest(),patched_main_sha256=hashlib.sha256(patched).hexdigest(),
        subsdk9_sha256=hashlib.sha256(module).hexdigest(),mailbox=hex(mailbox),
        hooks={"inventory_add":hex(ADD),"frame_update":hex(FRAME),"inventory_has":hex(HAS),"actor_factory":hex(FACTORY)},
        capabilities=advertised,reward_suppression=bool(plan),item_delivery=bool(bridge_manifest),live_ryujinx_validated=False,
        isolated_reward_test=reward_test,diagnostic_grant="50 rupees once after 360 gameplay frames" if reward_test else None)
    report["isolated_sentinel_suppression_test"]=reward_test or check_test
    report["loopback_transport_diagnostic"]=network_probe
    report["save_copy_observation"]=save_probe
    report["check_label"]=check_label
    report["diagnostic_receipt_persistence"]=receipt_test
    report['managed_check_plan']=plan
    report['shell_models_enabled']=world_visuals
    report['shell_visual_mode']='npc_component_experimental' if world_visuals else 'stock'
    report['world_visual_checks']=visual_records
    report['legacy_shell_parameter_renderer']=False
    report['validation_candidate']=validation_candidate
    report['death_link_enabled']=death_link
    report['hint_count']=len(hint_routes)
    report['shell_checks']=shell_rows if plan else []
    report['static_patches']=static_patches
    report['direct_item_checks']=direct_items if plan else []
    report['state_layout']=state_layout
    report['display_only_item_ids']=visual_ids if plan else []
    report['native_json_bridge_diagnostic']=bool(bridge_manifest)
    if bridge_manifest:
        report['bridge_supported_items']={r['name']:r['item_id'] for r in rewards['supported']}
        report['reward_programs']=rewards
    if plan:
        report['kind']='protocol_validation_candidate' if validation_candidate else 'managed_checks_development'
        report['managed_fingerprint']=fingerprint.hex()
    (output/"probe_report.json").write_text(json.dumps(report,indent=2))
    print(json.dumps({k:v for k,v in report.items() if k not in ('managed_check_plan','reward_programs')},indent=2))

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exefs",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--reward-test",action="store_true",help="ISOLATED COPIED SAVES ONLY: suppress sentinel and give 50 rupees once")
    parser.add_argument("--check-test",action="store_true",help="ISOLATED COPIED SAVES ONLY: suppress only the marked woods chest")
    parser.add_argument("--network-probe",action="store_true",help="Try a loopback PING/PONG diagnostic on TCP 17779; no AP delivery")
    parser.add_argument("--save-probe",action="store_true",help="Observe copies touching the live save without changing their data")
    parser.add_argument("--check-label",choices=("woods-south-chest","tarin"),default="woods-south-chest")
    parser.add_argument("--receipt-test",action="store_true",help="COPIED TARIN TEST SLOT ONLY: persist one 50-rupee diagnostic receipt")
    parser.add_argument('--managed-plan',type=Path,help='Development: compiled physical marker plan')
    parser.add_argument('--mod-romfs',type=Path,help='Generated RomFS, checked for save-state flag collisions')
    parser.add_argument('--save-id',help='Explicit copied-save identity for managed check persistence')
    parser.add_argument('--bridge-manifest',type=Path,help='Development JSON bridge with compiled registered reward programs')
    parser.add_argument('--expanded-state',action='store_true',help='Use version 2 save storage for up to 352 checks; requires a fresh test save')
    parser.add_argument('--clean-romfs',type=Path,help='Selected clean RomFS for executable/event verification')
    parser.add_argument('--las-source',type=Path,help='Selected pinned LAS randomizer source')
    parser.add_argument('--validation-candidate',action='store_true',help='Candidate protocol capabilities; must pass native validation before deployment')
    parser.add_argument('--world-visuals',action='store_true',help='EXPERIMENTAL copied-save shell NPC visuals; excluded from normal release mode')
    args=parser.parse_args()
    if args.reward_test and args.check_test:parser.error("Choose one test variant")
    build(args.exefs.resolve(),args.out.resolve(),args.reward_test,args.check_test,args.network_probe,args.save_probe,args.check_label,args.receipt_test,
          args.managed_plan,args.mod_romfs,args.save_id,args.bridge_manifest,args.expanded_state,args.clean_romfs,args.las_source,args.validation_candidate,args.world_visuals)
