"""Execute standalone ARM64 source hooks. Set LAS_TEST_MOD to private generated output.

Game assets and generated binaries must not be committed to the repository.
Requires unicorn==2.1.4 in addition to the builder dependencies.
"""
import json
import os
from pathlib import Path
import struct
import sys
import unittest
from elftools.elf.elffile import ELFFile

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from RandomizerCore.Native.nso import NSO,align
try:
    from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_INTR
    from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X2,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC
except ImportError:
    Uc=None

BASE=0x7100000000;MODULE=0x7200000000;STACK=0x7300000000;STOP=0x7400000000
BUILD=os.environ.get('LAS_TEST_NATIVE_MOD',os.environ.get('LAS_TEST_MOD'))

@unittest.skipUnless(BUILD and Uc,'Set LAS_TEST_MOD and install Unicorn to execute private-asset native tests')
class NativeSources(unittest.TestCase):
    def setUp(self):
        root=Path(BUILD)
        self.rows=json.loads((root/'native-build/sources.json').read_text())
        self.game=NSO((root/'exefs/main').read_bytes());self.module=NSO((root/'exefs/subsdk9').read_bytes())
        self.cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        for base,nso in ((BASE,self.game),(MODULE,self.module)):
            self.cpu.mem_map(base,align(nso.segments[2][0]+len(nso.segments[2][1])+nso.bss))
            for off,data in nso.segments:self.cpu.mem_write(base+off,bytes(data))
        self.cpu.mem_map(STACK,0x20000);self.cpu.mem_map(STOP,0x1000)
        with (root/'native-build/standalone.elf').open('rb') as stream:
            elf=ELFFile(stream)
            self.symbols={s.name:MODULE+s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols()}
            for section in elf.iter_sections():
                if section['sh_type']=='SHT_RELA':
                    for r in section.iter_relocations():
                        self.assertEqual(r['r_info_type'],1027)
                        self.cpu.mem_write(MODULE+r['r_offset'],struct.pack('<Q',MODULE+r['r_addend']))
            self.assertIn('DT_INIT',[t.entry.d_tag for t in elf.get_section_by_name('.dynamic').iter_tags()])
        self.calls=[]
        self.cpu.hook_add(UC_HOOK_INTR,self.interrupt)
        self.cpu.hook_add(UC_HOOK_CODE,self.instruction)
        self.call(self.symbols['_init'])
        self.assertEqual(self.u64(self.symbols['main_base']),BASE)
        self.cpu.mem_write(self.symbols['original_add_tail'],struct.pack('<Q',STOP+0x100))
        self.cpu.mem_write(self.symbols['original_has_tail'],struct.pack('<Q',STOP+0x104))
        self.cpu.mem_write(BASE+0x1CC1388,struct.pack('<Q',BASE+0x1CBB220+0x5DC0))
        self.cpu.mem_write(BASE+0x1CC1390,struct.pack('<Q',256))

    def u64(self,address):return struct.unpack('<Q',self.cpu.mem_read(address,8))[0]

    def interrupt(self,cpu,number,data):
        pc=cpu.reg_read(UC_ARM64_REG_PC)
        instruction=struct.unpack('<I',cpu.mem_read(pc-4,4))[0]
        self.assertEqual((instruction>>5)&0xFFFF,6)
        addr=cpu.reg_read(UC_ARM64_REG_X2);end=BASE+align(len(self.game.segments[0][1]))
        if addr<BASE:info=(0,BASE,0,0,0,0,0,0)
        elif addr<end:info=(BASE,end-BASE,3,0,5,0,0,0)
        else:cpu.reg_write(UC_ARM64_REG_X0,1);return
        cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X0),struct.pack('<QQ6I',*info));cpu.reg_write(UC_ARM64_REG_X0,0)
        for i in range(3,18):cpu.reg_write(UC_ARM64_REG_X0+i,0xBAD000+i)

    def instruction(self,cpu,address,size,data):
        if address==STOP:cpu.emu_stop();return
        if address in (STOP+0x100,STOP+0x104):
            args=[cpu.reg_read(UC_ARM64_REG_X0+i) for i in range(8)]
            self.calls.append((address,args))
            cpu.reg_write(UC_ARM64_REG_SP,cpu.reg_read(UC_ARM64_REG_SP)+(0x50 if address==STOP+0x100 else 0x30))
            cpu.reg_write(UC_ARM64_REG_X0,77)
            cpu.reg_write(UC_ARM64_REG_PC,cpu.reg_read(UC_ARM64_REG_X30))

    def call(self,address,args=()):
        self.cpu.reg_write(UC_ARM64_REG_SP,STACK+0x1F000)
        for i in range(29):self.cpu.reg_write(UC_ARM64_REG_X0+i,0)
        for i,value in enumerate(args):self.cpu.reg_write(UC_ARM64_REG_X0+i,value&0xFFFFFFFFFFFFFFFF)
        self.cpu.reg_write(UC_ARM64_REG_X30,STOP)
        self.cpu.emu_start(address,STOP+4,count=1000000)
        self.assertEqual(self.cpu.reg_read(UC_ARM64_REG_PC),STOP)
        self.assertEqual(self.cpu.reg_read(UC_ARM64_REG_SP),STACK+0x1F000)
        return self.cpu.reg_read(UC_ARM64_REG_X0)

    def set_flag(self,bit,value):
        address=BASE+0x1CBB220+0x5DC0+bit//8
        byte=self.cpu.mem_read(address,1)[0]
        self.cpu.mem_write(address,bytes([(byte|1<<(bit%8)) if value else (byte&~(1<<(bit%8)))]))

    def test_indexed_sources_suppress_vanilla_grant_and_use_saved_source_ownership(self):
        sources=[r for r in self.rows if r['index']>=0]
        self.assertEqual(len(sources),38)
        for row in sources:
            self.assertEqual(self.call(BASE+0x8D1A30,[row['item'],1,row['index']]),0)
            self.call(BASE+0x8D08E0,[row['item'],1,row['index']])
            self.assertEqual(self.calls,[])
            self.set_flag(row['flag'],True)
            self.assertEqual(self.call(BASE+0x8D1A30,[row['item'],1,row['index']]),1)
            self.set_flag(row['flag'],False)
            self.assertEqual(self.call(BASE+0x8D1A30,[row['item'],1,row['index']]),0)

    def test_real_collectibles_bypass_source_interception_and_decode_index(self):
        for item,limit in ((22,50),(58,32)):
            for index in range(limit):
                args=[item,1,0x53470000|index,3,4,5,6,7]
                self.assertEqual(self.call(BASE+0x8D08E0,args),77)
                args[2]=index
                self.assertEqual(self.calls[-1],(STOP+0x100,args))
            before=len(self.calls)
            self.call(BASE+0x8D08E0,[item,1,0x53470000|limit])
            self.assertEqual(len(self.calls),before)

    def test_stolen_shop_dummies_queue_without_entering_inventory(self):
        rows=[r for r in self.rows if r['pending']>=0]
        if not rows:self.skipTest('Shop patch is not installed')
        self.assertEqual(len(rows),10)
        for row in rows:
            self.call(BASE+0x8D08E0,[row['item'],1,-1])
            self.assertEqual(self.calls,[])
            address=BASE+0x1CBB220+0x5DC0+row['pending']//8
            self.assertTrue(self.cpu.mem_read(address,1)[0]&(1<<(row['pending']%8)))
            self.assertEqual(self.call(BASE+0x8D1A30,[row['item'],1,-1]),0)
            self.set_flag(row['flag'],True)
            self.assertEqual(self.call(BASE+0x8D1A30,[row['item'],1,-1]),1)

    def test_aggregate_and_unrelated_inventory_calls_are_forwarded(self):
        for args in ([22,50,-1,3,4,5,6,7],[6,1,-1,3,4,5,6,7],[22,1,49,3,4,5,6,7]):
            if any(r['item']==args[0] and r['index']==args[2] for r in self.rows):continue
            self.assertEqual(self.call(BASE+0x8D1A30,args),77)
            self.assertEqual(self.calls[-1][1],[x&0xFFFFFFFFFFFFFFFF for x in args])
        self.assertEqual(self.call(BASE+0x8D08E0,[105,1,-1,3,4,5,6,7]),77)

    def test_shop_dummies_never_reach_inventory_when_save_pointer_is_unavailable(self):
        self.cpu.mem_write(BASE+0x1CC1388,struct.pack('<Q',0))
        for row in self.rows:
            if row['pending']>=0:self.assertEqual(self.call(BASE+0x8D08E0,[row['item'],1,-1]),0)
        self.assertEqual(self.calls,[])

if __name__=='__main__':unittest.main()
