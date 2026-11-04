"""Execute the compiled ARM64 probe and dispatch gates using Unicorn."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import unittest
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC
from build import NSO, ADD, FRAME, HAS, FACTORY, PROLOGUES, align, copy_import_slots

BASE=0x7100000000
MODULE=0x7200000000
STACK=0x7300000000
STOP=0x7400000000
BUILD=None

class NativeTests(unittest.TestCase):
    def setUp(self):
        self.game=NSO((BUILD/"mod/exefs/main").read_bytes())
        self.module=NSO((BUILD/"mod/exefs/subsdk9").read_bytes())
        self.report=json.loads((BUILD/"probe_report.json").read_text())
        self.layout=self.report['state_layout']
        self.state_offset=self.layout['offset']
        self.state_size=self.layout['size']
        self.check_limit=self.layout['check_limit']
        self.cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        self.cpu.mem_map(BASE,align(self.game.segments[2][0]+len(self.game.segments[2][1])+self.game.bss))
        self.cpu.mem_map(MODULE,align(self.module.segments[2][0]+len(self.module.segments[2][1])+self.module.bss))
        self.cpu.mem_map(STACK,0x20000)
        self.cpu.mem_map(STOP,0x1000)
        self.sdk_stubs={}
        self.net_success=False
        self.sent=[]
        self.received_ping=False
        self.bridge_io=False
        self.incoming=bytearray()
        self.empty_reads=0
        self.rebind_imports=False
        for origin,nso in ((BASE,self.game),(MODULE,self.module)):
            for off,data in nso.segments:self.cpu.mem_write(origin+off,bytes(data))
        with (BUILD/"build/probe.elf").open("rb") as stream:
            elf=ELFFile(stream)
            self.symbols={s.name:s["st_value"]+MODULE for s in elf.get_section_by_name(".symtab").iter_symbols()}
            for sec in elf.iter_sections():
                if sec["sh_type"]=="SHT_RELA":
                    for r in sec.iter_relocations():
                        if r["r_info_type"]==1027:
                            value=MODULE+r["r_addend"]
                        elif r["r_info_type"] in (1025,1026):
                            sym=elf.get_section(sec["sh_link"]).get_symbol(r["r_info_sym"]).name
                            value=STOP+0x100+len(self.sdk_stubs)*4
                            self.sdk_stubs[value]=sym
                        else:self.fail("Unsupported native relocation")
                        self.cpu.mem_write(MODULE+r["r_offset"],struct.pack("<Q",value))
            self.assertTrue(any(t.entry.d_tag=="DT_INIT" for t in elf.get_section_by_name(".dynamic").iter_tags()))
        self.logs=[]
        self.cpu.hook_add(UC_HOOK_INTR,self.interrupt)
        self.cpu.hook_add(UC_HOOK_CODE,self.instruction)
        self.original_calls=[]
        self.reward_calls=[]
        self.event_calls=[]
        self.mock_events=False
        self.event_accept=True
        self.mock_factory=False
        self.mock_event_api=False
        self.api_calls=[]
        self.factory_infos=[]
        self.test_heap=STACK+0x10000
        self.reward_fail=False
        self.real_rewards=False
        self.snapshot_during_reward=False
        self.snapshot_return=None
        self.reentrant_snapshot=None
        self.copy_slots={}
        if self.report.get("save_copy_observation"):
            self.copy_slots=copy_import_slots(self.game)
            for i,(name,slot) in enumerate(self.copy_slots.items()):
                stub=STOP+0x800+i*4
                self.sdk_stubs[stub]=name
                self.cpu.mem_write(BASE+slot,struct.pack("<Q",stub))

    def interrupt(self,cpu,number,data):
        pc=cpu.reg_read(UC_ARM64_REG_PC)
        instruction=struct.unpack("<I",cpu.mem_read(pc-4,4))[0]
        svc=(instruction>>5)&0xFFFF
        if svc==0x27:
            self.logs.append(bytes(cpu.mem_read(cpu.reg_read(UC_ARM64_REG_X0),cpu.reg_read(UC_ARM64_REG_X1))).decode())
            cpu.reg_write(UC_ARM64_REG_X0,0)
        elif svc==6:
            address=cpu.reg_read(UC_ARM64_REG_X2)
            end=BASE+align(len(self.game.segments[0][1]))
            if address<BASE: info=(0,BASE,0,0,0,0,0,0)
            elif address<end: info=(BASE,end-BASE,3,0,5,0,0,0)
            else: cpu.reg_write(UC_ARM64_REG_X0,1);return
            cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X0),struct.pack("<QQ6I",*info))
            cpu.reg_write(UC_ARM64_REG_X0,0)
        else:self.fail(f"Unexpected SVC {svc:x}")
        # Horizon calls are not C calls; actively poison scratch registers to
        # detect accidental assumptions about the kernel's register preservation.
        for i in range(3,18):cpu.reg_write(UC_ARM64_REG_X0+i,0xBAD000+i)

    def instruction(self,cpu,address,size,data):
        if address==STOP:cpu.emu_stop()
        if self.mock_factory and address in (BASE+0x1D510,BASE+0x1431170,BASE+FACTORY+16):
            if address==BASE+0x1431170:
                size=cpu.reg_read(UC_ARM64_REG_X0);result=self.test_heap;self.test_heap+=align(size,16)
                assert self.test_heap<STACK+0x1D000
                cpu.reg_write(UC_ARM64_REG_X0,result)
            elif address==BASE+FACTORY+16:
                self.factory_infos.append(bytes(cpu.mem_read(cpu.reg_read(UC_ARM64_REG_X2),0x1C0)))
                cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X0),struct.pack('<QQ',STACK+0x1B000,STACK+0x1B100))
                cpu.reg_write(UC_ARM64_REG_SP,cpu.reg_read(UC_ARM64_REG_SP)+0x60)
            cpu.reg_write(UC_ARM64_REG_PC,cpu.reg_read(UC_ARM64_REG_X30));return
        api_names={0xFBBD80:'load',0x3DC20:'wait',0x3D9F0:'flow',0x80C290:'request',0x80DB00:'prepare',
                   0x81F2E0:'submit',0xBAE080:'release',0x1B730:'scene'}
        if self.mock_event_api and address-BASE in api_names:
            name=api_names[address-BASE];args=[cpu.reg_read(UC_ARM64_REG_X0+i) for i in range(3)]
            self.api_calls.append((name,args))
            if name in ('load','flow','request','submit'):
                number=('load','flow','request','submit').index(name)
                cpu.mem_write(args[0],struct.pack('<QQ',STACK+0x18000+number*0x100,STACK+0x18800+number*0x100))
            if name=='scene':cpu.mem_write(args[0],struct.pack('<QQ',STACK+0x1A000,STACK+0x1A100))
            cpu.reg_write(UC_ARM64_REG_PC,cpu.reg_read(UC_ARM64_REG_X30));return
        if self.mock_events and address in (self.symbols.get('native_request_common'),self.symbols.get('native_spawn_zol')):
            self.event_calls.append(address)
            cpu.reg_write(UC_ARM64_REG_X0,int(self.event_accept))
            cpu.reg_write(UC_ARM64_REG_PC,cpu.reg_read(UC_ARM64_REG_X30));return
        if address==STOP+0xC00 and self.snapshot_return is not None:
            self.reentrant_snapshot=bytes(cpu.mem_read(STACK+0x8000,0x5EE0))
            target=self.snapshot_return;self.snapshot_return=None
            cpu.reg_write(UC_ARM64_REG_PC,target);return
        if self.real_rewards and address in (BASE+0xDF40E0,BASE+0x1431CC0,BASE+0xDF42D0):
            # UI notification helpers do not participate in inventory storage.
            cpu.reg_write(UC_ARM64_REG_X0,0)
            cpu.reg_write(UC_ARM64_REG_PC,cpu.reg_read(UC_ARM64_REG_X30));return
        if address in self.sdk_stubs:
            name=self.sdk_stubs[address]
            args=[cpu.reg_read(UC_ARM64_REG_X0+i) for i in range(5)]
            result=0
            if name in ("memcpy","memmove"):
                cpu.mem_write(args[0],bytes(cpu.mem_read(args[1],args[2])));result=args[0]
            elif name=="write_file":result=0x12345678
            elif "Initialize" in name:result=0 if self.net_success else 1
            elif name=="nnsocketSocket":result=7
            elif name=="nnsocketConnect":result=-1
            elif name=="nnsocketGetLastErrno":result=11
            elif name=="nnsocketPoll":
                events=struct.unpack('<h',cpu.mem_read(args[0]+4,2))[0]
                ready=events if not self.bridge_io or events==4 or self.incoming else 0
                cpu.mem_write(args[0]+6,struct.pack('<h',ready));result=bool(ready)
            elif name=="nnsocketSend":self.sent.append(bytes(cpu.mem_read(args[1],args[2])));result=args[2]
            elif name=="nnsocketRecv":
                if self.bridge_io:
                    if self.incoming:
                        chunk=bytes(self.incoming[:min(7,args[2])]);del self.incoming[:len(chunk)]
                        cpu.mem_write(args[1],chunk);result=len(chunk)
                    else:self.empty_reads+=1;result=0
                elif not self.received_ping:
                    cpu.mem_write(args[1],b"PING\n");result=5;self.received_ping=True
                else:result=-1
            if self.rebind_imports and name in self.copy_slots:
                cpu.mem_write(BASE+self.copy_slots[name],struct.pack("<Q",address))
            cpu.reg_write(UC_ARM64_REG_X0,result&0xFFFFFFFFFFFFFFFF)
            cpu.reg_write(UC_ARM64_REG_PC,cpu.reg_read(UC_ARM64_REG_X30))
            return
        if address==BASE+0x7E18B0:
            args=[cpu.reg_read(UC_ARM64_REG_X0+i) for i in range(4)]
            self.reward_calls.append(args)
            if self.real_rewards:
                # Execute the real inspected inner inventory function, including
                # the native detour/forwarding path, instead of the effect stub.
                cpu.reg_write(UC_ARM64_REG_PC,BASE+ADD);return
            rupees=BASE+0x1CBB220+0x5540
            value=struct.unpack("<I",cpu.mem_read(rupees,4))[0]
            amounts={102:5,104:20,105:50,106:100,108:300}
            if self.reward_fail:
                cpu.reg_write(UC_ARM64_REG_PC,cpu.reg_read(UC_ARM64_REG_X30));return
            if args[0] in amounts:cpu.mem_write(rupees,struct.pack("<I",min(value+amounts[args[0]],9999)))
            elif args[0]==16:
                owned=BASE+0x1CBB220+0x5568
                bits=struct.unpack('<I',cpu.mem_read(owned,4))[0]
                cpu.mem_write(owned,struct.pack('<I',bits|0x1000))
            elif not self.report.get('reward_programs'):self.fail('Unexpected native grant item')
            found=BASE+0x1CBB220+0x55E4+args[0]//8
            cpu.mem_write(found,bytes([cpu.mem_read(found,1)[0]|(1<<(args[0]%8))]))
            if self.snapshot_during_reward:
                self.snapshot_during_reward=False
                self.snapshot_return=cpu.reg_read(UC_ARM64_REG_X30)
                cpu.reg_write(UC_ARM64_REG_X0,STACK+0x8000)
                cpu.reg_write(UC_ARM64_REG_X1,BASE+0x1CBB220)
                cpu.reg_write(UC_ARM64_REG_X2,0x5EE0)
                cpu.reg_write(UC_ARM64_REG_X30,STOP+0xC00)
                copier=struct.unpack('<Q',cpu.mem_read(BASE+self.copy_slots['memcpy'],8))[0]
                cpu.reg_write(UC_ARM64_REG_PC,copier);return
            cpu.reg_write(UC_ARM64_REG_PC,cpu.reg_read(UC_ARM64_REG_X30))
            return
        if address not in (BASE+ADD+16,BASE+FRAME+16):return
        if self.real_rewards and address==BASE+ADD+16:return
        which=ADD if address==BASE+ADD+16 else FRAME
        args=[cpu.reg_read(UC_ARM64_REG_X0+i) for i in range(8)]
        self.original_calls.append((which,args))
        sp=cpu.reg_read(UC_ARM64_REG_SP)
        if which==ADD:
            for offset,regs in ((0x10,(23,)),(0x20,(22,21)),(0x30,(20,19))):
                for i,reg in enumerate(regs):cpu.reg_write(UC_ARM64_REG_X0+reg,struct.unpack("<Q",cpu.mem_read(sp+offset+8*i,8))[0])
            cpu.reg_write(UC_ARM64_REG_SP,sp+0x50)
        else:
            for offset,reg in ((0x18,27),(0x20,26),(0x28,25)):
                cpu.reg_write(UC_ARM64_REG_X0+reg,struct.unpack("<Q",cpu.mem_read(sp+offset,8))[0])
            cpu.reg_write(UC_ARM64_REG_SP,sp+0x70)
        cpu.reg_write(UC_ARM64_REG_X0,0xC0FFEE)
        cpu.reg_write(UC_ARM64_REG_PC,cpu.reg_read(UC_ARM64_REG_X30))

    def call(self,address,args=()):
        self.cpu.reg_write(UC_ARM64_REG_SP,STACK+0x1F000)
        for i in range(29):self.cpu.reg_write(UC_ARM64_REG_X0+i,0x1000+i)
        for i,value in enumerate(args):self.cpu.reg_write(UC_ARM64_REG_X0+i,value)
        self.cpu.reg_write(UC_ARM64_REG_X30,STOP)
        self.cpu.emu_start(address,STOP+4,count=1000000)
        self.assertEqual(self.cpu.reg_read(UC_ARM64_REG_PC),STOP,"Native routine failed to return")
        self.assertEqual(self.cpu.reg_read(UC_ARM64_REG_SP),STACK+0x1F000)

    def test_fallback_add_preserves_all_eight_arguments(self):
        self.call(BASE+ADD,range(8))
        self.assertEqual(self.original_calls,[(ADD,list(range(8)))])
        self.assertEqual(self.logs,[])

    def test_fallback_frame_preserves_all_eight_arguments(self):
        self.call(BASE+FRAME,range(8))
        self.assertEqual(self.original_calls,[(FRAME,list(range(8)))])

    def test_display_only_ids_never_reach_inventory_even_without_a_marker(self):
        ids=self.report.get('display_only_item_ids')
        if not ids:self.skipTest('No display-only item IDs')
        self.call(self.symbols['las_init'])
        for item in ids:self.call(BASE+ADD,[item,1,0xFFFFFFFF,0,0,0,0,0])
        self.assertEqual(self.original_calls,[])
        self.assertEqual(self.reward_calls,[])
        self.call(BASE+ADD,[200,1,0xFFFFFFFF,0,0,0,0,0])
        self.assertEqual(len(self.original_calls),1)

    def test_native_init_finds_profile_and_populates_dispatch_slots(self):
        self.call(self.symbols["las_init"])
        mailbox=BASE+int(self.report["mailbox"],16)
        self.assertEqual(struct.unpack("<QQ",self.cpu.mem_read(mailbox,16)),
                         (self.symbols["las_add"],self.symbols["las_frame"]))

    def test_hook_add_forwards_and_preserves_return_value(self):
        self.call(self.symbols["las_init"])
        self.call(BASE+ADD,[102,1,0xDEADBEEF,3,4,5,6,7])
        self.assertEqual(self.original_calls,[(ADD,[102,1,0xDEADBEEF,3,4,5,6,7])])
        self.assertEqual(self.cpu.reg_read(UC_ARM64_REG_X0),0xC0FFEE)
        self.assertTrue(any("add index=00000000DEADBEEF" in line for line in self.logs))

    def test_hook_frame_forwards_and_preserves_return_value(self):
        self.call(self.symbols["las_init"])
        self.call(BASE+FRAME,range(8))
        self.assertEqual(self.original_calls,[(FRAME,list(range(8)))])
        self.assertEqual(self.cpu.reg_read(UC_ARM64_REG_X0),0xC0FFEE)
        self.assertTrue(any("frame=" in line for line in self.logs))

    def test_profile_mismatch_leaves_fallback_enabled(self):
        self.cpu.mem_write(BASE+ADD,b"\0"*4)
        self.call(self.symbols["las_init"])
        mailbox=BASE+int(self.report["mailbox"],16)
        self.assertEqual(bytes(self.cpu.mem_read(mailbox,16)),b"\0"*16)
        self.assertTrue(any("ERROR" in line for line in self.logs))

    def test_reward_variant_suppresses_only_the_sentinel(self):
        if not self.report.get("isolated_sentinel_suppression_test",self.report.get("isolated_reward_test")):self.skipTest("Read-only variant")
        self.call(self.symbols["las_init"])
        for _ in range(2):self.call(BASE+ADD,[105,1,0x4C415300,0,0,0,0,0])
        self.assertEqual(self.original_calls,[])
        self.assertEqual(self.reward_calls,[])
        label=self.report.get("check_label","woods-south-chest")
        self.assertEqual(sum("CHECK "+label in s for s in self.logs),2)

    def test_reward_variant_waits_for_gameplay_then_grants_once(self):
        if not self.report.get("isolated_reward_test"):self.skipTest("Read-only variant")
        self.call(self.symbols["las_init"])
        for _ in range(370):self.call(BASE+FRAME)
        self.assertEqual(self.reward_calls,[])
        manager=BASE+0x1CDA200
        self.cpu.mem_write(BASE+0x1C97188,struct.pack("<Q",manager))
        self.cpu.mem_write(manager+0x4B8,struct.pack("<Q",manager+0x600))
        for _ in range(359):self.call(BASE+FRAME)
        self.assertEqual(self.reward_calls,[])
        self.call(BASE+FRAME)
        self.assertEqual(self.reward_calls,[[105,1,0xFFFFFFFFFFFFFFFF,0]])
        for _ in range(360):self.call(BASE+FRAME)
        self.assertEqual(len(self.reward_calls),1)
        self.assertEqual(struct.unpack("<I",self.cpu.mem_read(BASE+0x1CBB220+0x5540,4))[0],50)

    def test_network_diagnostic_nonblocking_ping_pong(self):
        if not self.report.get("loopback_transport_diagnostic"):self.skipTest("No transport diagnostic")
        self.net_success=True
        self.call(self.symbols["las_init"])
        for _ in range(65):self.call(self.symbols["network_probe_tick"])
        self.assertEqual(self.sent,[b"LAS_NATIVE_PROBE_V1\n",b"PONG\n"])
        self.assertEqual(self.reward_calls,[])

    def test_network_initialization_failure_preserves_gameplay(self):
        if not self.report.get("loopback_transport_diagnostic"):self.skipTest("No transport diagnostic")
        self.call(self.symbols["las_init"])
        for _ in range(65):self.call(BASE+FRAME)
        self.assertEqual(len(self.original_calls),65)
        self.assertEqual(self.sent,[])
        self.assertTrue(any("initialize failed" in s for s in self.logs))

    def test_save_copy_observer_preserves_data_and_return(self):
        if not self.report.get("save_copy_observation"):self.skipTest("No save observer")
        self.call(self.symbols["las_init"])
        source=BASE+0x1CBB220+0x10;destination=STACK+0x500
        data=bytes(range(32));self.cpu.mem_write(source,data)
        function=struct.unpack("<Q",self.cpu.mem_read(BASE+self.copy_slots["memcpy"],8))[0]
        self.call(function,[destination,source,len(data)])
        self.assertEqual(bytes(self.cpu.mem_read(destination,len(data))),data)
        self.assertEqual(self.cpu.reg_read(UC_ARM64_REG_X0),destination)
        self.assertTrue(any("LAS_AP_SAVE copy source=" in s for s in self.logs))

    def test_save_copy_observer_ignores_unrelated_copies(self):
        if not self.report.get("save_copy_observation"):self.skipTest("No save observer")
        self.call(self.symbols["las_init"])
        source=STACK+0x500;destination=STACK+0x600
        self.cpu.mem_write(source,b"ordinary copy")
        function=struct.unpack("<Q",self.cpu.mem_read(BASE+self.copy_slots["memmove"],8))[0]
        self.call(function,[destination,source,13])
        self.assertEqual(bytes(self.cpu.mem_read(destination,13)),b"ordinary copy")
        self.assertFalse(any("LAS_AP_SAVE copy source=" in s for s in self.logs))

    def test_save_write_observer_preserves_buffer_and_result(self):
        if not self.report.get("save_copy_observation"):self.skipTest("No save observer")
        self.call(self.symbols["las_init"])
        source=STACK+0x100;data=bytes(range(256))*96
        self.cpu.mem_write(source,data)
        function=struct.unpack("<Q",self.cpu.mem_read(BASE+self.copy_slots["write_file"],8))[0]
        self.call(function,[7,0,source,len(data),0])
        self.assertEqual(bytes(self.cpu.mem_read(source,len(data))),data)
        self.assertEqual(self.cpu.reg_read(UC_ARM64_REG_X0),0x12345678)
        self.assertTrue(any("LAS_AP_SAVE write size=" in s for s in self.logs))

    def test_save_observers_survive_import_rebinding(self):
        if not self.report.get("save_copy_observation"):self.skipTest("No save observer")
        self.call(self.symbols["las_init"])
        self.rebind_imports=True
        source=BASE+0x1CBB220+0x10;destination=STACK+0x500
        self.cpu.mem_write(source,b"same snapshot")
        for name in ("memcpy","memmove"):
            slot=BASE+self.copy_slots[name]
            observer=struct.unpack("<Q",self.cpu.mem_read(slot,8))[0]
            for _ in range(2):
                self.call(observer,[destination,source,13])
                self.assertEqual(struct.unpack("<Q",self.cpu.mem_read(slot,8))[0],observer)
                self.assertEqual(bytes(self.cpu.mem_read(destination,13)),b"same snapshot")
        slot=BASE+self.copy_slots["write_file"]
        observer=struct.unpack("<Q",self.cpu.mem_read(slot,8))[0]
        for _ in range(2):
            self.call(observer,[7,0,source,0x5000,0])
            self.assertEqual(struct.unpack("<Q",self.cpu.mem_read(slot,8))[0],observer)
            self.assertEqual(self.cpu.reg_read(UC_ARM64_REG_X0),0x12345678)

    def state_call(self,name,args):
        self.call(self.symbols[name],args)
        return struct.unpack("<i",struct.pack("<I",self.cpu.reg_read(UC_ARM64_REG_X0)&0xFFFFFFFF))[0]

    def state_fixture(self):
        state,fp,previous,next_hash=STACK+0x4000,STACK+0x4200,STACK+0x4300,STACK+0x4400
        self.cpu.mem_write(fp,bytes(range(16)))
        self.cpu.mem_write(previous,hashlib.sha256(b"[]").digest())
        self.cpu.mem_write(next_hash,hashlib.sha256(b"[[105,-1,0]]").digest())
        return state,fp,previous,next_hash

    def test_native_receipt_core_rejects_wrong_identity_hash_and_future(self):
        state,fp,previous,nxt=self.state_fixture()
        self.assertEqual(self.state_call("las_state_bind",[state,fp]),1)
        snapshot=bytes(self.cpu.mem_read(state,self.state_size))
        self.assertEqual(self.state_call("las_state_prepare",[state,fp,1,previous,nxt]),-3)
        self.assertEqual(self.state_call("las_state_prepare",[state,fp,0,previous+64,nxt]),-4)
        self.assertEqual(self.state_call("las_state_prepare",[state,fp+64,0,previous,nxt]),-2)
        self.assertEqual(bytes(self.cpu.mem_read(state,self.state_size)),snapshot)

    def test_native_receipt_core_commit_duplicate_and_rollback(self):
        state,fp,previous,nxt=self.state_fixture()
        self.assertEqual(self.state_call("las_state_bind",[state,fp]),1)
        old=bytes(self.cpu.mem_read(state,self.state_size))
        self.assertEqual(self.state_call("las_state_commit",[state,fp,0,previous,nxt]),0)
        committed=bytes(self.cpu.mem_read(state,self.state_size))
        self.assertEqual(self.state_call("las_state_commit",[state,fp,0,previous,nxt]),2)
        self.assertEqual(bytes(self.cpu.mem_read(state,self.state_size)),committed)
        self.cpu.mem_write(state,old)
        self.assertEqual(self.state_call("las_state_cursor",[state]),0)
        self.assertEqual(self.state_call("las_state_commit",[state,fp,0,previous,nxt]),0)
        self.assertEqual(bytes(self.cpu.mem_read(state,self.state_size)),committed)

    def test_native_receipt_check_bounds_and_corrupt_state(self):
        state,fp,previous,nxt=self.state_fixture()
        self.cpu.mem_write(state+self.state_size,b"canary")
        self.assertEqual(self.state_call("las_state_bind",[state,fp]),1)
        self.assertEqual(self.state_call("las_state_check",[state,fp,self.check_limit-1]),0)
        self.assertEqual(self.state_call("las_state_check",[state,fp,self.check_limit]),-5)
        self.assertEqual(bytes(self.cpu.mem_read(state+self.state_size,6)),b"canary")
        self.cpu.mem_write(state+2,b'\xff')
        before=bytes(self.cpu.mem_read(state,self.state_size))
        self.assertEqual(self.state_call("las_state_bind",[state,fp]),-1)
        self.assertEqual(bytes(self.cpu.mem_read(state,self.state_size)),before)

    def test_native_state_all_check_bits_and_wrong_version(self):
        state,fp,previous,nxt=self.state_fixture()
        self.assertEqual(self.state_call('las_state_bind',[state,fp]),1)
        for ordinal in range(self.check_limit):
            self.assertEqual(self.state_call('las_state_check',[state,fp,ordinal]),0)
        self.assertEqual(self.state_call('las_state_validate',[state,fp]),0)
        bits=bytes(self.cpu.mem_read(state+56,(self.check_limit+7)//8))
        self.assertEqual(int.from_bytes(bits,'little'),(1<<self.check_limit)-1)
        self.cpu.mem_write(state+2,bytes([3-self.layout['version']]))
        before=bytes(self.cpu.mem_read(state,self.state_size))
        self.assertEqual(self.state_call('las_state_bind',[state,fp]),-1)
        self.assertEqual(bytes(self.cpu.mem_read(state,self.state_size)),before)

    def configure_receipt_game(self):
        manager=BASE+0x1CDA200
        self.cpu.mem_write(BASE+0x1C97188,struct.pack("<Q",manager))
        self.cpu.mem_write(manager+0x4B8,struct.pack("<Q",manager+0x600))
        self.cpu.mem_write(BASE+0x1CC1390,struct.pack("<I",256))
        self.cpu.mem_write(BASE+0x1CBB220+0x5544,b'\x0c\0')
        self.cpu.mem_write(BASE+0x1CC1388,struct.pack("<Q",BASE+0x1CBB220+0x5DC0))
        self.cpu.mem_write(BASE+0x1CC1368,struct.pack('<Q',BASE+0x1CBB220+0x54C0))
        self.cpu.mem_write(BASE+0x1CBB220+0x5DC0+258//8,bytes([1<<(258%8)]))
        table=STACK+0x6000
        self.cpu.mem_write(BASE+0x1CC11B0,struct.pack('<Q',table))
        for number in range(10):
            self.cpu.mem_write(table+number*8,struct.pack('<Q',BASE+0x1CBB220+0xE0+number*0x20))

    def command_call(self,name,packet):
        raw=json.dumps(packet,separators=(',',':')).encode()
        self.cpu.mem_write(STACK+0x3000,raw)
        self.assertEqual(self.state_call('wire_parse',[STACK+0x100,STACK+0x3000,len(raw)]),0)
        return self.state_call(name,[STACK+0x100])

    def bridge_fixture(self):
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        self.call(BASE+ADD,[6,1,self.report['managed_check_plan']['checks'][0]['marker'],0,0,0,0,0])
        for _ in range(61):self.call(BASE+FRAME)

    def read_bridge_state(self):
        size=self.state_call('native_bridge_state',[STACK+0x8000,8192])
        self.assertGreater(size,0)
        return json.loads(bytes(self.cpu.mem_read(STACK+0x8000,size)))

    def test_deathlink_command_is_idempotent_and_does_not_advance_item_receipts(self):
        if not self.report.get('native_json_bridge_diagnostic'):self.skipTest('No native bridge')
        self.bridge_fixture();self.mock_events=True
        command={'t':'deathlink','nonce':77}
        if not self.report.get('death_link_enabled'):
            self.assertEqual(self.command_call('native_bridge_deathlink',command),-1);return
        save=BASE+0x1CBB220;before=bytes(self.cpu.mem_read(save,0x5EE0))
        self.assertEqual(self.command_call('native_bridge_deathlink',command),0)
        self.assertEqual(self.command_call('native_bridge_deathlink',command),0)
        self.assertEqual(len(self.event_calls),1)
        state=self.read_bridge_state()
        self.assertEqual(state['deathlink_ack'],77);self.assertTrue(state['deathlink_busy']);self.assertFalse(state['ready'])
        self.assertEqual(state['cursor'],0);self.assertEqual(self.reward_calls,[])
        self.assertEqual(bytes(self.cpu.mem_read(save,0x5EE0)),before)
        self.cpu.mem_write(save+0x5544,b'\0\0');self.call(BASE+FRAME)
        state=self.read_bridge_state()
        self.assertFalse(state['alive']);self.assertFalse(state['deathlink_busy']);self.assertFalse(state['ready'])
        self.assertEqual(self.command_call('native_bridge_deathlink',{'t':'deathlink','nonce':78}),1)

    def test_native_hint_requests_are_bounded_idempotent_and_wait_for_dialog_completion(self):
        count=self.report.get('hint_count',0)
        if not self.report.get('native_json_bridge_diagnostic') or count<1:self.skipTest('No native hint table')
        self.bridge_fixture();self.mock_events=True
        before=bytes(self.cpu.mem_read(BASE+0x1CBB220,0x5EE0))
        packet={'t':'hint','nonce':111,'index':0}
        self.assertEqual(self.command_call('native_bridge_hint',packet),0)
        self.assertEqual(self.command_call('native_bridge_hint',packet),0)
        self.assertEqual(len(self.event_calls),1)
        state=self.read_bridge_state()
        self.assertEqual(state['hint_ack'],111);self.assertTrue(state['hint_busy']);self.assertFalse(state['ready'])
        if count>1:self.assertEqual(self.command_call('native_bridge_hint',dict(packet,index=1)),-1)
        self.assertEqual(self.command_call('native_bridge_hint',dict(packet,index=count)),-1)
        next_index=1 if count>1 else 0
        self.assertEqual(self.command_call('native_bridge_hint',dict(packet,nonce=112,index=next_index)),1)
        self.call(BASE+ADD,[6,1,0x4C420002,0,0,0,0,0])
        self.assertEqual(self.command_call('native_bridge_hint',dict(packet,nonce=112,index=next_index)),0)
        self.assertEqual(len(self.event_calls),2)
        self.assertEqual(self.reward_calls,[])
        self.assertEqual(bytes(self.cpu.mem_read(BASE+0x1CBB220,0x5EE0)),before)

    def test_bridge_state_buffer_bound_handles_every_managed_check(self):
        if not self.report.get('native_json_bridge_diagnostic'):self.skipTest('No native bridge')
        self.bridge_fixture()
        checks=len(self.report['managed_check_plan']['checks'])
        self.cpu.mem_write(BASE+0x1CBB220+self.state_offset+56,((1<<checks)-1).to_bytes((checks+7)//8,'little'))
        self.assertEqual(len(self.read_bridge_state()['checks']),checks)
        output=STACK+0x8000;self.cpu.mem_write(output,b'canary')
        self.assertEqual(self.state_call('native_bridge_state',[output,384+11*checks-1]),-1)
        self.assertEqual(bytes(self.cpu.mem_read(output,6)),b'canary')

    def test_unmanaged_vanilla_collectible_indexes_are_reserved(self):
        from reward_catalog import reserve_vanilla_indexes
        catalog={'logic_nodes':{'vanilla':{'type':'item','content':'seashell','index':0},
                                'managed':{'type':'item','content':'seashell','index':1},
                                'heart':{'type':'item','content':'heart-piece','index':2}}}
        rewards={'supported':[{'kind':'indexed','name':'seashell','indexes':[0,1,2]},
                              {'kind':'indexed','name':'heart-piece','indexes':[0,1,2]}]}
        reserved=reserve_vanilla_indexes(rewards,catalog,{'managed'})
        self.assertEqual(reserved['seashell'],[0]);self.assertEqual(reserved['heart-piece'],[2])
        self.assertEqual(rewards['supported'][0]['indexes'],[1,2])
        self.assertEqual(rewards['supported'][1]['indexes'],[0,1])

    def test_fresh_slot_binds_before_first_check_but_completed_vanilla_save_does_not(self):
        if not self.report.get('native_json_bridge_diagnostic'):self.skipTest('No native bridge')
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        save=BASE+0x1CBB220
        self.cpu.mem_write(save+0x5DC0+258//8,b'\0')
        victory=save+0x5DC0+240//8
        self.cpu.mem_write(victory,bytes([1<<(240%8)]))
        for _ in range(61):self.call(BASE+FRAME)
        state=self.read_bridge_state()
        self.assertFalse(state['victory']);self.assertFalse(state['ready'])
        self.cpu.mem_write(victory,b'\0');self.call(BASE+FRAME)
        state=self.read_bridge_state()
        self.assertTrue(state['ready']);self.assertTrue(state['alive'])
        self.assertEqual(state['cursor'],0);self.assertEqual(state['checks'],[])
        self.assertEqual(self.reward_calls,[])

    def test_json_reader_rejects_malformed_and_bounded_inputs(self):
        if 'wire_parse' not in self.symbols:self.skipTest('No JSON parser')
        ctx,text=STACK+0x100,STACK+0x3000
        valid=[b'{}',b'{"t":"deliver","grant":{"item_id":1280507904}}',b'[null,true,false,-1,1.25,1e2,"a\\u0041"]']
        invalid=[b'',b'{',b'{"a":}',b'{"a":1,}',b'[1,]',b'01',b'1.',b'1e',b'{}{}',b'"bad\\q"',b'"\x01"',b'['*18+b']'*18]
        for raw in valid+invalid:
            self.cpu.mem_write(text,raw or b'\0')
            result=self.state_call('wire_parse',[ctx,text,len(raw)])
            self.assertEqual(result==0,raw in valid,raw)

    def test_native_bridge_accepts_one_valid_receipt_and_rejects_wrong_or_unsupported_grants(self):
        if not self.report.get('native_json_bridge_diagnostic'):self.skipTest('No native JSON bridge')
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        row=self.report['managed_check_plan']['checks'][0]
        self.call(BASE+ADD,[6,1,row['marker'],0,0,0,0,0])
        for _ in range(61):self.call(BASE+FRAME)
        item=1280507989
        digest=lambda rows:hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()
        packet={'t':'deliver','expected_cursor':0,'expected_hash':digest([]),
                'next_hash':digest([[item,1280512316,1]]),
                'grant':{'item_id':item,'item_name':'rupee-50','item_key':'Rupee50',
                         'receipt_index':0,'collectible_index':-1,'dungeon':None,
                         'semantic':'las_event_reward','count':1}}
        def deliver(value):
            raw=json.dumps(value,separators=(',',':')).encode()
            self.cpu.mem_write(STACK+0x3000,raw)
            self.assertEqual(self.state_call('wire_parse',[STACK+0x100,STACK+0x3000,len(raw)]),0)
            return self.state_call('native_bridge_deliver',[STACK+0x100])
        bad=json.loads(json.dumps(packet));bad['expected_hash']='00'*32
        self.assertEqual(deliver(bad),-1)
        bad=json.loads(json.dumps(packet));bad['grant']['item_id']=1280507904
        self.assertEqual(deliver(bad),-1)
        self.assertEqual(self.reward_calls,[])
        self.assertEqual(deliver(packet),0)
        self.assertEqual(deliver(packet),0)
        self.assertEqual(len(self.reward_calls),1)
        save=BASE+0x1CBB220
        self.assertEqual(struct.unpack('<I',self.cpu.mem_read(save+0x5540,4))[0],50)
        self.assertEqual(self.state_call('las_state_cursor',[save+self.state_offset]),1)
        size=self.state_call('native_bridge_state',[STACK+0x8000,8192])
        state=json.loads(bytes(self.cpu.mem_read(STACK+0x8000,size)))
        self.assertEqual(state['cursor'],1)
        self.assertEqual(state['history_hash'],packet['next_hash'])
        self.assertEqual(state['checks'],[row['location_id']])
        if 'bridge_supported_items' in self.report:
            ocarina=self.report['bridge_supported_items']['ocarina']
            packet['expected_cursor']=1;packet['expected_hash']=packet['next_hash']
            packet['next_hash']=digest([[item,1280512316,1],[ocarina,1280512316,1]])
            packet['grant'].update(item_id=ocarina,item_name='ocarina',item_key='Ocarina',receipt_index=1)
            self.assertEqual(deliver(packet),0)
            self.assertEqual(deliver(packet),0)
            self.assertEqual(len(self.reward_calls),2)
            self.assertEqual(struct.unpack('<I',self.cpu.mem_read(save+0x5568,4))[0]&0x1000,0x1000)
            self.assertEqual(self.state_call('las_state_cursor',[save+self.state_offset]),2)

    def test_native_bridge_fragmented_ack_and_idle_socket_do_not_reconnect(self):
        if not self.report.get('native_json_bridge_diagnostic'):self.skipTest('No native JSON bridge')
        self.net_success=True;self.bridge_io=True
        self.incoming=bytearray(b'{"t":"hello_ack","protocol":1,"ok":true}\n')
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        row=self.report['managed_check_plan']['checks'][0]
        self.call(BASE+ADD,[6,1,row['marker'],0,0,0,0,0])
        for _ in range(300):self.call(BASE+FRAME)
        messages=[json.loads(raw) for raw in b''.join(self.sent).splitlines()]
        self.assertEqual(sum(m['t']=='hello' for m in messages),1)
        self.assertTrue(any(m.get('checks')==[row['location_id']] for m in messages if m['t']=='state'))
        self.assertEqual(self.empty_reads,0)

    def test_real_inner_game_equipment_and_progressive_storage(self):
        if not self.report.get('reward_programs'):self.skipTest('No compiled reward catalog')
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        save=BASE+0x1CBB220
        self.cpu.mem_write(BASE+0x1CC1368,struct.pack('<Q',save+0x54C0))
        self.call(BASE+ADD,[6,1,self.report['managed_check_plan']['checks'][0]['marker'],0,0,0,0,0])
        for _ in range(61):self.call(BASE+FRAME)
        self.real_rewards=True
        programs={r['name']:r for r in self.report['reward_programs']['supported']}
        names=['sword','sword','shield','shield','bracelet','bracelet','ocarina','hookshot','bow','feather','boots','shovel','rod']
        history=[]
        digest=lambda rows:hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()
        for index,name in enumerate(names):
            r=programs[name];previous=digest(history);history.append([r['item_id'],-1,0])
            packet={'t':'deliver','expected_cursor':index,'expected_hash':previous,'next_hash':digest(history),
                    'grant':{'item_id':r['item_id'],'item_name':name,'item_key':r['key'],
                             'receipt_index':index,'collectible_index':-1,'dungeon':None,
                             'semantic':'progressive' if r['kind']=='progressive' else 'las_event_reward','count':1}}
            raw=json.dumps(packet,separators=(',',':')).encode()
            self.cpu.mem_write(STACK+0x3000,raw)
            self.assertEqual(self.state_call('wire_parse',[STACK+0x100,STACK+0x3000,len(raw)]),0)
            self.assertEqual(self.state_call('native_bridge_deliver',[STACK+0x100]),0,name)
            self.assertEqual(self.state_call('native_bridge_deliver',[STACK+0x100]),0,name)
        self.assertEqual(len(self.reward_calls),len(names))
        self.assertEqual(bytes(self.cpu.mem_read(save+0x555C,1))[0]&7,7)
        owned=struct.unpack('<I',self.cpu.mem_read(save+0x5568,4))[0]
        for bit in (0,1,3,4,6,7,9,10,11,12):self.assertTrue(owned&(1<<bit),bit)
        self.assertEqual(self.state_call('las_state_cursor',[save+self.state_offset]),len(names))

    def test_event_receipts_wait_for_completion_and_reject_duplicate_effects(self):
        if not self.report.get('reward_programs'):self.skipTest('No reward programs')
        programs=[r for r in self.report['reward_programs']['supported'] if r['kind'] in ('event','spawn')]
        self.assertEqual(len(programs),7)
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        save=BASE+0x1CBB220
        self.cpu.mem_write(save+0x5544,b'\x0c\0')
        self.call(BASE+ADD,[6,1,self.report['managed_check_plan']['checks'][0]['marker'],0,0,0,0,0])
        for _ in range(61):self.call(BASE+FRAME)
        self.mock_events=True
        history=[]
        digest=lambda rows:hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()
        for r in programs:
            previous=digest(history);index=len(history);history.append([r['item_id'],-1,0])
            packet={'t':'deliver','expected_cursor':index,'expected_hash':previous,'next_hash':digest(history),
                    'grant':{'item_id':r['item_id'],'item_name':r['name'],'item_key':r['key'],
                             'receipt_index':index,'collectible_index':-1,'dungeon':None,'semantic':'las_event_reward','count':1}}
            def deliver():
                raw=json.dumps(packet,separators=(',',':')).encode();self.cpu.mem_write(STACK+0x3000,raw)
                self.assertEqual(self.state_call('wire_parse',[STACK+0x100,STACK+0x3000,len(raw)]),0)
                return self.state_call('native_bridge_deliver',[STACK+0x100])
            self.cpu.mem_write(save+0x5544,b'\x0c\0')
            self.event_accept=False
            self.assertEqual(deliver(),1)
            self.assertEqual(self.state_call('las_state_cursor',[save+self.state_offset]),index)
            self.event_accept=True
            self.assertEqual(deliver(),0)
            calls=len(self.event_calls)
            if r['kind']=='event':
                self.cpu.mem_write(save+0x5544,b'\x08\0')
                copyfn=struct.unpack('<Q',self.cpu.mem_read(BASE+self.copy_slots['memcpy'],8))[0]
                self.call(copyfn,[STACK+0x8000,save,0x5EE0])
                pending=bytes(self.cpu.mem_read(STACK+0x8000,0x5EE0))
                self.assertEqual(struct.unpack_from('<I',pending,self.state_offset+20)[0],index)
                # A save during the event contains its complete pre-event image.
                self.assertNotEqual(pending[0x5544:0x5546],b'\x08\0')
                if index==0:
                    self.call(copyfn,[save,STACK+0x8000,0x5EE0])
                    self.call(BASE+ADD,[6,1,0x4C420000,0,0,0,0,0])
                    self.assertEqual(self.state_call('las_state_cursor',[save+self.state_offset]),index)
                    for _ in range(61):self.call(BASE+FRAME)
                    self.assertEqual(deliver(),0)
                    calls=len(self.event_calls)
                self.assertEqual(deliver(),1)
                self.assertEqual(len(self.event_calls),calls)
                self.assertEqual(self.state_call('las_state_cursor',[save+self.state_offset]),index)
                if index==0:
                    self.cpu.mem_write(save+0x5544,b'\0\0')
                    self.call(BASE+FRAME)
                    size=self.state_call('native_bridge_state',[STACK+0x6000,8192])
                    self.assertFalse(json.loads(bytes(self.cpu.mem_read(STACK+0x6000,size)))['ready'])
                    self.cpu.mem_write(save+0x5544,b'\x0c\0')
                self.call(BASE+ADD,[6,1,0x4C420000,0,0,0,0,0])
            self.assertEqual(self.state_call('las_state_cursor',[save+self.state_offset]),index+1)
            self.assertEqual(deliver(),0)
            self.assertEqual(len(self.event_calls),calls)
        self.assertEqual(self.reward_calls,[])

    def test_direct_shop_checks_and_shell_sources_do_not_grant_inventory(self):
        if not self.report.get('managed_check_plan'):self.skipTest('No managed checks')
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        save=BASE+0x1CBB220
        shell_bitmap=(1<<50)-1
        heart_bitmap=(1<<32)-1
        self.cpu.mem_write(save+0x5550,heart_bitmap.to_bytes(8,'little'))
        self.cpu.mem_write(save+0x5548,shell_bitmap.to_bytes(8,'little'))
        if self.report.get('shell_checks'):
            self.assertEqual(self.state_call('las_has',[22,50,0xFFFFFFFFFFFFFFFF]),1)
        for row in self.report.get('shell_checks',[]):
            self.assertEqual(self.state_call('las_has',[row.get('native_id',22),1,row['index']]),0)
            self.call(BASE+ADD,[row.get('native_id',22),1,row['index'],0,0,0,0,0])
            self.assertEqual(self.state_call('las_has',[row.get('native_id',22),1,row['index']]),1)
        for item,ordinal in self.report.get('direct_item_checks',[]):
            self.call(BASE+ADD,[item,1,0xFFFFFFFFFFFFFFFF,0,0,0,0,0])
            bit=bytes(self.cpu.mem_read(save+self.state_offset+56+ordinal//8,1))[0]
            self.assertTrue(bit&(1<<(ordinal%8)))
        self.assertEqual(self.original_calls,[])
        self.assertEqual(self.reward_calls,[])
        self.assertEqual(int.from_bytes(self.cpu.mem_read(save+0x5548,8),'little'),shell_bitmap)
        self.assertEqual(int.from_bytes(self.cpu.mem_read(save+0x5550,8),'little'),heart_bitmap)

    def test_shell_factory_parameters_use_real_pool_and_preserve_spawn_info(self):
        if not self.report.get('legacy_shell_parameter_renderer'):
            self.skipTest('Retired factory-parameter renderer; NPC component visuals tested separately')
        rows=self.report.get('shell_checks',[])
        if not rows:self.skipTest('No hidden shells')
        if not self.report.get('shell_models_enabled',True):self.skipTest('World pickups retain vanilla models')
        self.call(self.symbols['las_init']);self.mock_factory=True
        info=STACK+0x6000;source=bytearray(0x1C0)
        struct.pack_into('<H',source,8,0x87)
        struct.pack_into('<I',source,0x10,rows[0]['index']);source[0x14]=3
        self.cpu.mem_write(info,bytes(source))
        self.call(self.symbols['las_factory'],[STACK+0x7000,STACK+0x7100,info,0,0,0,0,0])
        result=self.factory_infos[-1]
        self.assertEqual(bytes(self.cpu.mem_read(info,len(source))),bytes(source))
        self.assertEqual(result[0x1C],5);self.assertEqual(result[0x24],5)
        vector=struct.unpack('<QQQ',self.cpu.mem_read(BASE+0x1CAB2D0,24))
        def pool_string(index):
            p=vector[0]+index*32;raw=bytes(self.cpu.mem_read(p,24))
            if raw[0]&1:
                length,ptr=struct.unpack_from('<QQ',raw,8);return bytes(self.cpu.mem_read(ptr,length)).decode()
            return raw[1:1+(raw[0]>>1)].decode()
        self.assertEqual(pool_string(struct.unpack_from('<I',result,0x18)[0]),rows[0]['model_path'])
        self.assertEqual(pool_string(struct.unpack_from('<I',result,0x20)[0]),rows[0]['model_name'])
        self.call(self.symbols['las_factory'],[STACK+0x7000,STACK+0x7100,info,0,0,0,0,0])
        self.assertEqual(self.factory_infos[-1],result)
        self.assertEqual(struct.unpack('<QQQ',self.cpu.mem_read(BASE+0x1CAB2D0,24)),vector)

    def test_common_event_request_uses_inspected_game_call_order_and_releases_handles(self):
        if 'native_request_common' not in self.symbols:self.skipTest('No event adapter')
        self.mock_event_api=True
        self.cpu.mem_write(BASE+0x1CC6DB8,struct.pack('<Q',STACK+0x17000))
        self.cpu.mem_write(BASE+0x1CB24D8,struct.pack('<Q',STACK+0x17100))
        text=STACK+0x5000;self.cpu.mem_write(text,b'AP_Receive_zap_trap\0')
        self.assertEqual(self.state_call('native_request_common',[BASE,text]),1)
        self.assertEqual([n for n,a in self.api_calls],['load','wait','flow','request','prepare','submit']+['release']*4)
        self.assertEqual([args[0] for name,args in self.api_calls if name=='release'],
                         [STACK+0x18B00,STACK+0x18A00,STACK+0x18900,STACK+0x18800])
        load=self.api_calls[0][1]
        pointer,length=struct.unpack('<QQ',self.cpu.mem_read(load[2],16))
        self.assertEqual(bytes(self.cpu.mem_read(pointer,length)),b'event/Common.bfevfl')
        self.cpu.mem_write(BASE+0x1CB24D8,b'\0'*8)
        calls=len(self.api_calls)
        self.assertEqual(self.state_call('native_request_common',[BASE,text]),0)
        self.assertEqual(len(self.api_calls),calls)

    def test_zol_spawn_builds_native_actor_parameters_and_releases_temporary_refs(self):
        if 'native_spawn_zol' not in self.symbols:self.skipTest('No event adapter')
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        self.mock_event_api=True;self.mock_factory=True
        manager=BASE+0x1CDA200;player=manager+0x600;collision=STACK+0x16000
        self.cpu.mem_write(player+0x80,struct.pack('<Q',collision))
        self.cpu.mem_write(collision,struct.pack('<Q',BASE+0x1C501F0))
        self.cpu.mem_write(collision+0x80,struct.pack('<fff',12.5,6.0,30.0))
        self.cpu.mem_write(player+0xB0,struct.pack('<I',7))
        self.cpu.mem_write(STACK+0x1A000+0x228,struct.pack('<Q',STACK+0x1A300))
        self.cpu.mem_write(STACK+0x1A300+0x1B8,struct.pack('<QQ',STACK+0x1A600,STACK+0x1A700))
        self.assertEqual(self.state_call('native_spawn_zol',[BASE,19]),1)
        info=self.factory_infos[-1]
        self.assertEqual(struct.unpack_from('<H',info,8)[0],0x1B)
        self.assertEqual(struct.unpack_from('<I',info,12)[0],7)
        self.assertEqual(struct.unpack_from('<fff',info,0x180),(12.5,6.5,30.0))
        self.assertEqual(struct.unpack_from('<Q',info)[0],0x4C41505A00000013)
        for i in range(8):self.assertEqual(info[0x14+i*8],5)
        self.assertEqual([n for n,a in self.api_calls],['scene','release','release'])

    def test_server_check_sync_is_bounded_atomic_and_does_not_advance_receipts(self):
        if 'native_bridge_sync_checks' not in self.symbols:self.skipTest('No check reconciliation')
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        rows=self.report['managed_check_plan']['checks']
        self.call(BASE+ADD,[6,1,rows[0]['marker'],0,0,0,0,0])
        for _ in range(61):self.call(BASE+FRAME)
        state=BASE+0x1CBB220+self.state_offset
        before=bytes(self.cpu.mem_read(state,self.state_size))
        def sync(checks):
            raw=json.dumps({'t':'sync_checks','checks':checks},separators=(',',':')).encode()
            self.cpu.mem_write(STACK+0x3000,raw)
            self.assertEqual(self.state_call('wire_parse',[STACK+0x100,STACK+0x3000,len(raw)]),0)
            return self.state_call('native_bridge_sync_checks',[STACK+0x100])
        for bad in ([rows[1]['location_id'],4294967295],None,{},['bad'],[True],
                    [rows[1]['location_id']]*129):
            self.assertEqual(sync(bad),-1)
            self.assertEqual(bytes(self.cpu.mem_read(state,self.state_size)),before)
        chosen=rows[1:129]
        self.assertEqual(sync([r['location_id'] for r in chosen]),0)
        after=bytes(self.cpu.mem_read(state,self.state_size))
        self.assertEqual(after[:56],before[:56])
        for r in chosen:self.assertTrue(after[56+r['ordinal']//8]&(1<<(r['ordinal']%8)))
        self.assertEqual(sync([r['location_id'] for r in chosen]),0)
        self.assertEqual(bytes(self.cpu.mem_read(state,self.state_size)),after)
        self.assertEqual(self.reward_calls,[])
        self.assertEqual(self.state_call('las_state_cursor',[state]),0)

    def test_json_reader_nested_fields_hash_and_overflow(self):
        if 'wire_parse' not in self.symbols:self.skipTest('No JSON parser')
        ctx,text,key,out=STACK+0x100,STACK+0x3000,STACK+0x5000,STACK+0x5100
        raw=b'{"grant":{"item_id":4294967295},"item_id":4294967296,"hash":"'+b'ab'*32+b'"}'
        self.cpu.mem_write(text,raw);self.assertEqual(self.state_call('wire_parse',[ctx,text,len(raw)]),0)
        self.cpu.mem_write(key,b'grant\0');grant=self.state_call('wire_member',[ctx,0,key])
        self.cpu.mem_write(key,b'item_id\0');item=self.state_call('wire_member',[ctx,grant,key])
        self.assertEqual(self.state_call('wire_u32',[ctx,item,out]),0)
        self.assertEqual(bytes(self.cpu.mem_read(out,4)),b'\xff'*4)
        item=self.state_call('wire_member',[ctx,0,key])
        self.assertEqual(self.state_call('wire_u32',[ctx,item,out]),-1)
        self.cpu.mem_write(key,b'hash\0');item=self.state_call('wire_member',[ctx,0,key])
        self.assertEqual(self.state_call('wire_hash',[ctx,item,out]),0)
        self.assertEqual(bytes(self.cpu.mem_read(out,32)),b'\xab'*32)
        raw=b'{"t":1,"t":2}';self.cpu.mem_write(text,raw)
        self.assertEqual(self.state_call('wire_parse',[ctx,text,len(raw)]),0)
        self.cpu.mem_write(key,b't\0');self.assertEqual(self.state_call('wire_member',[ctx,0,key]),-2)

    def test_dungeon_receipts_target_all_nine_records_and_match_real_game_fields(self):
        if not self.report.get('reward_programs'):self.skipTest('No compiled reward catalog')
        programs=[r for r in self.report['reward_programs']['supported'] if r['kind']=='dungeon']
        if not programs:self.skipTest('No dungeon programs')
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        save=BASE+0x1CBB220
        self.cpu.mem_write(BASE+0x1CC1368,struct.pack('<Q',save+0x54C0))
        self.call(BASE+ADD,[6,1,self.report['managed_check_plan']['checks'][0]['marker'],0,0,0,0,0])
        for _ in range(61):self.call(BASE+FRAME)
        history=[]
        digest=lambda rows:hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()
        for index,r in enumerate(programs):
            previous=digest(history);history.append([r['item_id'],-1,0])
            packet={'t':'deliver','expected_cursor':index,'expected_hash':previous,'next_hash':digest(history),
                    'grant':{'item_id':r['item_id'],'item_name':r['name'],'item_key':r['key'],
                             'receipt_index':index,'collectible_index':-1,'dungeon':r['dungeon'],
                             'semantic':'dungeon_item','count':1}}
            raw=json.dumps(packet,separators=(',',':')).encode();self.cpu.mem_write(STACK+0x3000,raw)
            self.assertEqual(self.state_call('wire_parse',[STACK+0x100,STACK+0x3000,len(raw)]),0)
            self.assertEqual(self.state_call('native_bridge_deliver',[STACK+0x100]),0,r['name'])
            self.assertEqual(self.state_call('native_bridge_deliver',[STACK+0x100]),0,r['name'])
        self.assertEqual(len(programs),45)
        self.assertEqual(self.reward_calls,[])
        for number in (*range(8),9):
            record=save+0xE0+number*0x20
            self.assertEqual(bytes(self.cpu.mem_read(record,2)),b'\x01\x0f')
        self.assertEqual(self.state_call('las_state_cursor',[save+self.state_offset]),45)
        # Verify the field meanings against the real game ARM64 inventory body.
        self.real_rewards=True
        self.cpu.mem_write(BASE+0x1CC13C8,b'\x00')
        record=save+0xE0
        self.cpu.mem_write(record,b'\0\0')
        for native,bits in ((44,1),(45,3),(47,7),(49,15)):
            self.call(BASE+ADD,[native,1,0xFFFFFFFF,0,0,0,0,0])
            self.assertEqual(bytes(self.cpu.mem_read(record+1,1)),bytes([bits]))
        self.call(BASE+ADD,[48,1,0xFFFFFFFF,0,0,0,0,0])
        self.assertEqual(bytes(self.cpu.mem_read(record,1)),b'\x01')

    def test_real_inner_indexed_allocations_preserve_existing_vanilla_bits(self):
        if not self.report.get('reward_programs'):self.skipTest('No compiled reward catalog')
        programs=[r for r in self.report['reward_programs']['supported'] if r['kind']=='indexed']
        if not programs:self.skipTest('No indexed programs')
        self.assertEqual(len(programs),6)
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        save=BASE+0x1CBB220
        self.cpu.mem_write(BASE+0x1CC1368,struct.pack('<Q',save+0x54C0))
        self.cpu.mem_write(BASE+0x1CB9FB8,struct.pack('<Q',STACK+0xA000))
        self.cpu.mem_write(BASE+0x1CC1208,struct.pack('<Q',save+0x5D00))
        self.cpu.mem_write(BASE+0x1CC1210,struct.pack('<I',8))
        self.cpu.mem_write(BASE+0x1CC12A8,struct.pack('<Q',save+0x5D20))
        self.cpu.mem_write(BASE+0x1CC12B0,struct.pack('<I',8))
        self.call(BASE+ADD,[6,1,self.report['managed_check_plan']['checks'][0]['marker'],0,0,0,0,0])
        for _ in range(61):self.call(BASE+FRAME)
        self.real_rewards=True;history=[]
        digest=lambda rows:hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()
        for r in programs:
            if not r['indexes']:
                previous=digest(history)
                packet={'t':'deliver','expected_cursor':len(history),'expected_hash':previous,'next_hash':digest(history+[[r['item_id'],-1,0]]),
                        'grant':{'item_id':r['item_id'],'item_name':r['name'],'item_key':r['key'],
                                 'receipt_index':len(history),'collectible_index':None,'ap_item_ordinal':0,
                                 'dungeon':None,'semantic':r['semantic'],'count':1}}
                self.assertEqual(self.command_call('native_bridge_deliver',packet),-1)
                self.assertEqual(self.state_call('las_state_cursor',[save+self.state_offset]),len(history))
                continue
            storage=save+(r['storage_offset'] if r['storage_offset']>=0 else 0x5D00)
            first=r['indexes'][0]+r['storage_shift'];byte=storage+first//8
            self.cpu.mem_write(byte,bytes([self.cpu.mem_read(byte,1)[0]|(1<<(first%8))]))
            for ordinal in range(len(r['indexes'])):
                index=len(history);previous=digest(history);history.append([r['item_id'],-1,0])
                packet={'t':'deliver','expected_cursor':index,'expected_hash':previous,'next_hash':digest(history),
                        'grant':{'item_id':r['item_id'],'item_name':r['name'],'item_key':r['key'],
                                 'receipt_index':index,'collectible_index':None,'ap_item_ordinal':ordinal,
                                 'dungeon':None,'semantic':'las_event_reward','count':1}}
                raw=json.dumps(packet,separators=(',',':')).encode();self.cpu.mem_write(STACK+0x3000,raw)
                self.assertEqual(self.state_call('wire_parse',[STACK+0x100,STACK+0x3000,len(raw)]),0)
                self.assertEqual(self.state_call('native_bridge_deliver',[STACK+0x100]),0,r['name'])
                self.assertEqual(self.state_call('native_bridge_deliver',[STACK+0x100]),0,r['name'])
            for actual in r['indexes']:
                bit=actual+r['storage_shift'];self.assertTrue(self.cpu.mem_read(storage+bit//8,1)[0]&(1<<(bit%8)))
            calls=[c for c in self.reward_calls if c[0]==r['native_ids'][0]]
            self.assertEqual([c[2] for c in calls],r['indexes'][1:],r['name'])
        self.assertEqual(self.state_call('las_state_cursor',[save+self.state_offset]),len(history))

    def test_real_inner_capacity_refills_medicine_and_final_trade_slot(self):
        if not self.report.get('reward_programs'):self.skipTest('No compiled reward catalog')
        programs={r['name']:r for r in self.report['reward_programs']['supported']}
        if 'medicine' not in programs:self.skipTest('No extended programs')
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        save=BASE+0x1CBB220
        self.cpu.mem_write(BASE+0x1CB9FB8,struct.pack('<Q',STACK+0xA000))
        self.call(BASE+ADD,[6,1,self.report['managed_check_plan']['checks'][0]['marker'],0,0,0,0,0])
        for _ in range(61):self.call(BASE+FRAME)
        self.real_rewards=True;history=[]
        digest=lambda rows:hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()
        def deliver(name):
            r=programs[name];index=len(history);previous=digest(history);history.append([r['item_id'],-1,0])
            packet={'t':'deliver','expected_cursor':index,'expected_hash':previous,'next_hash':digest(history),
                    'grant':{'item_id':r['item_id'],'item_name':name,'item_key':r['key'],
                             'receipt_index':index,'collectible_index':-1,'dungeon':None,
                             'semantic':'capacity_upgrade' if r['kind']=='capacity' else 'las_event_reward','count':1}}
            raw=json.dumps(packet,separators=(',',':')).encode();self.cpu.mem_write(STACK+0x3000,raw)
            self.assertEqual(self.state_call('wire_parse',[STACK+0x100,STACK+0x3000,len(raw)]),0)
            self.assertEqual(self.state_call('native_bridge_deliver',[STACK+0x100]),0,name)
        for name in ('powder-capacity','bomb-capacity','arrow-capacity'):deliver(name)
        self.assertEqual(self.cpu.mem_read(save+0x555C,1)[0]&0x38,0x38)
        self.assertEqual(struct.unpack('<I',self.cpu.mem_read(save+0x5568,4))[0]&(4|8|256),0)
        deliver('bomb');deliver('powder');deliver('bow');deliver('arrow-capacity')
        self.assertEqual(bytes(self.cpu.mem_read(save+0x555E,3)),bytes([60,60,40]))
        self.cpu.mem_write(save+0x5544,b'\x04\0')
        deliver('medicine')
        self.assertEqual(struct.unpack('<H',self.cpu.mem_read(save+0x5544,2))[0],12)
        self.assertEqual(self.cpu.mem_read(save+0x556C,1)[0]&2,2)
        self.assertEqual(self.cpu.mem_read(save+0x55E4+100//8,1)[0]&(1<<(100%8)),0)
        deliver('magnifying-lens')
        self.assertEqual(self.cpu.mem_read(save+0x555A,1)[0],14)
        self.assertTrue(self.cpu.mem_read(save+0x5DC0+271//8,1)[0]&(1<<(271%8)))

    def test_save_checksum_matches_real_game_crc_routine(self):
        if 'las_image_crc' not in self.symbols:self.skipTest('No save CRC implementation')
        self.call(self.symbols['las_init'])
        first,second,owner=STACK+0x100,STACK+0x8000,STACK+0x10000
        raw=(bytes(range(256))*95)[:0x5EE0]
        self.cpu.mem_write(first,raw);self.cpu.mem_write(second,raw)
        self.call(self.symbols['las_image_crc'],[first,BASE+0x17029F8])
        self.cpu.mem_write(owner+0x5F00,struct.pack('<Q',second))
        self.cpu.mem_write(owner+0x5F20,struct.pack('<Q',second+0xE0))
        self.call(BASE+0xDFAD00,[owner])
        self.assertEqual(bytes(self.cpu.mem_read(first,0x5EE0)),bytes(self.cpu.mem_read(second,0x5EE0)))

    def test_reentrant_save_during_grant_serializes_complete_previous_receipt(self):
        if 'las_image_crc' not in self.symbols or not self.report.get('reward_programs'):self.skipTest('No transactional snapshots')
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        save=BASE+0x1CBB220
        self.call(BASE+ADD,[6,1,self.report['managed_check_plan']['checks'][0]['marker'],0,0,0,0,0])
        for _ in range(61):self.call(BASE+FRAME)
        r=next(r for r in self.report['reward_programs']['supported'] if r['name']=='rupee-50')
        digest=lambda rows:hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()
        packet={'t':'deliver','expected_cursor':0,'expected_hash':digest([]),'next_hash':digest([[r['item_id'],-1,0]]),
                'grant':{'item_id':r['item_id'],'item_name':r['name'],'item_key':r['key'],'receipt_index':0,
                         'collectible_index':-1,'dungeon':None,'semantic':'las_event_reward','count':1}}
        raw=json.dumps(packet,separators=(',',':')).encode();self.cpu.mem_write(STACK+0x3000,raw)
        self.assertEqual(self.state_call('wire_parse',[STACK+0x100,STACK+0x3000,len(raw)]),0)
        self.snapshot_during_reward=True
        self.assertEqual(self.state_call('native_bridge_deliver',[STACK+0x100]),0)
        self.assertIsNotNone(self.reentrant_snapshot)
        self.assertEqual(struct.unpack_from('<I',self.reentrant_snapshot,0x5540)[0],0)
        self.assertEqual(struct.unpack_from('<I',self.reentrant_snapshot,self.state_offset+20)[0],0)
        self.assertEqual(struct.unpack('<I',self.cpu.mem_read(save+0x5540,4))[0],50)
        self.assertEqual(self.state_call('las_state_cursor',[save+self.state_offset]),1)
        # Check the substituted snapshot with the game's own checksum writer.
        owner=STACK+0x10000
        self.cpu.mem_write(owner+0x5F00,struct.pack('<Q',STACK+0x8000))
        self.cpu.mem_write(owner+0x5F20,struct.pack('<Q',STACK+0x8000+0xE0))
        self.call(BASE+0xDFAD00,[owner])
        self.assertEqual(bytes(self.cpu.mem_read(STACK+0x8000,0x5EE0)),self.reentrant_snapshot)

    def test_native_victory_reads_inspected_ending_flag_only_for_bound_save(self):
        if not self.report.get('reward_programs'):self.skipTest('No native bridge')
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        save=BASE+0x1CBB220
        self.call(BASE+ADD,[6,1,self.report['managed_check_plan']['checks'][0]['marker'],0,0,0,0,0])
        def state():
            size=self.state_call('native_bridge_state',[STACK+0x8000,8192])
            return json.loads(bytes(self.cpu.mem_read(STACK+0x8000,size)))
        self.assertFalse(state()['victory'])
        self.cpu.mem_write(save+0x5DC0+240//8,b'\x01')
        self.assertTrue(state()['victory'])
        self.cpu.mem_write(save+self.state_offset+4,b'wrong-save-id!!!')
        self.assertFalse(state()['victory'])

    def test_managed_all_markers_commit_correct_bits_without_inventory_effect(self):
        plan=self.report.get('managed_check_plan')
        if not plan:self.skipTest('No managed marker plan')
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        for row in plan['checks']:
            self.call(BASE+ADD,[6,1,row['marker'],0,0,0,0,0])
        self.assertEqual(self.original_calls,[])
        self.assertEqual(self.reward_calls,[])
        state=BASE+0x1CBB220+self.state_offset
        bits=bytes(self.cpu.mem_read(state+56,(len(plan['checks'])+7)//8))
        self.assertEqual(int.from_bytes(bits,'little'),(1<<len(plan['checks']))-1)
        before=bytes(self.cpu.mem_read(state,self.state_size))
        self.call(BASE+ADD,[6,1,plan['checks'][0]['marker'],0,0,0,0,0])
        self.assertEqual(bytes(self.cpu.mem_read(state,self.state_size)),before)
        copyfn=struct.unpack('<Q',self.cpu.mem_read(BASE+self.copy_slots['memcpy'],8))[0]
        self.call(copyfn,[STACK+0x100,BASE+0x1CBB220,0x5EE0])
        saved=bytes(self.cpu.mem_read(STACK+0x100,0x5EE0))
        self.setUp();self.cpu.mem_write(BASE+0x1CBB220,saved)
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        self.call(BASE+ADD,[6,1,plan['checks'][0]['marker'],0,0,0,0,0])
        self.assertEqual(bytes(self.cpu.mem_read(state,self.state_size)),before)

    def test_managed_wrong_identity_and_unknown_markers_do_not_change_state(self):
        plan=self.report.get('managed_check_plan')
        if not plan:self.skipTest('No managed marker plan')
        self.call(self.symbols['las_init']);self.configure_receipt_game()
        state=BASE+0x1CBB220+self.state_offset
        self.call(BASE+ADD,[6,1,plan['checks'][0]['marker'],0,0,0,0,0])
        self.cpu.mem_write(state+4,b'wrong-save-test!')
        before=bytes(self.cpu.mem_read(state,self.state_size))
        for item,marker in ((6,plan['checks'][1]['marker']),(6,0x4C41FFFF),(105,plan['checks'][2]['marker'])):
            self.call(BASE+ADD,[item,1,marker,0,0,0,0,0])
            self.assertEqual(bytes(self.cpu.mem_read(state,self.state_size)),before)
        self.assertEqual(self.original_calls,[])

    def test_receipt_driver_saves_effect_and_cursor_then_reload_does_not_grant(self):
        if not self.report.get("diagnostic_receipt_persistence"):self.skipTest("No persistent diagnostic")
        self.call(self.symbols["las_init"]);self.configure_receipt_game()
        for _ in range(365):self.call(BASE+FRAME)
        self.assertEqual(len(self.reward_calls),1)
        state=BASE+0x1CBB220+self.state_offset
        self.assertEqual(self.state_call("las_state_cursor",[state]),1)
        copier=struct.unpack("<Q",self.cpu.mem_read(BASE+self.copy_slots["memcpy"],8))[0]
        self.call(copier,[STACK+0x100,BASE+0x1CBB220,0x5EE0])
        saved=bytes(self.cpu.mem_read(STACK+0x100,0x5EE0))
        self.assertEqual(struct.unpack_from("<I",saved,0x5540)[0],50)
        self.setUp()  # New module BSS/process state, restored serialized game data.
        self.cpu.mem_write(BASE+0x1CBB220,saved)
        self.call(self.symbols["las_init"]);self.configure_receipt_game()
        for _ in range(365):self.call(BASE+FRAME)
        self.assertEqual(self.reward_calls,[])
        self.assertEqual(struct.unpack("<I",self.cpu.mem_read(BASE+0x1CBB220+0x5540,4))[0],50)
        self.assertTrue(any("no duplicate grant" in s for s in self.logs))

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("build",type=Path);p.add_argument('--report-json',type=Path);a=p.parse_args()
    BUILD=a.build.resolve()
    class RecordedResult(unittest.TextTestResult):
        def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.passed=[]
        def addSuccess(self,test):self.passed.append(test.id().rsplit('.',1)[-1]);super().addSuccess(test)
    result=unittest.TextTestRunner(verbosity=2,resultclass=RecordedResult).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeTests))
    if a.report_json:
        from validation import verified_capabilities
        report={'success':result.wasSuccessful(),'tests_run':result.testsRun,'passed':sorted(result.passed),
                'skipped':{test.id().rsplit('.',1)[-1]:reason for test,reason in result.skipped},
                'verified_capabilities':verified_capabilities(result.passed,result.wasSuccessful()),
                'files':{name:hashlib.sha256((BUILD/'mod/exefs'/name).read_bytes()).hexdigest() for name in ('main','subsdk9')}}
        a.report_json.write_text(json.dumps(report,indent=2))
    raise SystemExit(not result.wasSuccessful())
