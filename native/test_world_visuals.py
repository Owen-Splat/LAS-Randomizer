"""NPC selector/asset safety tests, NOT a substitute for real scene rendering.

The NPC constructor is substituted only at its boundary to inspect arguments.
This suite never calls that substitution evidence that a model renders safely.
"""
from pathlib import Path
import sys,json,struct,unittest,tempfile,shutil,argparse,hashlib
import test_native as n
from world_visuals import validate
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X30,UC_ARM64_REG_PC,UC_ARM64_REG_SP
BASE,STACK=n.BASE,n.STACK
MOD=None;CLEAN=None;CONTROL=None;PLAN=None

class Selector(n.NativeTests):
    def setUp(self):
        super().setUp();self.npc_calls=[];self.factory_calls=[]
        self.call(self.symbols['las_init'])

    def instruction(self,cpu,address,size,data):
        if address==BASE+0x8c3f10+16:
            self.npc_calls.append([cpu.reg_read(UC_ARM64_REG_X0+i) for i in range(8)])
            sp=cpu.reg_read(UC_ARM64_REG_SP)
            for off,reg in ((0x10,21),(0x20,20),(0x28,19),(0x30,29),(0x38,30)):
                cpu.reg_write(UC_ARM64_REG_X0+reg,struct.unpack('<Q',cpu.mem_read(sp+off,8))[0])
            cpu.reg_write(UC_ARM64_REG_SP,sp+0x40)
            cpu.reg_write(UC_ARM64_REG_X0,0xabcdef)
            cpu.reg_write(UC_ARM64_REG_PC,cpu.reg_read(UC_ARM64_REG_X30));return
        if address==BASE+n.FACTORY+16:
            self.factory_calls.append([cpu.reg_read(UC_ARM64_REG_X0+i) for i in range(8)])
            sp=cpu.reg_read(UC_ARM64_REG_SP)
            for off,reg in ((0,28),(8,27),(0x10,26),(0x18,25),(0x20,24),(0x28,23),(0x30,22),(0x38,21)):
                cpu.reg_write(UC_ARM64_REG_X0+reg,struct.unpack('<Q',cpu.mem_read(sp+off,8))[0])
            cpu.reg_write(UC_ARM64_REG_SP,sp+0x60)
            cpu.reg_write(UC_ARM64_REG_X0,0xabcdef)
            cpu.reg_write(UC_ARM64_REG_PC,cpu.reg_read(UC_ARM64_REG_X30));return
        super().instruction(cpu,address,size,data)

    def arguments(self,index,kind=0x87,native=22,tag=3,vtable=0x1bc9408,name=b'ItemSecretSeashell'):
        actor=STACK+0x3000;context=STACK+0x4000;span=STACK+0x5000;text=STACK+0x5100
        self.cpu.mem_write(actor,bytes(0x380));self.cpu.mem_write(actor,struct.pack('<Q',BASE+vtable))
        self.cpu.mem_write(actor+0x98,struct.pack('<QH',0x1234567890,kind))
        self.cpu.mem_write(actor+0xbc,struct.pack('<II',index,tag));self.cpu.mem_write(actor+0x2e8,bytes([native]))
        self.cpu.mem_write(STACK+0x6100,b'Npc\0')
        # The real 0x8b3c18..0x8b3c38 callsite puts owner at +0x18.
        self.cpu.mem_write(context,struct.pack('<5Q',STACK+0x6100,3,1,actor,STACK+0x6000))
        self.cpu.mem_write(text,name+b'\0');self.cpu.mem_write(span,struct.pack('<QQ',text,len(name)))
        return [STACK+0x7000,context,span,3,4,5,6,7]

    def test_every_shell_selects_its_own_persistent_name_without_changing_owner(self):
        rows=self.report['world_visual_checks'];self.assertTrue(rows)
        names=[];save=BASE+0x1cbb220;before_save=bytes(self.cpu.mem_read(save,0x5ee0))
        for row in rows:
            args=self.arguments(row['index']);before=bytes(self.cpu.mem_read(STACK+0x3000,0x1040))
            self.call(self.symbols['las_world_npc'],args)
            actual=self.npc_calls[-1];expected=args.copy();expected[2]=actual[2]
            self.assertEqual(actual,expected);self.assertNotEqual(actual[2],args[2])
            text,length=struct.unpack('<QQ',self.cpu.mem_read(actual[2],16))
            self.assertEqual(bytes(self.cpu.mem_read(text,length)),row['npc_key'].encode())
            self.assertEqual(bytes(self.cpu.mem_read(STACK+0x3000,0x1040)),before)
            names.append((actual[2],text,length,row['npc_key']))
        self.assertEqual(len({x[0] for x in names}),len(rows))
        self.cpu.mem_write(STACK+0x3000,bytes(0x2200))
        for span,text,length,key in names:self.assertEqual(bytes(self.cpu.mem_read(text,length)),key.encode())
        self.assertEqual(bytes(self.cpu.mem_read(save,0x5ee0)),before_save)
        self.assertEqual(self.reward_calls,[])

    def test_unmanaged_heart_overlap_wrong_tag_class_and_metadata_forward_unchanged(self):
        known=self.report['world_visual_checks'][0]['index']
        for changes in ({'index':999},{'index':known,'native':58},{'index':known,'kind':0xb0},
                        {'index':known,'tag':5},{'index':known,'vtable':0x1bc9d50},
                        {'index':known,'name':b'UnexpectedNpc'}):
            args=self.arguments(**changes);self.call(self.symbols['las_world_npc'],args)
            self.assertEqual(self.npc_calls[-1],args)

    def test_factory_forwards_original_descriptor_and_all_eight_arguments(self):
        for kind,index,tag in ((0x87,1,3),(0xb0,1,3),(0x87,999,3),(0x87,1,5),(0x55,1,3)):
            info=STACK+0x1000;raw=bytearray(0x1c0)
            struct.pack_into('<H',raw,8,kind);struct.pack_into('<II',raw,0x10,index,tag)
            self.cpu.mem_write(info,bytes(raw));args=[STACK+0x800,STACK+0xa00,info,3,4,5,6,7]
            self.call(self.symbols['las_factory'],args)
            self.assertEqual(self.factory_calls[-1],args)
            self.assertEqual(bytes(self.cpu.mem_read(info,0x1c0)),bytes(raw))

class Assets(unittest.TestCase):
    def test_metadata_covers_every_indexed_shell_and_no_heart_piece(self):
        rows=validate(MOD/'romfs',CLEAN,PLAN,json.loads((MOD/'native-shell-plan.json').read_text())['checks'])
        self.assertTrue(rows);self.assertEqual({r['native_id'] for r in rows},{22})
        self.assertEqual(len({r['index'] for r in rows}),len(rows))
        data=json.loads((MOD/'native-world-visual-plan.json').read_text())
        sources=json.loads((MOD/'native-shell-plan.json').read_text())['checks']
        expected={r['location'] for r in sources if r.get('native_id',22)==22}
        self.assertEqual({r['location'] for r in rows}|{r['location'] for r in data['unsupported']},expected)

    def test_rooms_ap_events_and_original_npc_rows_are_unchanged(self):
        if CONTROL is None:
            data=json.loads((MOD/'native-world-visual-plan.json').read_text())
            self.assertTrue(data['preserved_file_hashes'])
            for relative,expected in data['preserved_file_hashes'].items():
                self.assertEqual(hashlib.sha256((MOD/'romfs'/relative).read_bytes()).hexdigest(),expected,relative)
            import oead
            updated=oead.gsheet.parse(oead.Bytes((MOD/'romfs/region_common/datasheets/Npc.gsheet').read_bytes()))
            original=oead.gsheet.Sheet()
            for field in ('alignment','hash','name','root_fields'):setattr(original,field,getattr(updated,field))
            original.values=oead.gsheet.StructArray(list(updated.values[:data['original_npc_count']]))
            self.assertEqual(hashlib.sha256(original.to_binary()).hexdigest(),data['original_npc_digest'])
            return
        for old in (CONTROL/'romfs').rglob('*'):
            if old.is_file() and old.name!='Npc.gsheet':
                self.assertEqual(old.read_bytes(),(MOD/old.relative_to(CONTROL)).read_bytes(),str(old.relative_to(CONTROL)))
        import oead
        relative='romfs/region_common/datasheets/Npc.gsheet'
        original=oead.gsheet.parse(oead.Bytes((CONTROL/relative).read_bytes()))
        updated=oead.gsheet.parse(oead.Bytes((MOD/relative).read_bytes()))
        self.assertEqual(list(updated.values[:len(original.values)]),list(original.values))

    def test_invalid_mapping_duplicate_and_changed_behavior_are_rejected(self):
        rows=json.loads((MOD/'native-shell-plan.json').read_text())['checks']
        original=json.loads((MOD/'native-world-visual-plan.json').read_text())
        with tempfile.TemporaryDirectory(prefix='visual-test-',dir=MOD.parent) as temporary:
            root=Path(temporary).resolve()
            self.assertEqual(root.parent,MOD.parent.resolve())
            romfs=root/'romfs';(romfs/'region_common/datasheets').mkdir(parents=True)
            shutil.copyfile(MOD/'romfs/region_common/datasheets/Npc.gsheet',romfs/'region_common/datasheets/Npc.gsheet')
            import copy
            for change in ('duplicate','wrong_native','wrong_reward','missing_npc'):
                data=copy.deepcopy(original)
                if change=='duplicate':data['checks'].append(data['checks'][0])
                if change=='wrong_native':data['checks'][0]['native_id']=58
                if change=='wrong_reward':data['checks'][0]['model_name']='InvalidModel'
                if change=='missing_npc':data['checks'][0]['npc_key']='Missing'
                (root/'native-world-visual-plan.json').write_text(json.dumps(data))
                with self.assertRaises(ValueError):validate(romfs,CLEAN,PLAN,rows)
            import oead
            (root/'native-world-visual-plan.json').write_text(json.dumps(original))
            sheet=oead.gsheet.parse(oead.Bytes((romfs/'region_common/datasheets/Npc.gsheet').read_bytes()))
            clone=next(r for r in sheet.values if r['symbol']==original['checks'][0]['npc_key'])
            clone['collision']['isStatic']=not clone['collision']['isStatic']
            (romfs/'region_common/datasheets/Npc.gsheet').write_bytes(sheet.to_binary())
            with self.assertRaisesRegex(ValueError,'pickup behavior'):validate(romfs,CLEAN,PLAN,rows)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('build',type=Path);p.add_argument('--mod',type=Path,required=True)
    p.add_argument('--clean-romfs',type=Path,required=True);p.add_argument('--control',type=Path);p.add_argument('--plan',type=Path,required=True)
    a=p.parse_args();n.BUILD=a.build;MOD=a.mod;CLEAN=a.clean_romfs;CONTROL=a.control;PLAN=json.loads(a.plan.read_text())
    suite=unittest.TestSuite(Selector(name) for name in Selector.__dict__ if name.startswith('test_'))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(Assets))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
