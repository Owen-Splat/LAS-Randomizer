"""NSO serialization and dispatch gates (MIT, LAS integration contributors)."""
import hashlib
import struct
import lz4.block
from elftools.elf.elffile import ELFFile
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
