from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN


class Patcher:
    def __init__(self):
        """Initializes a patcher object to convert and write patches"""

        self.nso_header_offset = 0x100
        self.ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        self.patches = []


    def addPatch(self, address: int, instruction: str):
        """Adds the patch to a list if the address offset is valid, raises ValueError if not
        
        NSO Header address offset is automatically handled"""
        
        address += self.nso_header_offset

        if address > 0xFFFFFFFF:
            raise ValueError('Patch address is not valid')
        else:
            self.patches.append((address, self.ks.asm(instruction, as_bytes=True)[0]))


    def generatePatch(self):
        """Writes and outputs the IPS32 patch"""

        result = b''
        result += bytearray('IPS32', 'ascii')

        for patch in self.patches:
            address = patch[0]
            instruction = patch[1]
            result += address.to_bytes(4, 'big')
            result += len(instruction).to_bytes(2, 'big')
            result += instruction
        
        result += bytearray('EEOF', 'ascii')

        return result
