# from keystone import * # - pip install keystone-engine


class Patcher:
    def __init__(self):
        """Initializes a patcher object to convert and write patches"""

        self.nso_header_offset = 0x100
        self.ks = None # Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        self.patches = []
    

    def addPatch(self, address: int, instruction):
        """Adds the patch to a list if the address offset is valid, raises ValueError if not
        
        NSO Header address offset is automatically handled"""
        
        address += self.nso_header_offset

        if address > 0xFFFFFFFF:
            raise ValueError('Patch address is not valid')
        else:
            self.patches.append((address, instruction))
        

    def generatePatch(self):
        """Writes and outputs the IPS32 patch"""

        result = bytearray('IPS32', 'ascii')

        for patch in self.patches:
            address = patch[0]
            instruction = bytearray(self.ks.asm(patch[1])[0])
            
            result += address.to_bytes(4, 'big')
            result += len(instruction).to_bytes(2, 'big')
            result += instruction
        
        result += bytearray('EEOF', 'ascii')

        return result
