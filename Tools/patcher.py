# from keystone import * # - pip install keystone-engine


class Patcher:
    def __init__(self):
        self.nso_header_offset = 0x100
        self.ks = None # Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        self.patches = []
    

    def addPatch(self, address: int, instruction):
        instruction = bytearray(self.ks.asm(instruction)[0])

        address += self.nso_header_offset
        if address > 0x0143109f:
            raise ValueError
        
        address = address.to_bytes(4, 'big')
        
        self.patches.append((address, instruction))
        

    def generatePatch(self):
        """Writes and outputs the IPS32 patch"""

        result = bytearray('IPS32', 'ascii')

        for patch in self.patches:
            address, instruction = patch
            result += address
            result += len(instruction).to_bytes(2, 'big')
            result += instruction
        
        result += bytearray('EEOF', 'ascii')

        return result
