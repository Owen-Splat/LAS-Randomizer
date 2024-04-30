from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN


class Patcher:
    def __init__(self):
        """Initializes a patcher object to convert and write patches"""

        self.nso_header_offset = 0x100
        self.ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        self.patches = []


    def addPatch(self, address: int, instruction: str):
        """Changes the ASM instruction at address
        
        Multi-line instructions do not change what address we write to afterwards"""

        instruction = self.ks.asm(instruction, as_bytes=True)[0]
        self.patches.append((address, instruction))


    def replaceString(self, address: int, new_string: str):
        """Changes a string at address into new_string"""

        instruction = bytes(new_string, 'utf-8') + b'\x00' # null-terminated
        self.patches.append((address, instruction))


    def generatePatch(self):
        """Writes and outputs the IPS32 patch"""

        result = b''
        result += bytearray('IPS32', 'ascii')

        for patch in self.patches:
            address = patch[0] + self.nso_header_offset
            instruction = patch[1]
            result += address.to_bytes(4, 'big')
            result += len(instruction).to_bytes(2, 'big')
            result += instruction

        result += bytearray('EEOF', 'ascii')

        return result
