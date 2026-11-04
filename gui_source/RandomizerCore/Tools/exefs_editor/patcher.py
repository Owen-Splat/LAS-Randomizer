from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN


class Patcher:
    def __init__(self):
        """Initializes a patcher object to convert and write patches"""

        self.nso_header_offset = 0x100
        self.ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        self.patches = []


    def addPatch(self, address: int, instruction: str, comment=None):
        """Changes the ASM instruction at address
        
        Multi-line instructions do not change what address we write to afterwards"""

        instruction = self.ks.asm(instruction, as_bytes=True)[0]
        self.patches.append((address, instruction, comment))


    def replaceString(self, address: int, new_string: str, comment=None):
        """Changes a string in the data section into new_string"""

        self.patches.append((address, new_string, comment))


    def replaceShort(self, address: int, value: int, comment=None):
        """Changes a short in the data section into value"""

        instruction = value.to_bytes(1, 'little', signed=True)
        self.patches.append((address, instruction, comment))


    def generateIPS32Patch(self):
        """Writes and outputs the IPS32 patch"""

        result = b''
        result += bytearray('IPS32', 'ascii')

        for patch in self.patches:
            address = patch[0] + self.nso_header_offset
            instruction = patch[1]
            if isinstance(instruction, str):
                instruction = instruction.replace('"', '')
                instruction = bytes(instruction, 'utf-8') + b'\x00' # null-terminated

            result += address.to_bytes(4, 'big')
            result += len(instruction).to_bytes(2, 'big')
            result += instruction

        result += bytearray('EEOF', 'ascii')

        return result


    def generatePCHTXT(self, build_id: str):
        version = "1.0.0" if build_id.startswith("A") else "1.0.1"
        outText = f"@nsobid-{build_id}\n"
        outText += f"# Zelda: Link's Awakening [01006BB00C6F0000] {version}\n\n"

        if self.nso_header_offset != 0:
            outText += f"@flag offset_shift {'0x{:x}'.format(self.nso_header_offset)}\n"

        for patch in self.patches:
            address, instruction, comment = patch
            address = address.to_bytes(4, 'big')
            if isinstance(instruction, bytes):
                instruction = instruction.hex().upper()
            if len(comment) > 0:
                outText += f"\n{comment}\n"
                outText += "@enabled\n"
            outText += f"{address.hex().upper()} {instruction}\n"

        outBuffer = bytearray(outText, "ascii")
        return outBuffer
