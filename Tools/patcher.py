# MIT License

# Copyright (c) 2022 Alden Mo

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Pokemon Brilliant Diamond Shining Pearl Randomizer
# by Aldo796, Copycat, SanGawku, XLuma, and Red.#9015


# from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN # - pip install keystone-engine



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

        result = b''
        result += bytearray('IPS32', 'ascii')

        for patch in self.patches:
            address = patch[0]
            # instruction = bytearray(self.ks.asm(patch[1])[0])
            instruction = bytearray(patch[1])
            result += address.to_bytes(4, 'big')
            result += len(instruction).to_bytes(2, 'big')
            result += instruction
        
        result += bytearray('EEOF', 'ascii')

        return result
