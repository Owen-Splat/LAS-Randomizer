import os.path
import struct
import time
from copy import copy
from tkinter import Tk, filedialog

import Tools.bntx_editor.bntx_editor
from Tools.bntx_editor import bntx_editor
from randomizer_paths import RESOURCE_PATH

# BFRES textures replacer
# Copyright © 2018 AboodXD


class BlockHeader:
    def __init__(self, endianness):
        self.format = endianness + '4s2I4x'

    def load(self, data, pos):
        (self.magic,
         self.nextBlkAddr,
         self.blockSize) = struct.unpack_from(self.format, data, pos)

    def isValid(self, magic):
        if self.magic != magic:
            return 4

    def save(self):
        return struct.pack(
            self.format,
            self.magic,
            self.nextBlkAddr,
            self.blockSize,
        )

class RelocTBL:
    class Block:
        def __init__(self, endianness):
            self.format = endianness + 'Q2I2i'
            self.basePtr = 0

        def load(self, data, pos):
            (self.basePtr,
             self.pos,
             self.size_,
             self.relocEntryIdx,
             self.relocEntryCount) = struct.unpack_from(self.format, data, pos)

        def loadEntries(self, relocEntries):
            self.entries = relocEntries[self.relocEntryIdx:self.relocEntryIdx + self.relocEntryCount]

        def save(self):
            return struct.pack(
                self.format,
                self.basePtr,
                self.pos,
                self.size_,
                self.relocEntryIdx,
                self.relocEntryCount,
            )

    class Entry:
        def __init__(self, endianness):
            self.endianness = endianness
            self.format = endianness + 'IH2B'

        def load(self, data, pos):
            (self.pos,
             self.structCount,
             self.offsetCount,
             self.paddingCount) = struct.unpack_from(self.format, data, pos)

            self.structs = []
            self.padding = self.paddingCount * 8
            pos = self.pos

            for _ in range(self.structCount):
                struct_ = []
                for _ in range(self.offsetCount):
                    struct_.append(pos)
                    pos += 8

                self.structs.append(struct_)
                pos += self.padding

        def save(self):
            self.structCount = len(self.structs)

            if self.structs:
                self.offsetCount = len(self.structs[0])

            else:
                self.offsetCount = 0

            return struct.pack(
                self.format,
                self.pos,
                self.structCount,
                self.offsetCount,
                self.paddingCount,
            )

    def __init__(self, endianness):
        self.endianness = endianness

    def load(self, data, pos, blockCount):
        self.blocks = []

        for _ in range(blockCount):
            block = self.Block(self.endianness)
            block.load(data, pos)

            self.blocks.append(block)
            pos += 0x18

        self.entries = []

        try:
            numEntries = max([block.relocEntryIdx + block.relocEntryCount for block in self.blocks])

        except ValueError:
            pass

        else:
            for _ in range(numEntries):
                entry = self.Entry(self.endianness)
                entry.load(data, pos)

                self.entries.append(entry)
                pos += 8

    def save(self):
        return b''.join([
            b''.join([block.save() for block in self.blocks]),
            b''.join([entry.save() for entry in self.entries]),
        ])


def test():
    print("BFRES textures replacer")
    print("(C) 2018 AboodXD")

    root = Tk()
    root.withdraw()

    filetypes = [('BFRES files', '.bfres')]
    filename = filedialog.askopenfilename(filetypes=filetypes)

    if filename:
        with open(filename, "rb") as inf:
            inb = inf.read()

        if inb[:8] == b'FRES    ':
            print("\nSwitch BFRES detected!")

            bom = ">" if inb[0xC:0xE] == b'\xFE\xFF' else "<"

            endianness = {">": "Big", "<": "Little"}
            print("Endianness: " + endianness[bom])

            alignmentShift = inb[0xE]
            relocTbloff = struct.unpack(bom + "I", inb[0x18:0x1C])[0]
            relocTbl = bytearray(inb[relocTbloff:])

            #Loading reloc table header
            relocTblHeader = BlockHeader(bom)
            relocTblHeader.load(inb, relocTbloff)
            returnCode = relocTblHeader.isValid(b'_RLT')
            if returnCode:
                return returnCode

            # Loading reloc table
            relocTblClass = RelocTBL(bom)
            relocTblClass.load(inb, relocTbloff + 16, relocTblHeader.blockSize)

            # Searching for BNTX file
            for blockIndex, block in enumerate(relocTblClass.blocks):
                blockMagic = struct.unpack(bom + "4s", inb[block.pos: block.pos + 4])[0]
                if blockMagic == b'BNTX':
                    print('Found BNTX at ' + hex(block.pos))
                    print('Size : ' + str(block.size_))

                    # Extracting BNTX
                    bntxContent = inb[block.pos: block.pos + block.size_]
                    bntxFilename = 'extractedBlock' + str(blockIndex)
                    with open(os.path.join(RESOURCE_PATH, bntxFilename + '.bntx'), 'wb') as f:
                        f.write(bntxContent)
                        print('Wrote BNTX file in ' + os.path.join(RESOURCE_PATH, bntxFilename + '.bntx'))

                    textureTypes = ['Junk', 'Key', 'SeaShell', 'LifeUpgrade']
                    originalInb = copy(inb)
                    for textureType in textureTypes:
                        replaceTextureInFile(os.path.join(RESOURCE_PATH, bntxFilename + '.bntx'),
                                             os.path.join(RESOURCE_PATH, bntxFilename + '_updated.bntx'),
                                             'MI_dungeonTreasureBox_01_alb',
                                             os.path.join(
                                                 RESOURCE_PATH,
                                                 'textures',
                                                 'chest', 'MI_dungeonTreasureBox' + textureType + '_01_alb.dds'
                                             )
                                             )

                        # Test injection (Files need to be the exact same size for now. I don't handle filesize change)
                        with open(os.path.join(RESOURCE_PATH, bntxFilename + '_updated.bntx'), "rb") as injectF:
                            injectB = injectF.read()
                            inb = bytearray(originalInb)
                            size = os.path.getsize(os.path.join(RESOURCE_PATH, bntxFilename + '_updated.bntx'))
                            inb[block.pos: block.pos + size] = injectB
                            with open(os.path.join(RESOURCE_PATH, 'ObjTreasureBox' + textureType + '.bfres'), "wb") as out:
                                out.write(inb)

                    os.remove(os.path.join(RESOURCE_PATH, bntxFilename + '.bntx'))
                    os.remove(os.path.join(RESOURCE_PATH, bntxFilename + '_updated.bntx'))
        else:
            print("\nUnable to recognize the input file!")
            time.sleep(5)
            exit(1)


def replaceTextureInFile(bntxFileInput, bntxFileOutput, textureName, textureFile):
    editor = bntx_editor.BNTXEditor()
    editor.openFile(bntxFileInput)

    # Get Texture Index by Name
    foundIndex = -1
    for imageIndex, element in enumerate(editor.bntx.textures):
        if element.name == textureName:
            foundIndex = imageIndex
            break

    if foundIndex < 0:
        raise Exception(f'Texture {textureName} not found')

    # Inject it back to the BNTX File
    editor.replaceTexByIndex(textureFile, foundIndex)
    editor.saveAs(bntxFileOutput)

