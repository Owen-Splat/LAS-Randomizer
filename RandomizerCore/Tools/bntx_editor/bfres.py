#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import struct
from copy import copy

from RandomizerCore.Tools.bntx_editor.structs import (BFRESHeader, BlockHeader, RelocTBL)

class BfresTexture:
    def __init__(self, bfresFile):
        self.size = None
        self.pos = None
        self.bfresFile = bfresFile

    def load(self):
        for blockIndex, block in enumerate(self.bfresFile.relocTbl.blocks):
            blockMagic = struct.unpack(
                self.bfresFile.header.endianness + "4s",
                self.bfresFile.rawData[block.pos: block.pos + 4]
            )[0]

            if blockMagic == b'BNTX':
                self.pos = block.pos
                self.size = block.size_
                break


class File:
    def __init__(self):
        self.bfresTexture = None
        self.relocTbl = None
        self.relocTblHeader = None
        self.header = None
        self.rawData = None

    def readFromFile(self, fname):
        with open(fname, "rb") as inf:
            inb = inf.read()

        return self.load(inb, 0)

    def load(self, data, pos):
        self.header = BFRESHeader()
        returnCode = self.header.load(data, pos)
        if returnCode:
            raise Exception("A problem occured while loading the BFRES file header")

        pos = self.header.relocAddr
        self.relocTblHeader = BlockHeader(self.header.endianness)
        self.relocTblHeader.load(data, pos)
        returnCode = self.relocTblHeader.isValid(b'_RLT')
        if returnCode:
            raise Exception("A problem occured while loading the BFRES relocation table header")

        self.relocTbl = RelocTBL(self.header.endianness)
        self.relocTbl.load(data, pos + 16, self.relocTblHeader.blockSize)

        self.rawData = copy(data)

        self.bfresTexture = BfresTexture(self)
        self.bfresTexture.load()
        return 0

    def extractMainBNTX(self, outFile):
        if self.bfresTexture.pos is None:
            raise Exception("No BNTX File found in this BFRES file")

        # TODO Find out why block's size gives something bigger (there is a padding).
        bntxContent = self.rawData[self.bfresTexture.pos: self.bfresTexture.pos + self.bfresTexture.size]
        with open(outFile, 'wb') as f:
            f.write(bntxContent)

    def replaceMainBNTX(self, inputFile):
        if self.bfresTexture.pos is None:
            raise Exception("No BNTX File to replace")

        # TODO / WARNING This is a byte-to-byte replacement. This might not work in every case. If size differs
        # Some parts might be broken
        with open(inputFile, "rb") as injectF:
            injectB = injectF.read()
            inb = bytearray(self.rawData)
            size = os.path.getsize(inputFile)
            inb[self.bfresTexture.pos: self.bfresTexture.pos + size] = injectB
            self.rawData = inb


    def saveAs(self, outFile):
        with open(outFile, "wb") as out:
            out.write(self.rawData)