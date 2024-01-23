#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Licensed under GNU GPLv3

import os.path
import Tools.bntx_editor.bntx as BNTX


class BNTXEditor:
    def __init__(self):
        super().__init__()
        self.BFRESPath = None
        self.bntx = BNTX.File()

    def openFile(self, file):
        if not file:
            return False

        self.BFRESPath = os.path.dirname(os.path.abspath(file))
        returnCode = self.bntx.readFromFile(file)
        if returnCode:
            return False

    def exportTexByIndex(self, index):
        self.bntx.extract(index, self.BFRESPath, 0)

    def replaceTexByIndex(self, file, index):
        if not file:
            return False
        texture = self.bntx.textures[index]
        texture_ = self.bntx.replace(texture, texture.tileMode, False, False, False, True, file)
        if texture_:
            self.bntx.textures[index] = texture_

    def replaceTextureByName(self, textureName, textureFile):
        # Get Texture Index by Name
        foundIndex = -1
        for imageIndex, element in enumerate(self.bntx.textures):
            if element.name == textureName:
                foundIndex = imageIndex
                break

        if foundIndex < 0:
            raise Exception(f'Texture {textureName} not found')

        # Inject it back to the BNTX File
        self.replaceTexByIndex(textureFile, foundIndex)

    def saveAs(self, file):
        if not file:
            return False

        with open(file, "wb") as out:
            out.write(self.bntx.save())