#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Licensed under GNU GPLv3

import RandomizerCore.Tools.bntx_editor.bntx as BNTX
from io import BytesIO


class BNTXEditor:
    def __init__(self):
        super().__init__()
        self.bntx = BNTX.File()

    def openFile(self, data):
        returnCode = self.bntx.readBytes(data)
        if returnCode:
            return False

    def exportTexByIndex(self, index) -> bytes:
        return self.bntx.extract(index)

    def replaceTexByIndex(self, file, index):
        if not file:
            return False
        texture = self.bntx.textures[index]
        texture_ = self.bntx.replace(texture, texture.tileMode, False, False, False, True, file)
        if texture_:
            self.bntx.textures[index] = texture_

    def save(self):
        return self.bntx.save()

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
        if isinstance(textureFile, str):
            with open(textureFile, "rb") as textureFileInstance:
                self.replaceTexByIndex(textureFileInstance, foundIndex)
        elif isinstance(textureFile, BytesIO):
            self.replaceTexByIndex(textureFile, foundIndex)
        else:
            raise Exception("textureFile is an unknown type")

    def saveAs(self, file):
        if not file:
            return False

        with open(file, "wb") as out:
            out.write(self.bntx.save())