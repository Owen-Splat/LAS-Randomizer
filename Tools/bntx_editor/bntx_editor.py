#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Licensed under GNU GPLv3

import os.path
import Tools.bntx_editor.bntx as BNTX


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