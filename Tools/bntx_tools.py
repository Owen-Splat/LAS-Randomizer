from PIL import Image
import Tools.bntx_editor.bntx_editor as bntx_editor
import os
import quicktex.dds as quicktex_dds
import quicktex.s3tc.bc3 as bc3

from Tools import oead_tools
from randomizer_paths import RESOURCE_PATH
from io import BytesIO


# This method aims to create a custom BNTX archive based on the original one to add a custom title screen
def createRandomizerTitleScreenArchive(rom_path):
    reader = oead_tools.readSarc(f'{rom_path}/region_common/ui/StartUp.arc')
    editor = bntx_editor.BNTXEditor()
    editor.openFile(reader.get_file('timg/__Combined.bntx').data)

    texture_to_replace = 'Logo_00^f'
    logo_texs = [t for t in editor.bntx.textures if t.name == texture_to_replace]
    if logo_texs:
        texture_index = editor.bntx.textures.index(logo_texs[0])
    else:
        raise Exception(f'Texture {texture_to_replace} not found')

    # Extracting the texture as DDS
    dds_tex = BytesIO(editor.exportTexByIndex(texture_index))
    png_tex = BytesIO()
    new_png = BytesIO()
    new_dds = BytesIO()

    # Convert texture to PNG
    im = Image.open(dds_tex)
    im.save(png_tex, format="PNG")

    # Merge our PNG with the original one to create the new title screen
    background = Image.open(png_tex)
    foreground = Image.open(os.path.join(RESOURCE_PATH, 'randomizer.png'))
    background.paste(foreground, (0, 0), foreground)
    background.save(new_png, format="PNG")

    updated_logo = Image.open(new_png)

    # Convert back to DDS using QuickTex
    quicktex_dds.encode(updated_logo, bc3.BC3Encoder(18), 'DXT5').save(new_dds)

    # Inject it back to the BNTX File
    editor.replaceTexByIndex(new_dds, texture_index)
    return editor.save()
