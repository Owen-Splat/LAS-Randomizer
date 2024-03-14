from PIL import Image
import Tools.bntx_editor.bntx_editor as bntx_editor
import os, struct
import quicktex.dds as quicktex_dds
import quicktex.s3tc.bc3 as bc3

from Tools import oead_tools
from RandomizerCore.Paths.randomizer_paths import RESOURCE_PATH
from io import BytesIO


# This method aims to create a custom BNTX archive based on the original one to add a custom title screen
def createRandomizerTitleScreenArchive(rom_path):
    reader = oead_tools.readSarc(f'{rom_path}/region_common/ui/StartUp.arc')
    editor = bntx_editor.BNTXEditor()
    editor.openFile(reader.get_file('timg/__Combined.bntx').data.tobytes())

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
    png_tex.seek(0)

    # Merge our PNG with the original one to create the new title screen
    background = Image.open(png_tex)
    foreground = Image.open(os.path.join(RESOURCE_PATH, 'randomizer.png'))
    background.paste(foreground, (0, 0), foreground)
    background.save(new_png, format="PNG")
    new_png.seek(0)

    updated_logo = Image.open(new_png)

    # Convert back to DDS using QuickTex
    save(quicktex_dds.encode(updated_logo, bc3.BC3Encoder(18), 'DXT5'), new_dds)
    new_dds.seek(0)

    # Inject it back to the BNTX File
    editor.replaceTexByIndex(new_dds, texture_index)
    return editor.save()


def save(dds_file, new_dds: BytesIO):
    """rewrite of quicktex DDSFile save function to work with BytesIO"""

    new_dds.write(b'DDS ')

    # WRITE HEADER
    new_dds.write(
        struct.pack(
            '<7I44x',
            124,
            int(dds_file.flags),
            dds_file.size[1],
            dds_file.size[0],
            dds_file.pitch,
            dds_file.depth,
            dds_file.mipmap_count,
        )
    )
    new_dds.write(
        struct.pack(
            '<2I4s5I',
            32,
            int(dds_file.pf_flags),
            bytes(dds_file.four_cc, 'ascii'),
            dds_file.pixel_size,
            *dds_file.pixel_bitmasks,
        )
    )
    new_dds.write(struct.pack('<4I4x', *dds_file.caps))

    assert new_dds.tell() == 128, 'error writing file: incorrect header size'

    for texture in dds_file.textures:
        new_dds.write(texture)
