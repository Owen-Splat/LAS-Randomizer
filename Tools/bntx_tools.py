from PIL import Image
import Tools.bntx_editor.bntx_editor as bntx_editor
import os
import quicktex.dds as quicktex_dds
import quicktex.s3tc.bc3 as bc3

from Tools import oead_tools
from randomizer_paths import RESOURCE_PATH


# This method aims to create a custom BNTX archive based on the original one to add a custom title screen
def createRandomizerTitleScreenArchive(rom_path):
    reader = oead_tools.readSarc(f'{rom_path}/region_common/ui/StartUp.arc')
    with open(os.path.join(RESOURCE_PATH, '__Combined-original.bntx'), 'wb') as nf:
        image_archive = reader.get_file('timg/__Combined.bntx')
        nf.write(image_archive.data)

    textureToReplace = 'Logo_00^f'

    editor = bntx_editor.BNTXEditor()
    editor.openFile(os.path.join(RESOURCE_PATH, '__Combined-original.bntx'))

    # Get Texture Index by Name
    foundIndex = -1
    for imageIndex, element in enumerate(editor.bntx.textures):
        if element.name == textureToReplace:
            foundIndex = imageIndex
            break

    if foundIndex < 0:
        raise Exception(f'Texture {textureToReplace} not found')

    # Extracting the texture as DDS
    editor.exportTexByIndex(foundIndex)

    # Converting in PNG
    im = Image.open(os.path.join(RESOURCE_PATH, f'{textureToReplace}.dds'))
    im.save(os.path.join(RESOURCE_PATH, f'{textureToReplace}.png'), format="PNG")

    # Merge our PNG with the original one to create the new title screen
    background = Image.open(os.path.join(RESOURCE_PATH, f'{textureToReplace}.png'))
    foreground = Image.open(os.path.join(RESOURCE_PATH, 'randomizer.png'))
    background.paste(foreground, (0, 0), foreground)
    background.save(os.path.join(RESOURCE_PATH, f'{textureToReplace}-updated.png'))

    updatedLogo = Image.open(os.path.join(RESOURCE_PATH, f'{textureToReplace}-updated.png'))

    # Convert back to DDS using QuickTex
    quicktex_dds.encode(updatedLogo, bc3.BC3Encoder(18), 'DXT5').save(os.path.join(RESOURCE_PATH, f'{textureToReplace}-updated.dds'))

    # Inject it back to the BNTX File
    editor.replaceTexByIndex(os.path.join(RESOURCE_PATH, f'{textureToReplace}-updated.dds'), foundIndex)
    editor.saveAs(os.path.join(RESOURCE_PATH, '__Combined.bntx'))

    #Cleanup
    os.remove(os.path.join(RESOURCE_PATH, '__Combined-original.bntx')) # Original BNTX file
    os.remove(os.path.join(RESOURCE_PATH, f'{textureToReplace}.dds'))  # Original DDS Texture
    os.remove(os.path.join(RESOURCE_PATH, f'{textureToReplace}.png'))  # PNG-converted Texture
    os.remove(os.path.join(RESOURCE_PATH, f'{textureToReplace}-updated.png'))  # Merged PNG texture
    os.remove(os.path.join(RESOURCE_PATH, f'{textureToReplace}-updated.dds'))  # Converted merged DDS texture