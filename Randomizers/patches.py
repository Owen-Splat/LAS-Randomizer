from Tools.patcher import Patcher


BASE_BUILD_ID = 'AE16F71E002AF8CB059A9A74C4D90F34BA984892' # version 1.0.0

UPD_BUILD_ID = '909E904AF78AC1B8DEEFE97AB2CCDB51968f0EC7' # version 1.0.1


def someExamplePatch(patcher):
    # example of address and instruction, not a real patch
    # IMPORTANT NOTE: addresses most likely change with version, I am solely focusing on the update currently
    # the patcher class handles the 0x100 nso (the main executable) header offset so we can just use the address offset in ghidra
    patcher.addPatch(0x1d3f, f'mov w0 #0x50')


def main():
    # initialize the patcher object and hand off individual patches to separate functions to make it easier to track & read
    patcher = Patcher()
    someExamplePatch(patcher)

    # create and write in binary to an ips file with the build id of version as the name
    with open('BUILD_ID.ips', 'wb') as f:
        f.write(patcher.generatePatch())
