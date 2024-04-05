# LAS-Randomizer
A randomizer for The Legend of Zelda: Link's Awakening remake.

You can download the randomizer here: https://github.com/Owen-Splat/LAS-Randomizer/releases/latest

## Information
This randomizes all the items in the game so that every playthrough is unique. It also aims to add quality of life changes, such as skipping cutscenes, or adding options that make the game more open-world.

**Logic**:
- Basic: No glitches or advanced tricks, although 2 tile jumps are included. Recommended for beginners.
- Advanced: Skews and bomb arrows will be added to logic.
- Glitched: Adds some glitches to logic that will not result in being softlocked.
- Hell: Adds more glitches to logic that can result in softlocks.
- None: Throws all logic out the window. Seeds will likely be unbeatable.

Please note that while most things are functional, there is a possibility of the logic resulting in softlocks. This will be especially true with the glitched logics. If this does happen, dying and selecting the Save + Quit option will respawn you back at Marin's house.

## How to play:
In order to play the randomizer, you must have the RomFS of the game extracted and on the device you're running this program from. This can be extracted through your choice of emulator, or with nxdumptool on a homebrewed Switch console.

The number of files will differ depending on settings, so clear out any old files first.

Switch: Set the output platform to `Console`. Copy and paste the `Atmosphere` folder from the output to the root of your SD card. I'd recommend to use a file transfer homebrew app to avoid needing to take the SD card out and relaunch CFW each time.

Emulator: Set the output platfrom to `Emulator` and set the output path to the emulator's mod directory for Link's Awakening. After creating a seed, simply just enable it and enjoy playing! You **MUST** play on v1.0.0 otherwise the exefs patches will not work on emulator.

## Discord Server
Join the Discord server to talk about the randomizer, ask questions, or even set up races!  
The Discord also contains some more detailed information about the current state of the randomizer, including known issues and what is shuffled.

https://discord.com/invite/rfBSCUfzj8

## Credits:
- Glan: Created the original early builds of the randomizer found here: https://github.com/la-switch/LAS-Randomizer
- j_im: Created the original tracker for the randomizer
- Br00ty: Maintains and updates the tracker for newer randomizer versions
- ProfessorLaw: Additional programming (Randomizer Title Screen)

### Special Thanks:
- To everyone who has reported bugs or given feedback and suggestions. This randomizer would not be where it is today without our community.

## Running from source:
**NOTE**: This is for advanced users or those helping with the development of this randomizer.
If you want to run from source, then you need to clone this repository and make sure you have Python 3.8+ installed

Open the folder in a command prompt and install dependencies by running:  
`py -3.8 -m pip install -r requirements.txt` (on Windows)  
`python3 -m pip install -r requirements.txt` (on Mac)  
`python3 -m pip install $(cat requirements.txt) --user` (on Linux)

Then run the randomizer with:  
`py -3.8 randomizer.py` (on Windows)  
`python3 randomizer.py` (on Mac)  
`python3 randomizer.py` (on Linux)  

If you are using a higher version of Python, change the commands to include your version instead

Once you have installed all the requirements, there is an included **build.bat** file. Run that (you can just enter `build` in the terminal) and it will automatically enter the commands to create a build. Once again, if you are using a different version of Python, you will need to edit this file to match your version
