# LAS-Randomizer
A randomizer for The Legend of Zelda: Link's Awakening remake. Currently still very early in development.

Based on the original randomizer [here](https://github.com/la-switch/LAS-Randomizer)

This release version allows for shuffling chests, NPC gifts including the Trading Quest, miscellaneous standing items, minigames, boss drops, instruments, and standing heart pieces. More work will come soon.

Several extra options, including Trapsanity, Shuffled Dungeons, Randomized Music, Randomized Enemies and more! Don't like checking a specific location? You can toggle it to always be junk! Want to start with a specific item? Go ahead!

Please note that while most things are functional, there is a definite possibility of the logic resulting in softlocks. This will be especially true with the glitched logics. If this does happen, dying and selecting the Save + Quit option will respawn you back at Marin's house.

**Logic**:
- Basic: No glitches or advanced tricks, although 2 tile jumps are included. Recommended for beginners.
- Advanced: Skews and bomb arrows will be added to logic.
- Glitched: Adds some glitches to logic that will not result in being softlocked.
- Hell: Adds more glitches to logic that can result in softlocks.
- None: Throws all logic out the window. Seeds will likely be unbeatable.

**NOTE**: The randomizer may temporarily get stuck while placing items and will attempt to fix it. If this happens, just wait it out. If it's taking too long, just cancel and try another seed. Very rarely will it actually be fully stuck.

In order to run the randomizer, you must have the RomFS of the game extracted and on the device you're running this program from. This can be extracted through your choice of emulator, or with nxdumptool on a homebrewed Switch console. The RomFS is the component of the game package with all of the data files (i.e. non-executable files).

Join the [Discord](https://discord.com/invite/rfBSCUfzj8) to talk about the randomizer or ask any questions you have!  
The Discord also contains some more detailed information about the current state of the randomizer, including known issues and what is shuffled.

## How to run:

Either just download the latest release, which will automatically be updated to include the latest build, or you can also run from source.
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

## How to build:

Once you have installed all the requirements, there is an included **build.bat** file. Run that (you can just enter `build` in the terminal) and it will automatically enter the commands to create a build. Once again, if you are using a different version of Python, you will need to edit this file to match your version

## How to play:

To play the randomizer, you will either need a homebrewed Switch console or a Nintendo Switch emulator.

The randomizer does not provide a second copy of the game to use, but rather makes use of the LayeredFS system for applying game mods. The simple way to explain this system is that we will provide a secondary RomFS which is external to the game's internal RomFS, and will force the game to use any corresponding external file instead of the internal one, provided an external one exists. This functionality is simple to set up.

(See also: [Switch game modding](https://nh-server.github.io/switch-guide/extras/game_modding/))

The number of files will differ depending on settings, so clear out any old files first.

Switch: Copy and paste the `Atmosphere` folder from the output to the root of your SD card. I'd recommend to use a file transfer homebrew app to avoid needing to take the SD card out and relaunch CFW each time.

Emulator: Set the output platfrom to emulator and set the output path to the emulator's mod directory for Link's Awakening. After creating a seed, simply just enable it and enjoy playing!

Applying this mod will not in any way affect your save data, so don't delete anything you don't want deleted. If you want to go back to the original game after, either manually clear the files out, or launch the game holding L. Keep in mind that exefs patches are still applied even when holding L. Because of this, the SimpleModManager homebrew app is a wonderful solution. You can simply toggle on/off individual mods.

### Known Issues:
- Dampe lacks logic for instrument shuffle
- Small key drops are still technically small key objects and will trigger the compass ringtone regardless of what they are
- While Trading Quest items work, they will not be displayed in the inventory
- Enemy Randomization is a very early work in progress. No logic, and needed kills are left vanilla

### Credits:
- Glan: Created the original early builds of the randomizer
- Br00ty: Maintains maptracker for newer rando versions
- EDL666: Bug reporting, feedback, suggestions

### Special Thanks:
- To everyone who has played this randomizer: Seeing people enjoy themselves playing this makes the time I've spent working on this feel worth it :)
