# LAS-Randomizer
A randomizer for The Legend of Zelda: Link's Awakening remake. Currently still very early in development.

This release version allows for shuffling chests, NPC gifts including the Trading Quest, miscellaneous standing items, boss drops, instruments, and heart pieces, with the sunken ones left vanilla due to issues with them. More work will come soon.

Also introducing Zapsanity and Blupsanity!

Please note that while most things are functional, there is a definite possibility of the logic resulting in softlocks. This will be especially true with the glitched logic. It is recommended to primarily play the basic logic and make backup saves before going into an area that you might not be able to exit (e.g. going into Angler Tunnel without the flippers or the feather and neither are there).

**NOTE**: There is a known issue with some seeds, rarely, getting stuck during generation. If this happens, just try again with a different seed. It should take in the vicinity of 10-20 seconds to generate, so much longer than that means it's probably stuck.

In order to run the randomizer, you must have the RomFS of the game extracted and on the device you're running this program from. This can be extracted through tools like [Hactool](https://github.com/SciresM/hactool). The RomFS is the component of the game package with all of the data files (i.e. non-executable files).

Join the [Discord](https://discord.com/invite/rfBSCUfzj8) to talk about the randomizer or ask any questions you have!  
The Discord also contains some more detailed information about the current state of the randomizer, including known issues and what is shuffled.

## How to run:

Either just download the latest release, which will automatically be updated to include the latest build, or you can also run from source.
If you want to run from source, then you need to clone this repository and make sure you have Python 3.9+ installed

Open the folder in a command prompt and install dependencies by running:  
`py -3.9 -m pip install -r requirements.txt` (on Windows)  
`python3 -m pip install -r requirements.txt` (on Mac)  
`python3 -m pip install $(cat requirements.txt) --user` (on Linux)

Then run the randomizer with:  
`py -3.9 main_window.py` (on Windows)  
`python3 main_window.py` (on Mac)  
`python3 main_window.py` (on Linux)  

## How to play:

To play the randomizer, you will need a homebrewed Switch console.

The randomizer does not provide a second copy of the game to use, but rather makes use of the LayeredFS system for applying game mods. The simple way to explain this system is that we will provide a secondary RomFS which is external to the game's internal RomFS, and will force the game to use any corresponding external file instead of the internal one, provided an external one exists. This functionality is simple to set up.

(See also: [Switch game modding](https://nh-server.github.io/switch-guide/extras/game_modding/))

On your SD card for your homebrew setup, navigate to the `Atmosphere/contents` folder and create a new directory named `01006BB00C6F0000`. Copy and paste the `RomFS` folder from the randomizer output into this new folder. That is, the folder structure here should look like `Atmosphere/contents/01006BB00C6F0000/RomFs/...`. After this, relaunch CFW and simply start up Link's Awakening to play the randomizer!

Applying this mod will not in any way affect your save data, so don't delete anything you don't want deleted. If you want to go back to the original game after, either manually clear the files out, or you can launch the game holding L

### Known Issues:
- Seeds can sometimes take a very long time to generate. If it's taking too long you can cancel it and try another seed
- The existence of the fishing bottle depends on whether you have the 2nd bottle in your inventory
- Small key drops, despite giving different items, are still technically speaking small key objects and will trigger the compass ringtone regardless of what they are
- Getting a capacity upgrade will display the item with no text
- Choosing Shuffled Bombs sets bomb drops to 0. This will not change even after finding your bombs until I figure out how to change it
- Zap traps in Seashell Mansion gives a green rupee for some reason
- Dampe is very broken currently, would recommend to leave off until fixed
- While Trading Quest items work, they will not be displayed in the inventory
