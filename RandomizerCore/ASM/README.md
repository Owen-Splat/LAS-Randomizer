### Comments
lines starting with "; " are dev comments

lines starting with ";* " are patch titles that will show in the .pchtxt files

### Settings
to access a randomizer setting for a patch, the line must look like ";settings SETTING_NAME"

".settings !SETTING_NAME" also works for patches that require a setting to be off

### Data
asm that requires randomizer data needs the instruction to end with ";data VARIABLE_NAME"

it will replace the last register on that line

this data is compiled in the assemble.py preSetup function

right now, this is just for the randomized chest enemy

### Patches
patches are finished by blank lines or lines starting with ".offset"

settings based patches need a blank line afterwards in order for the condition to be reset

just reference the existing patches if you're confused by the format

### Credits
if you add a patch, please credit with [ username ]

patches without explicit credit can be used by anyone else, no credit needed
