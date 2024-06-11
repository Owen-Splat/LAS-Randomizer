lines starting with "; " are comments
lines starting with ";* " are patch titles that will show in the .pchtxt files

indents are not needed and are just for readability

to access a randomizer setting for a patch, the line must look like ".settings SETTING_NAME"
".settings !SETTING_NAME" also works for patches that require a setting to be off

patches are finished by blank lines or lines starting with ".offset"
settings based patches need a blank line afterwards in order for the condition to be reset

asm that requires a variable needs to contain ".global VARIABLE_NAME"
right now, this is just for the randomized chest enemy
this data is compiled in the assemble.py preSetup function

just reference the existing patches if you're confused by the format

if you add a patch, please credit with [ username ]
patches without explicit credit are assumed to be written by me, and can be used by anyone else, without giving credit
