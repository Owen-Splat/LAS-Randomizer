; This contains the patches that are absolutely required for the randomizer to work


; Allows the player to open the Color Dungeon even with companions
; This is done by changing "companion == 0" to "companion != 5"
; Since companion value 5 is not a thing, the check always returns True
.offset 0xc868d4
    ccmp w9, #0, #5, ne


; Make the Iron Ball Soldier spawn even if the player has GoldenLeaf[4]
; This is done by instead running the code that checks for the Actor Switch flag
; For the randomizer, the flag is set True when the item drops after defeating the soldier
.offset 0x6a62f8
    cbz w0, 0x6a6340


; Rewrite some unused code that normally removes SwordLv1 to instead remove Bottle[1]
; This is so that we can actively add/remove it from inventory to control if it shows in the FishingPond
.offset 0x7e1f6c
    adrp x8, 0x14e0000
    ldr x8, [x8, #0x368]
    ldr w9, [x8, #0xa8]
    and w9, w9, 0xFFFFBFFF
    str w9, [x8, #0xa8]
    b -0x19C


; Rewrite the unused FlowControl::CompareInt event to return 1 if the values are equal, 0 if not
; This allows us to check the index of items through the EventFlow system
; The main purpose of this will be for Keysanity to know which dungeon text to display
; This is also used to set a flag for the Fishing Bottle
.offset 0x8049d8
    mov w8, #0x1
.offset 0x8049dc
    csel w0, w8, wzr, eq
