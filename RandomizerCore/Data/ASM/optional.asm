; This contains the patches required to make miscellaneous, optional settings work


; Makes Inventory.HasItem(44) always return True
; This lets the player read the egg path without having the Lens
.settings free-book
    .offset 0x7e3004
        mov w0, #1


; Randomize the green zol chest trap into another enemy
.settings randomize-enemies
    .offset 0xca92c0
        mov w9, #.global CHEST_ENEMY


; Make all forms of damage substract 80 health so Link always die in 1 hit
.settings OHKO
    .offset 0xd4c754 ; normal damage
        sub w22, w8, #80
    .offset 0xdb1f74 ; fall/drown damage
        sub w8, w21, #80
    .offset 0xd7c8c8 ; # trap damage
        sub w20, w8, #80
    .offset 0xd96950 ; blaino damage
        sub w8, w23, #80


; Beam slash with either sword
.settings lv1-beam
    .offset 0xde1ba8
        ldrb w9, [x8, #0xa8]


; Change the Magic Rod projectile instance limit from 3 to 16
.settings nice-rod
    .offset 0xd51698
        cmp x19, #16