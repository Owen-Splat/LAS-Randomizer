; This contains the patches required to make miscellaneous, optional settings work


;* Read the egg path without Lens
; This is done by making Inventory.HasItem(44) always return True
;settings free-book
.offset 0x7e3004
mov w0, #1


;* Randomize the EnemyZolGreen inside chests
;settings randomize-enemies
.offset 0xca92c0
mov w9, x0 ;data CHEST_ENEMY


;* Make all forms of damage kill Link in 1 hit
;settings OHKO
.offset 0xd4c754 ; normal damage
sub w22, w8, #80
.offset 0xdb1f74 ; fall/drown damage
sub w8, w21, #80
.offset 0xd7c8c8 ; # trap damage
sub w20, w8, #80
.offset 0xd96950 ; blaino damage
sub w8, w23, #80


;* Beam slash with base sword
;settings lv1-beam
.offset 0xde1ba8
ldrb w9, [x8, #0xa8]


;* Rapid-fire Magic Rod
; This is done by changing the Magic Rod projectile instance limit from 3 to 16
;settings nice-rod
.offset 0xd51698
cmp x19, #16


;* Rapid-fire Bombs
; This is done by changing a boolean value to always be True
;settings nice-bombs
.offset 0xd52958
mov w8, #1
