; This contains patches required for keysanity to work


; Allows using the item index to determine the dungeon the item goes to
; Replaces the variable holding the current level value with the item index
; This makes the dungeon items go to the dungeon that corresponds to the item index
; NOT WRITTEN YET BECAUSE IT NEEDS TO ONLY DO THIS IF YOU'RE NOT IN A DAMPE DUNGEON


;* Allows dungeon items to be obtained outside of dungeons
; For dungeon items, compare the item count instead of current level/item index
; This lets it work outside of dungeons as well as supporting item indexes of -1
;settings keys
.offset 0x8d0cf4 ; SmallKey
cmp w8, #-1
.offset 0x8d0cf8
b.eq 0x8d0d00
mov w8, #8
.offset 0x8d0e58 ; NightmareKey
cmp w8, #-1
.offset 0x8d0e5c
b.eq 0x8d0e64
mov w8, #8

;settings keys+mcb
.offset 0x8d0e04 ; Compass
cmp w8, #-1
.offset 0x8d0e08
b.eq 0x8d0e10
mov w8, #8
.offset 0x8d1278 ; DungeonMap
cmp w8, #-1
.offset 0x8d127c
b.eq 0x8d1284
mov w8, #8
.offset 0x8d1478 ; StoneBeak
cmp w8, #-1
.offset 0x8d147c
b.eq 0x8d1484
mov w8, #8
