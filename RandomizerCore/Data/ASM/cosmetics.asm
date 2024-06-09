; This contains patches that effect the visuals of the game


; Makes NPCs hold the proper item model before giving it to the player
; This is done by changing the itemID of the model to a new Items.gsheet entry with the proper model
.offset 0x9fa0f0
    mov w4, #200 ; bay-fisherman
.offset 0xa40374
    mov w3, #201 ; syrup
.offset 0xa534a4
    mov w8, #202 ; walrus


; Makes songs, tunics, and capacity upgrades show the correct item model by making them go to the default case
; Default case means it will use its own npcKey in Items.gsheet rather than a different item's npcKey
.offset 0xd798c4
    b +0x134
.offset 0xd79814
    b +0x1e4
.offset 0xd79804
    b +0x1f4


; Changes the string "PFXTiltShiftParam" that is used in postprocess.bfsha shader file
; This new string can be anything that isn't found in the shader
; As a result, the TiltShift is not applied anywhere
.settings blur-removal
    .offset 0x16cbd73
        .string NoTiltShift
