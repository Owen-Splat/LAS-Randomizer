; This contains the patches related to the shop


;* Always allow stealing
; Ignores sword check and checks shopkeeper direction
;settings stealing
.offset 0xa4a8f0
b 0xa4a910


;* Never allow stealing
; Ignores sword check and prevents the player from stealing
;settings !stealing
.offset 0xa4a8f0
b 0xa4a8f4
