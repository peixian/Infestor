import struct
import z3

#all bytes in the decrypted data need to XOR to 0x37, this is our target data
target = 0x37

#low and high counter positions
counterLow = 0
counterHigh = 0

#index positions for easier reference
POS_CONST0 = 0
POS_KEY0 = 1
POS_KEY2 = 2
POS_KEY4 = 3
POS_KEY6 = 4
POS_CONST2 = 5
POS_NONCE0 = 6
POS_NONCE2 = 7
POS_COUNTERLOW = 8
POS_COUNTERHIGH = 9
POS_CONST4 = 10
POS_KEY8 = 11
POS_KEY10 = 12
POS_KEY14 = 14
POS_CONST6 = 15

#constant values and positions
cVals = [ 30821, 25710, 11570, 25972 ] #constant petya matrix, derived from [ 0x7865, 0x646E, 0x2D32, 0x6574 ], from https://github.com/leo-stone/hack-petya/blob/master/main.go