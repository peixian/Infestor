import struct
import z3

# Input values to the Salsa round primitive, taken from https://cr.yp.to/salsa20.html
salsa_steps = [
  (4,0,12,7),
  (8,4,0,9),
  (12,8,4,13),
  (0,12,8,18),
  
  (9,5,1,7),
  (13,9,5,9),
  (1,13,9,13),
  (5,1,13,18),
  
  (14,10,6,7),
  (2,14,10,9),
  (6,2,14,13),
  (10,6,2,18),
  
  (3,15,11,7),
  (7,3,15,9),
  (11,7,3,13),
  (15,11,7,18),
  
  (1,0,3,7),
  (2,1,0,9),
  (3,2,1,13),
  (0,3,2,18),
  
  (6,5,4,7),
  (7,6,5,9),
  (4,7,6,13),
  (5,4,7,18),
  
  (11,10,9,7),
  (8,11,10,9),
  (9,8,11,13),
  (10,9,8,18),
  
  (12,15,14,7),
  (13,12,15,9),
  (14,13,12,13),
  (15,14,13,18),
]

#byte range for iterations
BYTERANGE = xrange(8)

#all bytes in the decrypted data need to XOR to 0x37, this is our target data (since this is the encrypyted sector)
TARGET = 0x37

#low and high counter positions
STREAMLOW = 0
STREAMHIGH = 0

#index positions for easier reference
#16 word state - 8 words of key, 2 words of stream position, 2 words of nonce, and 4 fixed words
#[Const, Key, Key, Key, key, Const, Nonce, Nonce, StreamPos, StreamPos, Const, Key, Key, Key, Key, Const]
P_CONST0 = 0
P_KEY0 = 1
P_KEY2 = 2
P_KEY4 = 3
P_KEY6 = 4
P_CONST2 = 5
P_NONCE0 = 6
P_NONCE2 = 7
P_STREAMLOW = 8
P_STREAMHIGH = 9
P_CONST4 = 10
P_KEY8 = 11
P_KEY10 = 12
P_KEY12 = 13
P_KEY14 = 14
P_CONST6 = 15

#constant positions and values 
c_pos = [ P_CONST0, P_CONST2, P_CONST4, P_CONST6 ] #constant positions, need to shuffle this into steps
c_vals = [ 30821, 25710, 11570, 25972 ] #constant petya matrix, derived from [ 0x7865, 0x646E, 0x2D32, 0x6574 ], from https://github.com/leo-stone/hack-petya/blob/master/main.go

#key position array
k_pos = [ P_KEY0, P_KEY2, P_KEY4, P_KEY6, P_KEY8, P_KEY10, P_KEY12, P_KEY14 ]
#key bytes and key words - words start with 0 - see http://www.tgsoft.it/english/news_archivio_eng.asp?id=712
k_bytes = [ z3.BitVec("kb{}".format(i), 8) for i in BYTERANGE]
k_words = [ 0 ]*8

#iterate through the range, extending the key_bytes and create
for i in BYTERANGE:
    low = z3.ZeroExt(8, k_bytes[i]) + 0x7A #key expansion, see paper/petyaCode/key_expand.c
    hi = z3.ZeroExt(8, k_bytes[i]) << 9
    print(hi)
    print(low)
    k_words[i] = hi | low

print(k_words)

#create a z3 solver, using SMT-LIB logic: http://smtlib.cs.uiowa.edu/
#this one uses quantifier-free expressinos, and the entire family of bit-vector sorts and all the functions defined in the Fix_Size_BitVectors theory: https://smtlib.github.io/jSMTLIB/SMTLIBTutorial.pdf
solver = z3.SolverFor("QF_AUFBV")      
        
def salsa(arr):
    """10 iterations of the salsa16 round"""
    #only shuffle this 10 rounds because it's the `s20_rev_littleendian` function doesn't shift by any amount besides 8, see samples/badsalsa.c
    for i in xrange(10):
        salsa_iteration(arr)
    
def salsa_iteration(arr):
    """One iteration of the salsa16 round"""
    for salsa_round in salsa_steps:
        step(arr, *salsa_round) 

def step(arr, out_pos, in_left, in_right, rotate_amount):
    """steps through the salsa16 primitive, follows the add-rotate-xor operation: https://en.wikipedia.org/wiki/Block_cipher#Operations"""
    total = z3.ZeroExt(16, arr[in_left] + arr[in_right]) #add 
    rot = z3.RotateLeft(total, rotate_amount) #rotate
    arr[out_pos] ^= z3.Extract(15, 0, rot) #xor

def read_init(sourceName = "src.txt", nonceName = "nonce.txt"):
    """Reads hexadecimal values of the source and nonce data, same as: https://petya-pay-no-ransom-mirror1.herokuapp.com/"""
    #opens the files in binary mode, and reads them into a struct
    #extracts nonce words
    with open(nonceName, "rb") as f_nonce:
        nonce = f_nonce.read().replace(" ", "")
        print("\nnonce: {}\n".format(nonce))
        nonce = nonce.decode("hex")

        #4 unsigned shorts
        (n0, n2, n4, n6) = struct.unpack("HHHH", nonce)
        #make the intial array
        init = make_salsa_matrix(n0, n4, STREAMLOW, STREAMHIGH)
        init_clone = [i for i in init]
    
    #extracts ciphertext words
    with open(sourceName, "rb") as f_src:
        src = "".join(line.strip() for line in f_src).replace(" ", "")
        print("src: {}".format(src))
        src = src.decode("hex")
        #creates a bytearray of the source, then constructs the words from it 
        srcbytes = bytearray(src)
        srcwords = [ None ]* len(init)
        for i in xrange(len(init)):
            #bitwise xor vs the target, shift it left to find the max bound
            low = (srcbytes[4*i] ^ TARGET)
            high = (srcbytes[4*i+1] ^ TARGET) << 8 #shift by 8 because bad salsa always uses 8 bit shift (check line 44-47 of `samples/badsalsa.c`)
            #source words is the ciphertext
            srcwords[i] = z3.BitVecVal(low | high, 16) #hash only has 16 bit words, not 32 bit (see `samples/badsalsa.c`)
            
    return (init, init_clone, srcwords)
    
def make_salsa_matrix(nonce0, nonce2, streamLow, streamHigh):
    """Creates the salsa matrix with the nonce/low counter/high counter"""
    matrix = [ 0 ] * 16
    #4 constant values
    for val in xrange(len(c_vals)):
        matrix[c_pos[val]] = z3.BitVecVal(c_vals[val], 16)
    #8 key values
    for key in xrange(len(k_words)):
        matrix[k_pos[key]] = k_words[key]
    #2 nonces, 2 streamPos
    matrix[P_NONCE0] = z3.BitVecVal(nonce0, 16)
    matrix[P_NONCE2] = z3.BitVecVal(nonce2, 16)
    matrix[P_STREAMLOW] = z3.BitVecVal(streamLow, 16)
    matrix[P_STREAMHIGH] = z3.BitVecVal(streamHigh, 16)
    
    return matrix    
    
init, init_clone, srcwords = read_init()  

#constraints on the keys
for k in k_bytes:
    #adds the constraints, cannot be any of these, see https://github.com/leo-stone/hack-petya/blob/master/main.go
    solver.add(z3.Or(z3.And(k >= 97, k <= 120), z3.And(k >= 41, k <= 88), z3.And(k >= 49, k <= 57)))
    solver.add(k != 79)
    solver.add(k != 108)
    solver.add(k != 73)
    
#shuffle salsa
salsa(init)

#constraints on output
for i in xrange(len(init)):
    #endWord is a combination of the shifted array + inital array, see the Salsa20 core definition: https://cr.yp.to/salsa20.html
    endWord = init[i] + init_clone[i]
    #the end word should match the source word
    solver.add(endWord == srcwords[i])

#check for finish: https://en.wikipedia.org/wiki/Boolean_satisfiability_problem
if solver.check() == z3.sat:
    m = solver.model()
    outbytes = map(lambda x: chr(m[x].as_long()), k_bytes)
    out = "x".join(outbytes)
    out = out if len(out) == 16 else out + "x"
    print("\npassword is: \n{}\n".format(out))
else:
    print("Problem is bool-unsat-able!")