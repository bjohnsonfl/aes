import logging

logger = logging.getLogger(__name__)

# AES128 Constants
Nr = 10
Nb = 4
Nk = 4

s_box = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76], 
         [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0], 
         [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15], 
         [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75], 
         [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84], 
         [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf], 
         [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8], 
         [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2], 
         [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73], 
         [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb], 
         [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79], 
         [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08], 
         [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a], 
         [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e], 
         [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf], 
         [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]

def print_state(state):
    for row in state:
        hex_row = [hex(x) for x in row]  
        logger.debug(hex_row)

def print_round_key(w):
    logger.debug("Round_key")
    matrix = [ [hex((w[i] >> (24 - 8*j)) & 0xFF) for i in range(4)] for j in range(4) ]
    [logger.debug([matrix[i][j] for j in range(4)]) for i in range(4)]
 
def SubBytes(state):
    for i in range(4):
        for j in range(4):
            row = (state[i][j] >> 4) & 0x0F
            col = state[i][j] & 0x0F
            state[i][j] = s_box[row][col]
    logger.debug("SubBytes")
    print_state(state)
    return state
    
    
def ShiftRows(state):
    state_shift = [row[:] for row in state]
    # S(r,c)' =S(r,(c+shift(r,Nb))mod Nb) for0<r<4 and 0≤c<Nb, (5.3) 
    # shift(1,4)=1; shift(2,4)=2; shift(3,4)=3. (5.4)
    # the row is the same by how much you rotate
    for r in range(4):
        for c in range(4):
            state_shift[r][c] = state[r][(c + r) % Nb]
    state = state_shift
    logger.debug("ShiftRows")
    print_state(state)
    return state

def MixColumns(state):
    # S(0,c)′ = ({02} * S(0,c) ) ^ ({03}* S(1,c)) ^ S(2,c) ^ S(3,c) 
    # S(1,c)′ = S(0,c) ^ ({02} * S(1,c)) ^ ({03} * S(2,c) )^ S(3,c) 
    # S(2,c)′ = S(0,c) ^ S(1,C) ^ ({02} * S(2,C) ) ^ ({03} * S(3,c))
    # S(3,c)′ = ({03} * S(0,c) ) ^ S(1,c) ^ S(2,c) ^ ({02} * S(3,c))
    # mult(0x57,0x13)
    state_mix = [row[:] for row in state]
    
    for c in range(4):
        state_mix[0][c] = mult(0x02, state[0][c]) ^ mult(0x03, state[1][c]) ^ state[2][c] ^ state[3][c]
        state_mix[1][c] = state[0][c] ^ mult(0x02, state[1][c]) ^ mult(0x03, state[2][c]) ^ state[3][c]
        state_mix[2][c] = state[0][c] ^ state[1][c] ^ mult(0x02, state[2][c]) ^ mult(0x03, state[3][c])
        state_mix[3][c] = mult(0x03, state[0][c]) ^ state[1][c] ^ state[2][c] ^ mult(0x02, state[3][c])
    state = state_mix
    logger.debug("MixColumns")
    print_state(state)
    return state

def mult(a, b):
    res = 0
    idx = 0
    xtimes_lut = [a]
    tmp = a
    for i in range(8):
        tmp = xtimes(tmp)
        xtimes_lut.append(tmp)

    for i in range(8):
        idx = 1 << i
        if idx & b:
            res ^= xtimes_lut[i]
    return res

def xtimes(a):
    tmp = (a & 0xFF) << 1
    if tmp & 0x100:
        tmp = (tmp ^ 0x11b) & 0xff
    # logger.debug(f'a: {hex(a)} out: {hex(tmp)}')
    return tmp

def AddRoundKey(state, w):
    #logger.debug(w)
    print_round_key(w)
    for i in range(4):
        #logger.debug(hex(w[i]))
        for j in range(Nb):
            #logger.debug(hex((w[i] >> (24 - 8*j)) & 0xFF))
            w_byte = (w[i] >> (24 - 8*j)) & 0xFF
            state[j][i] ^= w_byte
    logger.debug("AddRoundKey")
    print_state(state)
    return state

# Takes in a word of 4 bytes
def RotWord(word):
    # [a0 a1 a2 a3] -> [a1 a2 a3 a0]
    word_hex = word.to_bytes(4,'big')
    rotated_hex = word_hex[1:] + word_hex[:1]
    return int.from_bytes(rotated_hex, 'big') 

# Apply S-Box sub to each byte in a word
def SubWord(word):
    word_hex = word.to_bytes(4,'big')
    subword_hex = []
    for i in range(4):
        row = (word_hex[i] >> 4) & 0x0F
        col = word_hex[i] & 0x0F
        subword_hex.append(s_box[row][col])
    return int.from_bytes(subword_hex, 'big')

def Cipher(text_in, w):
    text_in_hex = text_in
    if isinstance(text_in_hex, str):
        logger.info("input was string not binary")
        text_in_hex = bytes.fromhex(text_in)
    state = []
    # s[r,c]=in[r+4c] for0≤r<4 and 0≤c<Nb, (3.3)
    for r in range(0,4):
        row = []
        for c in range(0,Nb):
            row.append(text_in_hex[r+4*c])
        state.append(row)
    print_state(state)
    
    w = KeyExpansion(w, Nk)

    logger.debug("\nRound: 0")
    logger.debug("input")
    print_state(state)

    state = AddRoundKey(state, w[0:Nb])

    for round in range(1, Nr):
        logger.debug(f"\nRound: {round}")
        logger.debug("start")
        print_state(state)

        state = SubBytes(state)
        state = ShiftRows(state)
        state = MixColumns(state)
        state = AddRoundKey(state, w[round*Nb : ((round+1)*Nb)])
    
    state = SubBytes(state)
    state = ShiftRows(state)
    state = AddRoundKey(state, w[Nr*Nb : ((Nr+1)*Nb)])

    out = bytes(state[r][c] for c in range(4) for r in range(Nb)).hex()
    logger.debug(f'out: {out}')
    return out

def KeyExpansion(key, Nk):
    temp = None
    w = []
    key_hex = bytes.fromhex(key)

    w = [
        int.from_bytes(key_hex[i:i+4], 'big') for i in range(0, len(key_hex), 4)
    ]

    # Pre calculate rcon[]
    rcon_arr = [0, 0x01_00_00_00]
    for i in range(2, Nb*(Nr + 1)):
        rcon_arr.append(xtimes(rcon_arr[i-1] >> 24) << 24)

    logger.debug("KeyExpansion")
    [logger.debug(f'{i//4}: {hex(w[i])}') for i in range(Nb)]

    for i in range(Nk, Nb * (Nr+1)):
        temp = w[i-1]
        if (i%Nk ==0):
            temp = SubWord(RotWord(temp)) ^ rcon_arr[i//Nk]
        w.append( w[i-Nk] ^ temp )
        logger.debug(f'{i//4}: {hex(w[i])}')

    return w


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )