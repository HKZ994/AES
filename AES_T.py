import numpy as np
import time
from utils.aes_table import mc_matrix
from utils.aes_function import *


'''
    AES-128 Encryption T-table实现
    round = sr, T-table(sbox, mc), ak
'''

Te = np.zeros((4, 256), dtype=np.uint32)
for i in range(4):
    col = mc_matrix[:, i]
    for j in range(256):
        for z in range(4):
            if z < 3:
                Te[i][j] = (Te[i][j] ^ Mul_GF(AES_Sbox[j], col[z])) << 8
            else:
                Te[i][j] = Te[i][j] ^ Mul_GF(AES_Sbox[j], col[z])

plt = [0x00, 0x01, 0x00, 0x01, 0x01, 0xa1, 0x98, 0xaf, 0xda, 0x78, 0x17, 0x34, 0x86, 0x15, 0x35, 0x66]
key = [0x00, 0x01, 0x20, 0x01, 0x71, 0x01, 0x98, 0xae, 0xda, 0x79, 0x17, 0x14, 0x60, 0x15, 0x35, 0x94]

start = time.time()

state = AddRoundKey(plt, key)

for i in range(10):
    # print("ROUND:", i+1)

    if i < 9:
        temp = [
            Te[0][state[0]] ^ Te[1][state[5]] ^ Te[2][state[10]] ^ Te[3][state[15]],
            Te[0][state[4]] ^ Te[1][state[9]] ^ Te[2][state[14]] ^ Te[3][state[3]],
            Te[0][state[8]] ^ Te[1][state[13]] ^ Te[2][state[2]] ^ Te[3][state[7]],
            Te[0][state[12]] ^ Te[1][state[1]] ^ Te[2][state[6]] ^ Te[3][state[11]]
        ]
        state = [
            temp[0] >> 24, (temp[0] >> 16) & 0xff, (temp[0] >> 8) & 0xff, temp[0] & 0xff,
            temp[1] >> 24, (temp[1] >> 16) & 0xff, (temp[1] >> 8) & 0xff, temp[1] & 0xff,
            temp[2] >> 24, (temp[2] >> 16) & 0xff, (temp[2] >> 8) & 0xff, temp[2] & 0xff,
            temp[3] >> 24, (temp[3] >> 16) & 0xff, (temp[3] >> 8) & 0xff, temp[3] & 0xff
        ]
        print_state_hex(state, "after MixColumns")
    else:
        state = ShiftRows(SubBytes(state))
        print_state_hex(state, "after MixColumns")

    key = KeyExpand(key, i)
    # print expanded round key
    # print([hex(k) for k in key])
    state = AddRoundKey(state, key)
    # print_state_hex(state, "after AddRoundKey")

print_state_hex(state, "ciphertext")

print("time", time.time()-start)
