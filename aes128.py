#! /usr/bin/env python3

# oceancholic - 2024
# ***********************************************************
# AES 128bit implementation in traditional style (from scratch)
# includes Sbox - InvSbox - Rcon implementations as well
# more info
# https://csrc.nist.gov/pubs/fips/197/final
#
# for educational only and gives insight of how AES works.
# Performance/Efficiency was not a concern
# Tested with NIST Known Answer Test (KAT)
# ************************************************************
#
#       NOT FOR PRODUCTION !!NOT SAFE!! 
# 
# ************************************************************
# only use cryptographic libraries which supports 
# specialized CPU instructions more info at
# https://www.intel.com/content/www/us/en/developer/articles/tool/intel-advanced-encryption-standard-aes-instructions-set.html
#
# Do not use Apples aes.c imlementation they obviously choose performance over security
# Prone to Side Channel attacks. (just saying)
# 
# Contributions and Suggestions are Welcome 
# -------------------------------------------

# Helper Function for inverse modulo
def gf_degree(a):
    res = 0
    a >>= 1
    while (a != 0):
        a >>= 1
        res += 1
    return res

# Inverse Modulo Routine 
# 100011011 is AES Constant
def gf_invert(a, mod=0b100011011):
    v = mod
    g1 = 1
    g2 = 0
    j = gf_degree(a) - 8
    while (a != 1):
        if (j < 0):
            a, v = v, a
            g1, g2 = g2, g1
            j = -j
        a ^= v << j
        g1 ^= g2 << j
        a %= 256  
        g1 %= 256
        j = gf_degree(a) - gf_degree(v)
    return g1

# rotating bits of n left to right d times
def rightRotate(n, d):
    bits = 8
    return (n >> d)|(n << (bits - d)) & 0xFF

# this routine creates the S Box
def generate_enc_box():
    s_box = []
    c = 0b01100011
    for i in range(0,256):
        b = gf_invert(i) if i != 0 else 0
        b ^= rightRotate(b,4) ^ rightRotate(b,5) ^ rightRotate(b,6) ^ rightRotate(b,7) ^ c
        s_box.append(b)
    return s_box

# This routine creates inv S Box
def generate_inv_box():
    inv_s_box = []
    d = 0b00000101
    for i in range(0,256):
        b = rightRotate(i,2) ^ rightRotate(i, 5) ^ rightRotate(i,7) ^ d
        check = gf_invert(b) if b != 0 else 0
        inv_s_box.append(check)
    return inv_s_box

# the algorithm to create Round Constants (Rcon)
def generate_rcon():
    rcon = [0x00, 0x01]
    for i in range(2,32):
        t = (rcon[-1] * 2)
        t = t if t < 255 else (t ^ 0b100011011)
        rcon.append(t)
    return rcon


Sbox = generate_enc_box()
InvSbox = generate_inv_box()
Rcon = generate_rcon()

# for 4x4 matrix used as state
def text2matrix(text):
    matrix = []
    for i in range(0,len(text),4):
        temp = []
        for j in range(i, i+4, 1):
            temp.append(text[j])
        matrix.append(temp)
    return matrix

# from state back to text 
def matrix2text(matrix):
    text = b""
    for i in range(4):
        text += b"".join([bytes(matrix[i][j] for j in range(4))])
    return text

def xor_bytes(a, b):
    return bytes(i^j for i, j in zip(a, b))

# SBox Substitution for key expansion function 
def sub_key_bytes(s):
    for i in range(4):
        s[i] = Sbox[s[i]]

# AES Key Expansion routine 
# https://en.wikipedia.org/wiki/AES_key_schedule
def key_expansion(key):
    Nb = 4                  
    Nk = int(len(key)/4);   
    Nr = Nk + 6;            

    w = [None for _ in range(int(Nb*(Nr+1)))]
    temp = [None for _ in range(4)];

    for i in range(Nk):
        r = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]];
        w[i] = r;
    
    for i in range(Nk, int(Nb*(Nr+1))):
        w[i] = [None for _ in range(4)]
        for t in range(4) : temp[t] = w[i-1][t]
        if (i % Nk == 0):
            temp.append(temp.pop(0))
            sub_key_bytes(temp)
            temp[0] ^= Rcon[int(i/Nk)]
        w[i] = [(w[i-Nk][t] ^ temp[t]) for t in range(4)];
    return [w[4*i : 4*(i+1)] for i in range(len(w) // 4)]

# https://crypto.stackexchange.com/questions/14902/understanding-multiplication-in-the-aes-specification
def xTime(a):
    if(a & 0x80):
        return ((a << 1) ^ 0x1B) & 0xFF
    else:
        return a << 1

# XOR state matrice with aes key   
def add_round_key(s, key):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= key[i][j]

# Substitution phase for encryption
def sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = Sbox[s[i][j]]

# Substitution phase for decryption
def inv_sub_bytes(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = InvSbox[s[i][j]]

# https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step
def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

# inversion of shift rows
def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

# helper function for mix column
# as the name suggests it works on one row at a time
def mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xTime(a[0] ^ a[1])
    a[1] ^= t ^ xTime(a[1] ^ a[2])
    a[2] ^= t ^ xTime(a[2] ^ a[3])
    a[3] ^= t ^ xTime(a[3] ^ u)

# https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_MixColumns_step
def mix_columns(s):
    for i in range(4):
        mix_single_column(s[i])

# inversion of mix column step
def inv_mix_columns(s):
    for i in range(4):
        u = xTime(xTime(s[i][0] ^ s[i][2]))
        v = xTime(xTime(s[i][1] ^ s[i][3]))
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v
    mix_columns(s)

# encrypts 16byte - 128bit state matrice
def encrypt16(plain, key):
    s = text2matrix(plain)
    add_round_key(s,key[0])
    for i in range(1,10,1):
        sub_bytes(s)
        shift_rows(s)
        mix_columns(s)
        add_round_key(s,key[i])
    sub_bytes(s)
    shift_rows(s)
    add_round_key(s,key[-1])
    return matrix2text(s)

# decrypts 16byte - 128bit state matrice
def decrypt16(cipher, key):
    cipher_state = text2matrix(cipher)
    add_round_key(cipher_state, key[-1])
    inv_shift_rows(cipher_state)
    inv_sub_bytes(cipher_state)
    for i in range(9,0,-1):
        add_round_key(cipher_state, key[i])
        inv_mix_columns(cipher_state)
        inv_shift_rows(cipher_state)
        inv_sub_bytes(cipher_state)
    add_round_key(cipher_state, key[0])
    return matrix2text(cipher_state)

# pkcs7 padding
def padder(plain_bytes):
    if(len(plain_bytes) % 16 == 0): return plain_bytes
    lenght = 16 - len(plain_bytes) % 16
    padding_byte = lenght.to_bytes(1,'little')
    return plain_bytes + (lenght * padding_byte)

#pkcs7 unpadding
def unpadder(padded_bytes):
    if(len(padded_bytes) == 16): return padded_bytes
    pad = int(padded_bytes[-1])
    return padded_bytes[0:len(padded_bytes)-pad]

# Main encryption Function 
# divides givin data to 16byte arrays
# returns cipher this mode is called ECB mode.
# if you XOR first 16byteArray with IV and XOR every other bytesArrays
# with the previous encrypted block it will be CBC mode
def encrypt(plain, key):
    exp = key_expansion(key)
    plain = padder(plain)
    cipher = []
    blocks = int(len(plain) / 16)
    for i in range(blocks):
        cipher.append(encrypt16(plain[i*16:16*(i+1)],exp))
    return b"".join([c for c in cipher])

# decryption routine
# basically it is inverted verison of encryption.
def decrypt(cipher, key):
    exp = key_expansion(key)
    blocks = int(len(cipher) / 16)
    plain_padded = []
    for i in range(blocks):
        plain_padded.append(decrypt16(cipher[i*16:16*(i+1)], exp))
    return unpadder(b"".join([b for b in plain_padded]))


# NIST KAT(Known answer test) values
# https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Block-Ciphers#AES
def kat_test():
    kat_data = [
        ('f34481ec3cc627bacd5dc3fb08f273e6','0336763e966d92595a567cc9ce537f5e'),
        ('9798c4640bad75c7c3227db910174e72','a9a1631bf4996954ebc093957b234589'),
        ('96ab5c2ff612d9dfaae8c31f30c42168','ff4f8391a6a40ca5b25d23bedd44a597'),
        ('6a118a874519e64e9963798a503f1d35','dc43be40be0e53712f7e2bf5ca707209'),
        ('cb9fceec81286ca3e989bd979b0cb284','92beedab1895a94faa69b632e5cc47ce'),
        ('b26aeb1874e47ca8358ff22378f09144','459264f4798f6a78bacb89c15ed3d601'),
        ('58c8e00b2631686d54eab84b91f0aca1','08a4e2efec8a8e3312ca7460b9040bbf')
    ]
    
    keyhex = "00000000000000000000000000000000"
    key = bytes.fromhex(keyhex)
    for test in kat_data:
        test_item = bytes.fromhex(test[0])
        enc = encrypt(test_item, key)
        if enc.hex() == test[1]:
            print("[+] Encryption Test OK.") 
        else:
            print(f"[ERROR] {enc.hex()} -! {test[1]}")
            print("[ERROR] Encryption Test Failed.")
        dec = decrypt(enc, key)
        if dec.hex() == test[0]:
            print("[+] Decryption Test Ok.")
        else:
            print("[ERROR] Decryption Test Failed.")
        print(f"{'+-' * 10 + '+'}")

kat_test()