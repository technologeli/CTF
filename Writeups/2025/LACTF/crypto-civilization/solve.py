import hashlib
from pwn import *
import binascii
import random

# PRG function
def PRG(s: bytes) -> bytes:
    assert len(s) == 2
    h = hashlib.new("sha3_256")
    h.update(s)
    return h.digest()[:4]

# XOR function
def xor_bytes(bytes1: bytes, bytes2: bytes) -> bytes:
    return bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2))

# Precompute PRG values
prg_map = {i.to_bytes(2, "big"): PRG(i.to_bytes(2, "big")) for i in range(65536)}
prg_set = set(prg_map.values())  # Fast lookup
keys = list(prg_map.keys())

def pick_com(y):
    for _ in range(40_000):
        s = random.choice(keys)
        s_xor = s
        com = prg_map[s]
        com_xor_y = xor_bytes(com, y)

        if com_xor_y in prg_set:
            s_xor = [k for k, v in prg_map.items() if v == com_xor_y][0]
            break  # We found valid (s, s_xor)
    return s, s_xor, com


if __name__ == "__main__":
    c_good = 0
    c_total = 0
    b_good = 0
    b_total = 0

    # p = remote("chall.lac.tf", 31173)
    p = process(["python", "./civ.py"])
    for i in range(200):
        p.recvuntil(b"y: ")
        y = bytes.fromhex(p.recvline().decode().split()[-1])
        p.recvuntil(b"> ")

        s, s_xor, com = pick_com(y)
        p.sendline(com.hex().encode())
        pick = p.recvuntil(b"> ")

        if b"chicken" in pick:
            p.sendline(s.hex().encode())
            c_total += 1
        else:
            p.sendline(s_xor.hex().encode())
            b_total += 1

        result = p.recvuntil(b".")
        if b"Good" in result:
            if b"chicken" in pick:
                c_good += 1
            else:
                b_good += 1
        p.recvline()
        info(f"chicken: {c_good:3}/{c_total:3}, beef: {b_good:3}/{b_total:3}, total: {c_good + b_good:3}/{c_total + b_total:3}")
        print(p.recvline())
    p.interactive()
