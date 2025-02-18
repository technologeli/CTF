from pwn import *

local = process("./a.out")
cookies = local.recvall().decode().strip().split("\n")

exe = process("./main")

for cookie in cookies:
    print(exe.recvuntil(b": "))
    sleep(0.1)
    info(cookie.encode())
    exe.sendline(cookie.encode())

exe.interactive()
