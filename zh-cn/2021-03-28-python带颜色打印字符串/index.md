# python带颜色打印字符串

之前调试pwn题的时候，有时候需要将某些特别的，重要的信息用不一样的颜色打印出来。查阅一些[资料](https://stackoverflow.com/questions/287871/how-to-print-colored-text-to-the-terminal)，了解了`print`函数的特性后，自己写了一个脚本，可以用来获取带颜色信息的字符串或者打印一串带颜色、背景色、下划线等的字符串。

<!-- more -->
### 脚本内容
```python
#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
'''
@File    : print_with_color.py
@Time    : 2021/03/07 12:41:35
@Author  : Lynne
@Email   : ch22166@163.com
@Desc    : None
'''
from functools import partial

class FontColor:
    BLACK = 30
    RED = 31
    GREEN = 32
    YELLO = 33
    BLUE = 34
    AMARANTH = 35
    CYAN = 36
    WHITE = 37
    
class BackgroundColor:
    NOCOLOR = -1
    BLACK = 40
    RED = 41
    GREEN = 42
    YELLO = 43
    BLUE = 44
    AMARANTH = 45
    CYAN = 46
    WHITE = 47
    
class TerminalMode:
    DEFAULT = 0
    HIGHLIGHT = 1
    UNDERLINE = 4
    TWINKLE = 5
    ANTI_WHITE = 7
    INVISIBLE = 8
    

def __check(font_color:int, background_color:int, terminal_mode:int) -> bool:
    b1 = (font_color >= FontColor.BLACK and font_color <= FontColor.WHITE)
    b2 = (background_color >= BackgroundColor.BLACK and background_color <= BackgroundColor.WHITE) or background_color == BackgroundColor.NOCOLOR
    b3 = (terminal_mode >= TerminalMode.DEFAULT and terminal_mode <= TerminalMode.INVISIBLE and terminal_mode != 2 and terminal_mode != 3 and terminal_mode != 6)
    return (b1 and b2 and b3)


def get_str_with_color(print_str:str, *,
                       font_color:int=FontColor.WHITE, 
                       background_color:int=BackgroundColor.NOCOLOR, 
                       terminal_mode:int=TerminalMode.DEFAULT)-> str:
    """Decorate a string with color

    Args:
        print_str (str): The str you want to modify.
        font_color (int, optional): Font color. Defaults to FontColor.WHITE.
        background_color (int, optional): Background color. Defaults to BackgroundColor.NOCOLOR.
        terminal_mode (int, optional): terminal mode. Defaults to TerminalMode.DEFAULT.

    Returns:
        str: A string with elaborate decoration.
    """
    check = __check(font_color, background_color, terminal_mode)
    if not check:
        print('\033[1;31;47mWARNING: Failure to set color!\033[0m')
        return print_str
    if background_color == BackgroundColor.NOCOLOR:
        background_color = ''
    else:
        background_color = ';'+str(background_color)
    res_str = '\033[{};{}{}m{}\033[0m'.format(terminal_mode, font_color, background_color, print_str)
    return res_str


def print_color(print_str:str, *,
                font_color:int=FontColor.WHITE, 
                background_color:int=BackgroundColor.NOCOLOR, 
                terminal_mode:int=TerminalMode.DEFAULT):
    """print a string with color

    Args:
        print_str (str): The str you want to modify.
        font_color (int, optional): Font color. Defaults to FontColor.WHITE.
        background_color (int, optional): Background color. Defaults to BackgroundColor.NOCOLOR.
        terminal_mode (int, optional): terminal mode. Defaults to TerminalMode.DEFAULT.

    """
    print(get_str_with_color(print_str, font_color=font_color, background_color=background_color, terminal_mode=terminal_mode))
    

# make rgb print func
print_red = partial(print_color, 
                    font_color=FontColor.RED, 
                    background_color=BackgroundColor.NOCOLOR, 
                    terminal_mode=TerminalMode.DEFAULT)

print_green = partial(print_color, 
                    font_color=FontColor.GREEN, 
                    background_color=BackgroundColor.NOCOLOR, 
                    terminal_mode=TerminalMode.DEFAULT)

print_blue = partial(print_color, 
                    font_color=FontColor.BLUE, 
                    background_color=BackgroundColor.NOCOLOR, 
                    terminal_mode=TerminalMode.DEFAULT)

if __name__ == '__main__':
    print('Original print: lynne')
    print_red('Print with red font: lynne')
    print_green('Print with green font: lynne')
    print_blue('Print with blue font:lynne')
    print_color('Print with cyan font, blue background and underline: lynne', font_color=FontColor.CYAN, background_color=BackgroundColor.BLUE, terminal_mode=TerminalMode.UNDERLINE)
```

在控制台的打印效果如下：
![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210307164058.png)

### 使用
- get_str_with_color：获取带颜色信息的字符串
- print_color：带颜色打印字符串
- print_red/print_green/print_blue：自已定义一些偏函数，方便使用

---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2021-03-28-python%E5%B8%A6%E9%A2%9C%E8%89%B2%E6%89%93%E5%8D%B0%E5%AD%97%E7%AC%A6%E4%B8%B2/  

