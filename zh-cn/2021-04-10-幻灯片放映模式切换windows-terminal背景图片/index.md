# 幻灯片放映模式切换windows terminal背景图片

### 脚本功能

以`幻灯片模式`自动切换`windows terminal`的背景图片，可自定义包含图片的目录、切换频率等。

使用命令`python change_tty_image.py --help`查看使用帮助。

代码一共就`162`行，核心功能代码事实上可能只有不到`50`行，其他都是一些检查、日志等语句。感兴趣的可以`download`脚本，自行定制一些功能。

<!-- more -->

### 开发需求

近期在折腾`windows terminal`，于我而言这款终端软件也基本完全替代`xshell`，特别是`win 10`内置了`ssh, scp`等命令，用起来非常舒服和流畅。再和`wsl`结合起来一起玩，简直爽到飞起。

`windows terminal`可以自定义主题样式，自定义背景图片。作为一个`伪二次元`爱好者，当然要把背景换成`adroable`的小姐姐！

然而，每次终端只能设置一张图片，根本无法滿足敲命令的时候看`不一样的`二次元小姐姐的需求。联想到`windows`可以设定图片目录，并选择`幻灯片`模式动态切换桌面背景，于是去`google`一番，发现`windows terminal`的`settings.json`好像没有这个选项。查阅[官方文档]([Windows Terminal Appearance Profile Settings | Microsoft Docs](https://docs.microsoft.com/en-us/windows/terminal/customize-settings/profile-appearance))如下：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210410195841.png)

要么给一个路径，要么就和桌面壁纸设置为一样。

所以，如果想要自动切换`windows terminal`的背景图片，有一个折中方案：把`backgroundImage`设置为`desktopWallpaper`，然后桌面背景搞成`幻灯片`模式，也就是下面这样子：

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210410201103.png)

这样就能自动切换。

但是像我这样`壁纸`比较多的`收藏家`，正愁壁纸多得无处安放，怎么能把`desktop`和`windows terminal`设置成一样的背景呢？这多不合适！

于是，我花了`1`个小时，用`python`写了一个简单的脚本，支持设置`壁纸目录`、`更新频率`、`随机更新`功能，每个固定时间就为`windows terminal`切换一张背景图片。

### 使用技术

要实现这个功能其实很简单，不需要高大上的技术。整个开发需求主要包含两点：

- 定时任务
- 修改`windows terminal`的`settings.json`中的`backgroundImage`项，切换为指定目录下的图片路径，并进行轮循设置。

针对两点需求，实现手段分别为：

- 使用`time.sleep()`设置定时任务。这应该是简单的方式了，适合简单的定时任务触发。
- 使用`IO`操作，先读取指定目录的所有`image`路径，然后取一个路径出来，替换掉`backgroundImage`的值即可。

实现起来很简单，也顺便帮我复习了一下`python`操作文件和目录的一些接口。

- `time`模块获取时间，方便记录日志
- `random`模块获取随机数，得到随机图片，显然，此处无需使用`安全随机数生成器`
- `os.walk()`遍历所有目录下所有的图片路径
- 设置临时文件，读配置的时候，边读边写，然后可以使用`re`模块，正则匹配含有`backgroundImage`的行，替换掉路径
- 线程休眠实现定时任务

### 操作说明

- `python change_tty_image.py -h`查看帮助
- 确保`settings.json`中已经预定义了一个路径
- 每次开始任务之前会备份一份配置文件，不用担心原有配置丢失
- 更新频率至少为`10 min`，太快了不就走马观花
- 建议使用`pythonw`后台运行脚本



### 使用示例

#### 查看帮助

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210410203719.png)

#### 输入参数使用

![](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/20210410204201.png)

关键操作都会记录日志，或在屏幕输出！

### 脚本详情

```python
# -*- encoding: utf-8 -*-
'''
@File    : change_tty_image.py
@Time    : 2021/04/08 21:00:20
@Author  : Roderick Chan
@Email   : ch22166@163.com
@Desc    : Change windows-terminal background image automatically
'''

import os
import sys
import functools
import random
import re
import time

# key word to set image
key_word = "\"backgroundImage\""

# help message
help_msg = """
Usage: 
    python change_tty_image.py [settings_path] [picture_directory] [update_frequency] [random]
Function:
    Change windows-terminal background image automatically.
Note:
    settings_path:          [required]
        The absolute path of windows-terminal setting file.
    picture_directory:      [required]
        A absolute directory path fulled with pictures, only support 'png', 'jpg', 'gif'.
    update_frequency:       [required]
        The frequency to update image, should be more than 10, default value is 30, which represents 30min.
    random:                 [optional]
        Select image randomly or not. Default value: False.
Tips:
    1. Use `python` to run this script and output log-info on the screen.
    2. Use `pythonw` to run this script in the background and output nothing, but your can use 'tasklist' and 'taskkill' to stop. 
    3. recommendation command:
        pythonw change_tty_image.py [settings_path] [picture_directory] [update_frequency] [random] > change_image.log
    4. Use `python change_tty_image.py -h` to get help.
"""

def get_time():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) 

def log(msg):
    print("\033[1;32mINFO\033[0m: {}    \033[1;34mTime\033[0m: {}\n".format(msg, get_time()))

# parse args
# check args
args = sys.argv
arg_len = len(args)

# show help
if len(args) > 1 and (args[1] == "-h" or args[1] == "--help"):
    print(help_msg)
    sys.exit(0)

if arg_len < 4 or arg_len > 5:
    print("\033[1;31m[-] Args Error!\033[0m\n")
    print(help_msg)
    sys.exit(-1)

# validate args
settings_path = args[1]
picture_directory = args[2]
update_frequency = args[3]
random_enabled = False
if arg_len == 5:
    random_enabled = bool(args[4])

assert os.path.exists(settings_path), "settings_path doesn't exist."
assert os.path.isfile(settings_path), "settings_path is not a file path."
assert os.path.exists(picture_directory), "picture_directory doesn't exist."
assert os.path.isdir(picture_directory), "picture_directory is not a dir path."

# process settings_path
settings_dir, settings_full_name = os.path.split(settings_path)
settings_name, setting_suffix = os.path.splitext(settings_full_name)
backup_setting_path = os.path.join(settings_dir, settings_name + "_backup" + setting_suffix)
tmp_setting_path = os.path.join(settings_dir, settings_name + "_tmpfile" + setting_suffix)


# process update_frequency
if update_frequency.isdecimal():
    update_frequency = int(update_frequency)
    if update_frequency < 10:
        update_frequency = 30
else:
    update_frequency = 30
log('settings_path: {}'.format(settings_path))
log('backup_setting_path: {}'.format(backup_setting_path))
log('picture_directory: {}'.format(picture_directory))
log('update_frequency: {}'.format(update_frequency))
log('random_enabled: {}'.format(random_enabled))

# get all picture path
all_picture_path = []
support_suffix = ('.jpg', '.png', '.gif')
for r, dl, fl in os.walk(picture_directory,):
    for f in fl:
        is_ok = functools.reduce(lambda a, b : a or b, map(lambda x: f.endswith(x), support_suffix))
        if not is_ok:
            continue
        # check size
        if len(all_picture_path) > 0x1000:
            continue;
        all_picture_path.append(os.path.join(r, f))

assert len(all_picture_path) > 0, 'no pictures appended, check your picture_directory.'

# validate settings_path
flag = False
with open(file=settings_path, mode='r+', encoding='utf-8') as fd:
    for line in fd:
        if line.strip().startswith(key_word):
            flag = True
            break
assert flag, "please initial your windows-terminal settings file first, add {} value at least.".format(key_word)

log('all_picture_path : {}'.format(all_picture_path))

# back up
if not os.path.exists(backup_setting_path):
    cmd = "copy {} {}".format(settings_path, backup_setting_path)
    os.popen(cmd)
    log("execute \"{}\"".format(cmd))

idx = -1

while True:
    if random_enabled:
        idx = random.randint(0, len(all_picture_path) - 1)
    else:
        idx += 1
        idx %= len(all_picture_path)
    
    # replace '\' with '/'
    cur_picture_path = all_picture_path[idx].replace("\\", "/")
    log('cur_picture_path: {}'.format(cur_picture_path))
    with open(file=settings_path, mode='r', encoding='utf-8') as fd_src:
        with open(file=tmp_setting_path, mode='w+', encoding='utf-8') as fd_bck:
            for line in fd_src:
                if not line.strip().startswith(key_word):
                    fd_bck.write(line)
                    continue
                res = re.sub(r"({}\s?:\s?)\".+\",".format(key_word), r'\1"{}",'.format(cur_picture_path), line)
                fd_bck.write(res)
    
    cmd = "copy {} {}".format(tmp_setting_path, settings_path)
    os.popen(cmd)
    log("execute \"{}\"".format(cmd))
    
    cmd = "del {}".format(tmp_setting_path)
    os.popen(cmd)
    log("execute \"{}\"".format(cmd))
    
    # sleep
    log("sleep start...")
    time.sleep(update_frequency * 60)
    log("sleep end...")
    

```



### 引用参考

`windows terminal profile setting`：<[Windows Terminal Appearance Profile Settings | Microsoft Docs](https://docs.microsoft.com/en-us/windows/terminal/customize-settings/profile-appearance)>



---

> 作者: [roderick](https://roderickchan.github.io)  
> URL: https://roderickchan.github.io/zh-cn/2021-04-10-%E5%B9%BB%E7%81%AF%E7%89%87%E6%94%BE%E6%98%A0%E6%A8%A1%E5%BC%8F%E5%88%87%E6%8D%A2windows-terminal%E8%83%8C%E6%99%AF%E5%9B%BE%E7%89%87/  

