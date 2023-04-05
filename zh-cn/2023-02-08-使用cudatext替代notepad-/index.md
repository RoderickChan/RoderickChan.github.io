# 使用cudatext替代notepad++


> 鉴于`notepad++`的作者总是发表降智言论，抵制`notepad++`，从我做起。

<!--more-->

# 前言

虽然`notepad++`在同款软件中很好用，但由于其作者经常公开发表不当的政治言论，支持台独分子，因此，我们必须对该作者的行为予以谴责，对`notepad++`予以抵制。

前段时间，`notepad++`的作者声称其会在软件中新增一个功能：如果软件使用者不同意他的政治观点，`notepad++`会在源代码中随机添加任意字符。

![4dd89a9681cd8b92](https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/4dd89a9681cd8b92.jpg)



尽管其后续称以上言论是一个玩笑，但这种解释却无法令人信服。

<img src="https://lynne-markdown.oss-cn-hangzhou.aliyuncs.com/img/6c9785cdc3d69956.jpg" alt="6c9785cdc3d69956" style="zoom: 25%;" />



`notepad++`虽然好用，但并非不可替代！

常用的编程`IDE`中，`vscode`是生产力工具，但太过笨重，没有必要为了查看/编辑一个配置文件打开`vscode`，特别是在安装了很多插件的情况下。因此，需要像`notepad++`这样轻量级的文本处理工具。

在网上搜索一番后，结合使用体验，发现`cudatext`这款软件很不错，在此推荐此软件并记录使用过程。



# 安装

可以访问官网[CudaText - Home](https://cudatext.github.io/download.html)查看`cudatext`的介绍，然后到[CudaText - Browse /release at SourceForge.net](https://sourceforge.net/projects/cudatext/files/release/)下载最新版的安装包。我平常在`windows`平台上使用，所以我下载的是`cudatext-windows-amd64-1.183.0.0.zip`，下载后解压即可使用。



若是由于网络原因导致下载缓慢的话，可以从[cudatext-windows-amd64-1.183.0.0.zip](https://download.roderickchan.cn/software/cudatext-windows-amd64-1.183.0.0.zip)下载离线包，从[CudaText_addons.zip](https://download.roderickchan.cn/software/CudaText_addons.zip)下载插件包。若下载需要账户密码，账户密码为：`roderick/rode@rick`。



# 插件

到[CudaText - Browse /addons_all at SourceForge.net](https://sourceforge.net/projects/cudatext/files/addons_all/)下载插件，插件下载后，解压，然后依次点击`file->Open file`操作打开插件即可安装。插件安装时可以批量选择。

如果需要卸载插件，从`Plugins-> Addons-manager->Remove add-on`卸载即可。

从上面链接下载的插件包是全部的插件包，在查看了每一个插件的描述后，我整理了一个建议版的插件包，可以从[cudatext_addon_suggestion.7z](https://download.roderickchan.cn/software/cudatext_addon_suggestion.7z)下载。下载，安装插件时直接<kbd> Ctrl</kbd>+<kbd>A</kbd>全部选择。

`cudatext`的插件也都是很轻量的，我装了`60`多个插件后，运行`cudatext`的内存占用不超过`30 MB`，和`vscode`动辄几百兆的内存占用相比，显得尤为轻便。

这款编辑器主要使用`python`，想要自己写插件的话，可以访问[CudaText API - Free Pascal wiki](https://wiki.freepascal.org/CudaText_API)阅读`API`。然后实现所需功能即可。


---

> 作者: [roderick](https://www.roderickchan.cn)  
> URL: https://www.roderickchan.cn/zh-cn/2023-02-08-%E4%BD%BF%E7%94%A8cudatext%E6%9B%BF%E4%BB%A3notepad-/  

