# PuttyPlus for windows
PuttyPlus是Windows上的一款开源软件，它基于同样开源的[PuTTY](https://www.chiark.greenend.org.uk/~sgtatham/putty/)软件，并作了一些功能上的增强。

PuttyPlus可用作SSH Client、串口调试、ADB Shell登陆工具，也可作为windows console使用。



## 软件下载

https://github.com/albuer/puttyplus/releases



## 主要功能

* SSH/Telnet Client  
	PuTTY软件原本支持的功能。
	
* 串口调试  
	PuTTY本身具有该功能，但过于简单；在PuttyPlus中，为它添加了以下功能：
	
	* Ctrl + Shift + z：清除屏幕内容并回滚
	* 列出当前可用的串口，避免从设备管理器中查看串口序号的烦恼。
	* Ctrl + Shift + s：暂停/继续当前会话，停止串口的输出。
	
* ADB Shell  
	在windows console中使用adb shell，无法支持Linux快捷键的功能，比如Tab键补全之类的，在PuttyPlus中可以支持这些快捷键。
	
* Console  
	这是一个类似windows console的功能，支持文件拖曳、命令历史记录，但不支持Tab补全。平时用来配合adb完成push/pull等操作倒是没什么问题了。
	
* Z-Modem文件传输  
	支持z-modem协议，可与Linux系统互传文件
	
* 支持字符串查找

  * Ctrl + Shift + F：打开查找对话框进行字符串搜索
  * Shift+F3/F4、F3/F4：快速搜索选定的字符串

* 增加中文版本

  汉化补丁合并自larryli的[putty中文版](https://github.com/larryli/putty)

PuttyPlus自身不支持多标签，可通过第三方软件来实现多标签功能，比如MTPuTTY/WindowTabs等软件。



## 编译

在windows系统上，使用Microsoft VS2010软件打开`puttyplus/windows/msvc2010/puttyplus/puttyplus.sln`进行编辑即可



## 注意

在使用SSH功能时候，默认使用的密钥验证算法是`Diffie-Hellman group exchange`，但有一些服务器已不支持该算法，现在修改默认算法为`Diffie-Hellman group 14`

## 