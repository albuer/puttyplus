# PuttyPlus for windows
PuttyPlus是Windows上的一款开源、免费软件，它基于同样免费的PuTTY软件，并作了一些功能上的增强，它可用作SSH Client、串口调试、ADB Shell登陆工具，也可作为windows console使用

程序下载地址：
https://github.com/albuer/puttyplus/raw/master/release/PuttyPlus_v1.01.zip

主要功能如下:
* SSH Client  
	PuTTY原有功能。
* 串口调试  
	PuTTY本身具有该功能，但过于简单；在PuttyPlus中，为它添加了以下功能：
	* 查找字符串，可以通过Shift+F3/F4、F3/F4等快捷键来实现快速搜索
	* 暂停输入输出
	* 清屏回滚
	* 列出当前可用的串口，避免从设备管理器中查看串口序号的烦恼。
* ADB Shell  
	在windows console中使用adb shell，无法支持Linux快捷键的功能，比如Tab键补全之类的，在PuttyPlus中可以支持这些快捷键。
* Console  
	这是一个类似windows console的功能，支持文件拖曳、命令历史记录，但不支持Tab补全。平时用来配合adb完成push/pull等操作倒是没什么问题了。
* Z-Modem文件传输  
	支持z-modem协议，可与Linux系统互传文件

PuttyPlus自身不支持多标签，可通过第三方软件来实现多标签功能，比如MTPuTTY/WindowTabs等软件。
