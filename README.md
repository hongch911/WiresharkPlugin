# WiresharkPlugin
There is the Video and Audio plugin for Wireshark

Wireshark的音视频插件


# 文件说明
rtp_h264_export.lua用于解析RTP包中的H264编码数据。本插件参考作者HuangQiangxiong(qiangxiong.huang@gmail.com)所作的H264解析插件，并进行了修改。

rtp_h265_export.lua用于解析RTP包中的H265编码数据，并提取裸数据到码流文件中。

rtp_ps.lua和rtp_ps_export.lua插件用于实现对PS媒体流进行解析及导出ps裸流到文件中。同时也可以直接使用ps中的相应媒体协议导出媒体数据流。

rtp_pcma_export.lua、rtp_pcmu_export.lua、rtp_silk_export.lua、rtp_g729_export.lua、rtp_amr_export.lua等插件用于对RTP流中的相应格式的音频流进行解析并导出成文件。


# 加载插件方法

在Wireshark的About(关于)页面Folders(文件夹)目录下Personal plugins(个人Lua插件)对应的目录中存放lua插件文件。本方法中的插件只能存放在该的目录下，不能识别该目录下的子目录。


# 插件中直接播放媒体

如果需要在插件中直接播放媒体，需要使用到ffmpeg程序。

为了在Wireshark中直接点击插件对话框的 play 按钮进行播放，需要额外准备ffmpeg可执行程序。
把下载的ffmpeg可执行程序解压后，需设置好系统变量，以便命令行可以直接执行ffmpeg -version，并正常输出ffmpeg信息。


# ffmpeg二进制文件下载

下载ffmpeg可执行程序的见
https://github.com/tomaszzmuda/Xabe.FFmpeg/releases
https://johnvansickle.com/ffmpeg/

请选择相应的操作系统二进制文件。
