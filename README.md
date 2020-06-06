# WiresharkPlugin
There is the Video and Audio plugin for Wireshark

rtp_h264_export.lua用于解析RTP包中的H264编码数据。本插件参考作者HuangQiangxiong(qiangxiong.huang@gmail.com)所作的H264解析插件，并进行了修改。

rtp_h265_export.lua用于解析RTP包中的H265编码数据，并提取裸数据到码流文件中。为了该插件能识别出H265协议，在低版本的wireshark中需导入rtp_h265.lua插件；对于Wireshark3.0以上的版本已经支持了H265的解析，因而不需要导入rtp_h265.lua插件。

rtp_ps.lua和rtp_ps_export.lua插件可以实现对PS媒体流进行解析及导出裸流到文件中。

rtp_pcma_export.lua、rtp_pcmu_export.lua、rtp_silk_export.lua、rtp_g729_export.lua、rtp_amr_export.lua等插件用于对RTP流中的相应格式的音频流进行解析并导出成文件。


加载插件方法：

在Wireshark的About(关于)页面Folders(文件夹)目录下Personal plugins(个人Lua插件)对应的目录下存放所需的插件。在该方法中，插件只能存放在指定的目录下，且不能识别该目录下的子目录。

被插件使用ffmpeg可执行程序，可以直接播放导出后的媒体文件。

下载ffmpeg可执行程序的网址见https://ffmpeg.zeranoe.com/builds/

本地存放好ffmpeg可执行程序后，需要把ffmpeg目录设置到系统变量PATH路径中。
