# WiresharkPlugin
There is the Video and Audio plugin for Wireshark

rtp_h264_export.lua用于解析RTP包中的H264编码数据。本插件参考作者Huang Qiangxiong(qiangxiong.huang@gmail.com)所做的H264解析插件，并进行了修改。

rtp_h265_export.lua用于解析RTP包中的H265编码数据，并提取裸数据到码流文件中。为了该插件能识别出H265协议，在低版本的wireshark中需导入rtp_h265.lua插件；对于Wireshark3.0以上的版本已经支持了H265的解析，因而不需要导入rtp_h265.lua插件。

rtp_ps.lua和rtp_ps_export.lua插件可以实现对PS媒体流进行解析及导出裸流到文件中，根据PS中的视频流类型自动识别H264码流或H265码流。

rtp_pcma_export.lua、rtp_pcmu_export.lua、rtp_silk_export.lua、rtp_g729_export.lua、rtp_amr_export.lua等插件用于对RTP流中的相应格式的音频流进行解析并导出成文件。

加载插件方法：
1：在Wireshark中需要在安装路径下的init.lua文件中加载插件，为了避免每次添加lua插件文件时都修改init.lua文件，建议在init.lua文件中使用如下方式自动扫描相关目录下的所有lua插件进行自动加载。
```lua
--dofile(DATA_DIR.."dtd_gen.lua")
for filename in Dir.open(USER_DIR, ".lua") do 
    dofile(USER_DIR..filename)
end
```
2：在Wireshark的About(关于)页面Folders(文件夹)目录下Personal plugins(个人Lua插件)对应的目录下存放所需的插件即可。
