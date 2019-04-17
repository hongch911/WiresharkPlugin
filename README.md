# WiresharkPlugin
The plugin for Wireshark

本插件用于解析RTP包中的H265编码数据，并提取裸数据到码流文件中。为了rtp_h265_export.lua能识别出H265协议，在低版本的wireshark中需导入rtp_h265.lua插件；对于Wireshark3.0以上的版本已经支持了H265的解析，因而不需要导入rtp_h265.lua插件。

在Wireshark中需要在安装路径下的init.lua文件中加载插件，为了避免每次添加lua插件文件时都修改init.lua文件，建议在init.lua文件中使用如下方式自动扫描相应目录下的所有lua插件进行加载。
```lua
--dofile(DATA_DIR.."dtd_gen.lua")
for filename in Dir.open(USER_DIR, ".lua") do 
    dofile(USER_DIR..filename)
end
```

