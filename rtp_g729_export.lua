-- Dump RTP G.729 payload to raw file
-- Write it to from<sourceIp_sourcePort>to<dstIp_dstPort> file.
-- You can access this feature by menu "Tools"
-- Author: Yang Xing (hongch_911@126.com)
------------------------------------------------------------------------------------------------
do
    local proto_g729 = Proto("g729", "G.729")
    
    local fp_payload = ProtoField.bytes("g729.payload", "Raw")
    
    proto_g729.fields = {
        fp_payload
    }

    -- Wireshark对每个相关数据包调用该函数
    -- tvb:Testy Virtual Buffer报文缓存; pinfo:packet infomarmation报文信息; treeitem:解析树节点
    function proto_g729.dissector(tvb, pinfo, tree)
        -- add proto item to tree
        local proto_tree = tree:add(proto_g729, tvb())
        proto_tree:append_text(string.format(" (Len: %d)",tvb:len()))
        pinfo.columns.protocol = "G.729"
    end

    -- register this dissector to specific payload type (specified in preferences windows)
    local payload_type_table = DissectorTable.get("rtp.pt")
    function proto_g729.init()
        payload_type_table:add(18, proto_g729)
    end

    -- 导出数据到文件部分
    -- for geting data (the field's value is type of ByteArray)
    local f_data = Field.new("g729")

    -- menu action. When you click "Tools" will run this function
    local function export_data_to_file()
        -- window for showing information
        local tw = TextWindow.new("Export File Info Win")
        
        -- add message to information window
        function twappend(str)
            tw:append(str)
            tw:append("\n")
        end
        
        -- variable for storing rtp stream and dumping parameters
        local stream_infos = nil

        -- trigered by all ps packats
        local my_tap = Listener.new(tap, "g729")
        
        -- get rtp stream info by src and dst address
        function get_stream_info(pinfo)
            local key = "from_" .. tostring(pinfo.src) .. "_" .. tostring(pinfo.src_port) .. "_to_" .. tostring(pinfo.dst) .. "_" .. tostring(pinfo.dst_port)
            key = key:gsub(":", ".")
            local stream_info = stream_infos[key]
            if not stream_info then -- if not exists, create one
                stream_info = { }
                stream_info.filename = key.. ".g729"
                stream_info.file = io.open(stream_info.filename, "wb")
                stream_infos[key] = stream_info
                twappend("Ready to export data (RTP from " .. tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port) 
                         .. " to " .. tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port) .. " to file:[" .. stream_info.filename .. "] ...\n")
            end
            return stream_info
        end
        
        -- write data to file.
        local function write_to_file(stream_info, data_bytes)
            stream_info.file:write(data_bytes:raw())
        end
        
        -- call this function if a packet contains ps payload
        function my_tap.packet(pinfo,tvb)
            if stream_infos == nil then
                -- not triggered by button event, so do nothing.
                return
            end
            local datas = { f_data() } -- using table because one packet may contains more than one RTP
            
            for i,data_f in ipairs(datas) do
                if data_f.len < 1 then
                    return
                end
                local data = data_f.range:bytes()
                local stream_info = get_stream_info(pinfo)
                write_to_file(stream_info, data)
            end
        end
        
        -- close all open files
        local function close_all_files()
            if stream_infos then
                local no_streams = true
                for id,stream in pairs(stream_infos) do
                    if stream and stream.file then
                        stream.file:flush()
                        stream.file:close()
                        twappend("File [" .. stream.filename .. "] generated OK!\n")
                        stream.file = nil
                        no_streams = false
                    end
                end
                
                if no_streams then
                    twappend("Not found any Data over RTP streams!")
                end
            end
        end
        
        function my_tap.reset()
            -- do nothing now
        end
        
        local function remove()
            my_tap:remove()
        end
        
        tw:set_atclose(remove)
        
        local function export_data()
            stream_infos = {}
            retap_packets()
            close_all_files()
            stream_infos = nil
        end
        
        local function export_all()
            export_data()
        end
        
        tw:add_button("Export All", export_all)
    end
    
    -- Find this feature in menu "Tools"
    register_menu("Audio/Export G729", export_data_to_file, MENU_TOOLS_UNSORTED)
end