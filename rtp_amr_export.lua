-- Dump RTP AMR payload to raw file
-- According to RFC3267 to dissector payload of RTP to NALU
-- The AMR file header (#!AMR\n)
-- +---------------+---------------+---------------+
-- |  0x23   0x21  |  0x41   0x4d  |  0x52   0x0a  |
-- |    语音帧1                                    |
-- |    语音帧2                                    |
-- |    ...                                        |
-- Write it to from<sourceIp_sourcePort>to<dstIp_dstPort> file.
-- You can access this feature by menu "Tools"
-- Author: Yang Xing (hongch_911@126.com)
------------------------------------------------------------------------------------------------
do

    function get_temp_path()
        local tmp = nil
        if tmp == nil or tmp == '' then
            tmp = os.getenv('HOME')
            if tmp == nil or tmp == '' then
                tmp = os.getenv('USERPROFILE')
                if tmp == nil or tmp == '' then
                    tmp = persconffile_path('temp')
                else
                    tmp = tmp .. "/wireshark_temp"
                end
            else
                tmp = tmp .. "/wireshark_temp"
            end
        end
        return tmp
    end

    -- 导出数据到文件部分
    local version_str = string.match(_VERSION, "%d+[.]%d*")
    local version_num = version_str and tonumber(version_str) or 5.1
    local bit = (version_num >= 5.2) and require("bit32") or require("bit")

    -- for geting data (the field's value is type of ByteArray)
    local f_data = Field.new("amr")
    local f_amr_decode_mode = Field.new("amr.payload_decoded_as")
    local f_amr_ft = Field.new("amr.nb.toc.ft")

    local data_vaild_len_vals = {
        [0] = 13,
        [1] = 14,
        [2] = 16,
        [3] = 18,
        [4] = 20,
        [5] = 21,
        [6] = 27,
        [7] = 32,
        [8] = 6
    }

    local filter_string = nil

    -- menu action. When you click "Tools" will run this function
    local function export_data_to_file()
        -- window for showing information
        local tw = TextWindow.new("Export File Info Win")
        
        -- add message to information window
        function twappend(str)
            tw:append(str)
            tw:append("\n")
        end

        -- temp path
        local temp_path = get_temp_path()
        
        -- variable for storing rtp stream and dumping parameters
        local stream_infos = nil

        -- trigered by all ps packats
        local list_filter = ''
        if filter_string == nil or filter_string == '' then
            list_filter = "amr"
        elseif string.find(filter_string,"amr")~=nil then
            list_filter = filter_string
        else
            list_filter = "amr && "..filter_string
        end
        twappend("Listener filter: " .. list_filter .. "\n")
        local my_tap = Listener.new("frame", list_filter)
        
        -- get rtp stream info by src and dst address
        function get_stream_info(pinfo)
            local key = "from_" .. tostring(pinfo.src) .. "_" .. tostring(pinfo.src_port) .. "_to_" .. tostring(pinfo.dst) .. "_" .. tostring(pinfo.dst_port)
            key = key:gsub(":", ".")
            local stream_info = stream_infos[key]
            if not stream_info then -- if not exists, create one
                stream_info = { }
                stream_info.filename = key.. ".amr"
                -- stream_info.file = io.open(stream_info.filename, "wb")
                if not Dir.exists(temp_path) then
                    Dir.make(temp_path)
                end
                stream_info.filepath = temp_path.."/"..stream_info.filename
                stream_info.file,msg = io.open(temp_path.."/"..stream_info.filename, "wb")
                if msg then
                    twappend("io.open "..stream_info.filepath..", error "..msg)
                end
                stream_info.file:write("\x23\x21\x41\x4d\x52\x0a")  -- "#!AMR\n"
                stream_infos[key] = stream_info
                twappend("Ready to export data (RTP from " .. tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port) 
                         .. " to " .. tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port) .. " write to file:[" .. stream_info.filename .. "] ...\n")
            end
            return stream_info
        end
        
        -- write data to file.
        local function write_to_file(stream_info, ft, data_bytes)
            local frame_header = bit.bor(0x04 ,bit.lshift(ft, 3))
            data_bytes:set_index(0, frame_header)
            -- 需要byte数组整体左移两个bit
            for index=1,data_bytes:len()-2 do
                local A = bit.lshift(data_bytes:get_index(index), 2)
                local B = bit.rshift(data_bytes:get_index(index+1), 6)
                data_bytes:set_index(index, bit.band(bit.bor(A, B), 0xff))
            end
            data_bytes:set_index(data_bytes:len()-1, bit.band(bit.lshift(data_bytes:get_index(data_bytes:len()-1), 2), 0xff))
            
            local data_vaild_len = data_vaild_len_vals[ft]

            stream_info.file:write(data_bytes:raw(0, data_vaild_len))
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

                local decoded_mode = f_amr_decode_mode().value
                if decoded_mode == 1 then
                    local ft_bits = f_amr_ft().value
                    local stream_info = get_stream_info(pinfo)
                    local data = data_f.range:bytes()
                    write_to_file(stream_info, ft_bits, data)
                end
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
                        stream.file = nil
                        twappend("File [" .. stream.filename .. "] generated OK!")
                        twappend("ffplay -f amr -acodec amrnb -autoexit "..stream.filename)
                        no_streams = false
                    end
                end
                
                if no_streams then
                    twappend("Not found any Data over RTP streams!")
                else
                    tw:add_button("Browser", function () browser_open_data_file(temp_path) end)
                end
            end
        end

        twappend("Only support BW-efficient mode")
        
        function my_tap.reset()
            -- do nothing now
        end
        
        tw:set_atclose(function ()
            my_tap:remove()
            if Dir.exists(temp_path) then
                Dir.remove_all(temp_path)
            end
        end)
        
        local function export_data()
            stream_infos = {}
            retap_packets()
            close_all_files()
            stream_infos = nil
        end
        
        tw:add_button("Export All", function ()
            export_data()
        end)

        tw:add_button("Set Filter", function ()
            tw:close()
            dialog_menu()
        end)
    end

    local function dialog_func(str)
        filter_string = str
        export_data_to_file()
    end

    function dialog_menu()
        new_dialog("Filter Dialog",dialog_func,"Filter")
    end

    local function dialog_default()
        filter_string = get_filter()
        export_data_to_file()
    end
    
    -- Find this feature in menu "Tools"
    register_menu("Audio/Export AMR", dialog_default, MENU_TOOLS_UNSORTED)
end
