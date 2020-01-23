-- Dump RTP PS payload to raw h.264/5 file
-- According to RFC2250 to dissector payload of RTP to NALU
-- Write it to from<sourceIp_sourcePort>to<dstIp_dstPort> file.
-- You can access this feature by menu "Tools"
-- Author: Yang Xing (hongch_911@126.com)
------------------------------------------------------------------------------------------------
do
    local version_str = string.match(_VERSION, "%d+[.]%d*")
    local version_num = version_str and tonumber(version_str) or 5.1
    local bit = (version_num >= 5.2) and require("bit32") or require("bit")

    local ps_stream_type_vals = {
        [0x10] = "MPEG-4 Video",
        [0x1b] = "H.264",
        [0x24] = "H.265",
        [0x80] = "SVAC Video",
        [0x90] = "G.711",
        [0x92] = "G.722.1",
        [0x93] = "G.723.1",
        [0x99] = "G.729",
        [0x9b] = "SVAC Audio",
    }
    local file_stream_type_vals = {
        [0x10] = ".mpge-4",
        [0x1b] = ".264",
        [0x24] = ".265",
        [0x80] = ".SVACVideo",
        [0x90] = ".g711",
        [0x92] = ".g722",
        [0x93] = ".g723",
        [0x99] = ".g729",
        [0x9b] = ".SVACAudio",
    }
    local function get_enum_name(list, index)
        local value = list[index]
        return value and value or ""
    end

    -- for geting ps data (the field's value is type of ByteArray)
    local f_pes_data = Field.new("ps.pes.data_bytes")
    local f_stream_type = Field.new("ps.program_map.map.stream_type")

    local filter_string = nil

    -- menu action. When you click "Tools" will run this function
    local function export_data_to_file()
        -- window for showing information
        local tw = TextWindow.new("Export PS to File Info Win")
        local pgtw;
        
        -- add message to information window
        function twappend(str)
            tw:append(str)
            tw:append("\n")
        end
        
        -- running first time for counting and finding sps+pps, second time for real saving
        local first_run = true 
        -- variable for storing rtp stream and dumping parameters
        local stream_infos = nil

        -- trigered by all ps packats
        local list_filter = (filter_string == nil or filter_string == '') and ("ps") or ("ps && "..filter_string)
        twappend("Listener filter: " .. list_filter .. "\n")
        local my_ps_tap = Listener.new("frame", list_filter)
        
        -- get rtp stream info by src and dst address
        function get_stream_info(pinfo)
            local key = "from_" .. tostring(pinfo.src) .. "_" .. tostring(pinfo.src_port) .. "_to_" .. tostring(pinfo.dst) .. "_" .. tostring(pinfo.dst_port)
            key = key:gsub(":", ".")
            local stream_info = stream_infos[key]
            if not stream_info then -- if not exists, create one
                if f_stream_type() and f_stream_type().value then
                    local stream_type = f_stream_type().value
                    local streamType = get_enum_name(ps_stream_type_vals, stream_type)
                    local fileType = get_enum_name(file_stream_type_vals, stream_type)
                    twappend("streamType="..streamType.." fileType="..fileType)
                    stream_info = { }
                    stream_info.streamtype = streamType
                    stream_info.filename = key.. fileType
                    stream_info.file = io.open(stream_info.filename, "wb")
                    stream_info.counter = 0 -- counting ps total NALUs
                    stream_info.counter2 = 0 -- for second time running
                    stream_infos[key] = stream_info
                    twappend("Ready to export PS data (RTP from " .. tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port) 
                            .. " to " .. tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port) .. " write to file:[" .. stream_info.filename .. "] ...")
                end
            end
            return stream_info
        end
        
        -- write a NALU or part of NALU to file.
        local function write_to_file(stream_info, str_bytes, type)
            if first_run then
                stream_info.counter = stream_info.counter + 1
                
                -- save SPS or PPS
                if ((str_bytes:byte(0,1)==0x00) and (str_bytes:byte(1,1)==0x00)
                    and (str_bytes:byte(2,1)==0x00) and (str_bytes:byte(3,1)==0x01)) then
                    if "H.264"==type then
                        local nalu_type = bit.band(str_bytes:byte(4,1), 0x1F)
                        if not stream_info.sps and nalu_type == 7 then
                            stream_info.sps = str_bytes
                        elseif not stream_info.pps and nalu_type == 8 then
                            stream_info.pps = str_bytes
                        end
                    elseif "H.265"==type then
                        local nalu_type = bit.rshift(bit.band(str_bytes:byte(1,1), 0x7e),1)
                        if not stream_info.sps and nalu_type == 33 then
                            stream_info.sps = str_bytes
                        elseif not stream_info.pps and nalu_type == 34 then
                            stream_info.pps = str_bytes
                        end
                    end
                end
                
            else -- second time running
                
                if stream_info.counter2 == 0 then
                    -- write SPS and PPS to file header first
                    if stream_info.sps then
                        stream_info.file:write(stream_info.sps)
                    else
                        twappend("Not found SPS for [" .. stream_info.filename .. "], it might not be played!")
                    end
                    if stream_info.pps then
                        stream_info.file:write(stream_info.pps)
                    else
                        twappend("Not found PPS for [" .. stream_info.filename .. "], it might not be played!")
                    end
                end
            
                stream_info.file:write(str_bytes)
                stream_info.counter2 = stream_info.counter2 + 1

                -- update progress window's progress bar
                if stream_info.counter > 0 and stream_info.counter2 < stream_info.counter then
                    pgtw:update(stream_info.counter2 / stream_info.counter)
                end
            end
        end
        
        -- call this function if a packet contains ps payload
        function my_ps_tap.packet(pinfo,tvb)
            if stream_infos == nil then
                -- not triggered by button event, so do nothing.
                return
            end
            local datas = { f_pes_data() } -- using table because one packet may contains more than one RTP
            
            for i,data_f in ipairs(datas) do
                if data_f.len < 5 then
                    return
                end
                local data = data_f.range:bytes()
                local stream_info = get_stream_info(pinfo)
                if stream_info then
                    write_to_file(stream_info, data:tvb():raw(), stream_info.streamtype)
                end
            end
        end
        
        -- close all open files
        local function close_all_files()
            twappend("")
            local index = 0;
            if stream_infos then
                local no_streams = true
                for id,stream in pairs(stream_infos) do
                    if stream and stream.file then
                        stream.file:flush()
                        stream.file:close()
                        stream.file = nil
                        index = index + 1
                        twappend(index .. ": [" .. stream.filename .. "] generated OK!")
                        local anony_fuc = function()
                            twappend("ffplay -x 640 -autoexit "..stream.filename)
                            os.execute("ffplay -x 640 -autoexit "..stream.filename)
                        end
                        tw:add_button("Play "..index, anony_fuc)
                        no_streams = false
                    end
                end
                
                if no_streams then
                    twappend("Not found any PS over RTP streams!")
                end
            end
        end
        
        function my_ps_tap.reset()
            -- do nothing now
        end
        
        local function remove()
            my_ps_tap:remove()
        end
        
        tw:set_atclose(remove)
        
        local function export_data()
            pgtw = ProgDlg.new("Export PS to File Process", "Dumping PS data to file...")
            first_run = true
            stream_infos = {}
            -- first time it runs for counting ps packets and finding SPS and PPS
            retap_packets()
            first_run = false
            -- second time it runs for saving ps data to target file.
            retap_packets()
            close_all_files()
            -- close progress window
            pgtw:close()
            stream_infos = nil
        end
        
        local function export_all()
            export_data()
        end
        
        tw:add_button("Export All", export_all)
    end

    local function dialog_func(str)
        filter_string = str
        export_data_to_file()
    end

    local function dialog_menu()
        new_dialog("Filter Dialog",dialog_func,"Filter")
    end
    
    -- Find this feature in menu "Tools"
    register_menu("Video/Export PS", dialog_menu, MENU_TOOLS_UNSORTED)
end
