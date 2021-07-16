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
    function get_ffmpeg_path()
        local tmp = nil
        if tmp == nil or tmp == '' then
            tmp = os.getenv('FFMPEG')
            if tmp == nil or tmp == '' then
                tmp = ""
            else
                if not string.ends(tmp, "/bin/") then
                    tmp = tmp .. "/bin/"
                end
            end
        end
        return tmp
    end

    -- for geting ps data (the field's value is type of ByteArray)
    local f_ps = Field.new("ps")

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
        
        local ffmpeg_path = get_ffmpeg_path()
        -- temp path
        local temp_path = get_temp_path()
        
        -- running first time for counting and finding sps+pps, second time for real saving
        local first_run = true 
        -- variable for storing rtp stream and dumping parameters
        local stream_infos = nil

        -- trigered by all ps packats
        local list_filter = ''
        if filter_string == nil or filter_string == '' then
            list_filter = "ps"
        elseif string.find(filter_string,"ps")~=nil then
            list_filter = filter_string
        else
            list_filter = "ps && "..filter_string
        end
        twappend("Listener filter: " .. list_filter .. "\n")
        local my_ps_tap = Listener.new("frame", list_filter)
        
        -- get rtp stream info by src and dst address
        function get_stream_info(pinfo)
            local key = "from_" .. tostring(pinfo.src) .. "_" .. tostring(pinfo.src_port) .. "_to_" .. tostring(pinfo.dst) .. "_" .. tostring(pinfo.dst_port)
            key = key:gsub(":", ".")
            local stream_info = stream_infos[key]
            if not stream_info then -- if not exists, create one
                stream_info = { }
                stream_info.filename = key.. ".ps"
                -- stream_info.filepath = stream_info.filename
                -- stream_info.file,msg = io.open(stream_info.filename, "wb")
                if not Dir.exists(temp_path) then
                    Dir.make(temp_path)
                end
                stream_info.filepath = temp_path.."/"..stream_info.filename
                stream_info.file,msg = io.open(temp_path.."/"..stream_info.filename, "wb")
                if msg then
                    twappend("io.open "..stream_info.filepath..", error "..msg)
                end
                -- twappend("Output file path:" .. stream_info.filepath)
                stream_info.counter = 0 -- counting ps total NALUs
                stream_info.counter2 = 0 -- for second time running
                stream_infos[key] = stream_info
                twappend("Ready to export PS data (RTP from " .. tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port) 
                         .. " to " .. tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port) .. " write to file:[" .. stream_info.filename .. "] ...")
            end
            return stream_info
        end
        
        -- write a NALU or part of NALU to file.
        local function write_to_file(stream_info, str_bytes)
            if first_run then
                stream_info.counter = stream_info.counter + 1
                
            else -- second time running
                
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
            local datas = { f_ps() } -- using table because one packet may contains more than one RTP
            
            for i,data_f in ipairs(datas) do
                -- if data_f.len < 5 then
                --     return
                -- end
                local data = data_f.range:bytes()
                local stream_info = get_stream_info(pinfo)
                if stream_info then
                    write_to_file(stream_info, data:tvb():raw())
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
                        local anony_fuc = function ()
                            twappend("ffplay -x 640 -y 640 -autoexit "..stream.filename)
                            --copy_to_clipboard("ffplay -x 640 -y 640 -autoexit "..stream.filepath)
                            os.execute(ffmpeg_path.."ffplay -x 640 -y 640 -autoexit "..stream.filepath)
                        end
                        tw:add_button("Play "..index, anony_fuc)
                        no_streams = false
                    end
                end
                
                if no_streams then
                    twappend("Not found any PS over RTP streams!")
                else
                    tw:add_button("Browser", function () browser_open_data_file(temp_path) end)
                end
            end
        end
        
        function my_ps_tap.reset()
            -- do nothing now
        end
        
        tw:set_atclose(function ()
            my_ps_tap:remove()
            if Dir.exists(temp_path) then
                Dir.remove_all(temp_path)
            end
        end)
        
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
    register_menu("Video/Export PS", dialog_default, MENU_TOOLS_UNSORTED)
end
