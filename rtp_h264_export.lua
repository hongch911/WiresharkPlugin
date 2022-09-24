-- Dump RTP h.264 payload to raw h.264 file (*.264)
-- According to RFC3984 to dissector H264 payload of RTP to NALU, and write it
-- to from<sourceIp_sourcePort>to<dstIp_dstPort>.264 file. By now, we support single NALU,
-- STAP-A and FU-A format RTP payload for H.264.
-- You can access this feature by menu "Tools"
-- Author: Huang Qiangxiong (qiangxiong.huang@gmail.com)
-- Modify by Yang Xing (hongch_911@126.com)
------------------------------------------------------------------------------------------------
do
    local version_str = string.match(_VERSION, "%d+[.]%d*")
    local version_num = version_str and tonumber(version_str) or 5.1
    local bit = (version_num >= 5.2) and require("bit32") or require("bit")

    function string.starts(String,Start)
        return string.sub(String,1,string.len(Start))==Start
     end
     
     function string.ends(String,End)
        return End=='' or string.sub(String,-string.len(End))==End
     end
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

    -- for geting h264 data (the field's value is type of ByteArray)
    local f_h264 = Field.new("h264") 
    local f_rtp = Field.new("rtp") 
    local f_rtp_seq = Field.new("rtp.seq")
    local f_rtp_timestamp = Field.new("rtp.timestamp")

    local filter_string = nil

    -- menu action. When you click "Tools->Export H264 to file" will run this function
    local function export_h264_to_file()
        -- window for showing information
        local tw = TextWindow.new("Export H264 to File Info Win")
        local pgtw;
        
        -- add message to information window
        function twappend(str)
            tw:append(str)
            tw:append("\n")
        end
        
        local ffmpeg_path = get_ffmpeg_path()
        -- temp path
        local temp_path = get_temp_path()
        
        -- running first time for counting and finding sps+pps, second time for real saving (to string),
        -- will write to file on third time.
        local first_run = true 
        local writed_nalu_begin = false
        -- variable for storing rtp stream and dumping parameters
        local stream_infos = nil

        local rtp_pkts = {}
        local min_rtp_seq = -1
        local max_rtp_seq = -1

        -- trigered by all h264 packats
        local list_filter = ''
        if filter_string == nil or filter_string == '' then
            list_filter = "h264"
        elseif string.find(filter_string,"h264")~=nil then
            list_filter = filter_string
        else
            list_filter = "h264 && "..filter_string
        end
        twappend("Listener filter: " .. list_filter .. "\n")
        local my_h264_tap = Listener.new("frame", list_filter)
        
        function get_stream_info_key(pinfo)
            local key = "from_" .. tostring(pinfo.src) .. "_" .. tostring(pinfo.src_port) .. "_to_" .. tostring(pinfo.dst) .. "_" .. tostring(pinfo.dst_port)
            key = key:gsub(":", ".")
            return key
        end

        -- get rtp stream info by src and dst address
        function get_stream_info(pinfo)
            local key = get_stream_info_key(pinfo)
            local stream_info = stream_infos[key]
            if not stream_info then -- if not exists, create one
                stream_info = { }
                stream_info.filename = key.. ".264"
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
                stream_info.counter = 0 -- counting h264 total NALUs
                stream_info.counter2 = 0 -- for second time running
                stream_infos[key] = stream_info
                twappend("Ready to export H.264 data (RTP from " .. tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port) 
                         .. " to " .. tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port) .. " write to file:[" .. stream_info.filename .. "] ...")
            end
            return stream_info
        end
        
        -- write a NALU or part of NALU to file.
        local function write_to_file(stream_info, rtp_seq, str_bytes, begin_with_nalu_hdr, end_of_nalu)
            if first_run then
                stream_info.counter = stream_info.counter + 1
                
                if begin_with_nalu_hdr then
                    -- save SPS PPS
                    local nalu_type = bit.band(str_bytes:byte(0,1), 0x1F)
                    if not stream_info.sps and nalu_type == 7 then
                        stream_info.sps = str_bytes
                    elseif not stream_info.pps and nalu_type == 8 then
                        stream_info.pps = str_bytes
                    end
                end
            else -- second time running
                if not writed_nalu_begin then
                    if begin_with_nalu_hdr then
                        writed_nalu_begin = true
                    else
                        return
                    end
                end
                
                if stream_info.counter2 == 0 then
                    local nalu_type = bit.band(str_bytes:byte(0,1), 0x1F)
                    if nalu_type ~= 7 then
                        -- write SPS and PPS to file header first
                        if stream_info.sps then
                            rtp_pkts[rtp_seq]["stream_data"] = rtp_pkts[rtp_seq]["stream_data"].."\x00\x00\x00\x01"..stream_info.sps
                        else
                            twappend("Not found SPS for [" .. stream_info.filename .. "], it might not be played!")
                        end
                        if stream_info.pps then
                            rtp_pkts[rtp_seq]["stream_data"] = rtp_pkts[rtp_seq]["stream_data"].."\x00\x00\x00\x01"..stream_info.pps
                        else
                            twappend("Not found PPS for [" .. stream_info.filename .. "], it might not be played!")
                        end
                    end
                end
            
                if begin_with_nalu_hdr then
                    -- *.264 raw file format seams that every nalu start with 0x00000001
                    rtp_pkts[rtp_seq]["stream_data"] = rtp_pkts[rtp_seq]["stream_data"].."\x00\x00\x00\x01"
                end
                rtp_pkts[rtp_seq]["stream_data"] = rtp_pkts[rtp_seq]["stream_data"]..str_bytes
                stream_info.counter2 = stream_info.counter2 + 1

                -- update progress window's progress bar
                if stream_info.counter > 0 and stream_info.counter2 < stream_info.counter then
                    pgtw:update(stream_info.counter2 / stream_info.counter)
                end
            end
        end
        
        -- read RFC3984 about single nalu/stap-a/fu-a H264 payload format of rtp
        -- single NALU: one rtp payload contains only NALU
        local function process_single_nalu(stream_info, rtp_seq, h264)
            write_to_file(stream_info, rtp_seq, h264:tvb():raw(), true, true)
        end
        
        -- STAP-A: one rtp payload contains more than one NALUs
        local function process_stap_a(stream_info, rtp_seq, h264)
            local h264tvb = h264:tvb()
            local offset = 1
            repeat
                local size = h264tvb(offset,2):uint()
                write_to_file(stream_info, rtp_seq, h264tvb:raw(offset+2, size), true, true)
                offset = offset + 2 + size
            until offset >= h264tvb:len()
        end
        
        -- FU-A: one rtp payload contains only one part of a NALU (might be begin, middle and end part of a NALU)
        local function process_fu_a(stream_info, rtp_seq, h264)
            local h264tvb = h264:tvb()
            local fu_idr = h264:get_index(0)
            local fu_hdr = h264:get_index(1)
            local end_of_nalu =  (bit.band(fu_hdr, 0x40) ~= 0)
            if bit.band(fu_hdr, 0x80) ~= 0 then
                -- start bit is set then save nalu header and body
                local nalu_hdr = bit.bor(bit.band(fu_idr, 0xE0), bit.band(fu_hdr, 0x1F))
                write_to_file(stream_info, rtp_seq, string.char(nalu_hdr) .. h264tvb:raw(2), true, end_of_nalu)
            else
                -- start bit not set, just write part of nalu body
                write_to_file(stream_info, rtp_seq, h264tvb:raw(2), false, end_of_nalu)
            end
        end
        
        -- call this function if a packet contains h264 payload
        function my_h264_tap.packet(pinfo,tvb)
            if stream_infos == nil then
                -- not triggered by button event, so do nothing.
                return
            end
            local h264s = { f_h264() } -- using table because one packet may contains more than one RTP

            local rtp_pkt = {}
            rtp_pkt["rtp_timestamp"] = f_rtp_timestamp().value
            rtp_pkt["stream_info_key"] = get_stream_info_key(pinfo)
            rtp_pkt["pkt_num"] = pinfo.number
            rtp_pkt["stream_data"] = ""
            local rtp_seq = f_rtp_seq().value
            if min_rtp_seq == -1 or rtp_seq < min_rtp_seq then
                min_rtp_seq = rtp_seq
            end
            if max_rtp_seq == -1 or rtp_seq > max_rtp_seq then
                max_rtp_seq = rtp_seq
            end
            rtp_pkts[rtp_seq] = rtp_pkt

            for i,h264_f in ipairs(h264s) do
                if h264_f.len < 2 then
                    return
                end
                local h264 = h264_f.range:bytes() 
                local hdr_type = bit.band(h264:get_index(0), 0x1F)
                local stream_info = get_stream_info(pinfo)
                
                if hdr_type > 0 and hdr_type < 24 then
                    -- Single NALU
                    process_single_nalu(stream_info, rtp_seq, h264)
                elseif hdr_type == 24 then
                    -- STAP-A Single-time aggregation
                    process_stap_a(stream_info, rtp_seq, h264)
                elseif hdr_type == 28 then
                    -- FU-A
                    process_fu_a(stream_info, rtp_seq, h264)
                else
                    twappend("Error: No.=" .. tostring(pinfo.number) .. " unknown type=" .. hdr_type .. " ; we only know 1-23(Single NALU),24(STAP-A),28(FU-A)!")
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
                    twappend("Not found any H.264 over RTP streams!")
                else
                    tw:add_button("Browser", function () browser_open_data_file(temp_path) end)
                end
            end
        end
        
        function my_h264_tap.reset()
            -- do nothing now
        end
        
        tw:set_atclose(function ()
            my_h264_tap:remove()
            if Dir.exists(temp_path) then
                Dir.remove_all(temp_path)
            end
        end)
        
        local function export_h264()
            pgtw = ProgDlg.new("Export H264 to File Process", "Dumping H264 data to file...")
            first_run = true
            stream_infos = {}
            -- first time it runs for counting h.264 packets and finding SPS and PPS
            retap_packets()
            first_run = false
            -- second time it runs for saving h264 data to target file.
            retap_packets()

            for rtp_seq= min_rtp_seq,max_rtp_seq do
                local rtp_pkt = rtp_pkts[rtp_seq]
                if rtp_pkt ~= nil then
                    local stream_info = stream_infos[rtp_pkt["stream_info_key"]]
                    stream_info.file:write(rtp_pkt["stream_data"])
                end
            end

            close_all_files()
            -- close progress window
            pgtw:close()
            stream_infos = nil
        end
        
        tw:add_button("Export All", function ()
            export_h264()
        end)

        tw:add_button("Set Filter", function ()
            tw:close()
            dialog_menu()
        end)
    end

    local function dialog_func(str)
        filter_string = str
        export_h264_to_file()
    end

    function dialog_menu()
        new_dialog("Filter Dialog",dialog_func,"Filter")
    end

    local function dialog_default()
        filter_string = get_filter()
        export_h264_to_file()
    end
    
    -- Find this feature in menu "Tools"
    register_menu("Video/Export H264", dialog_default, MENU_TOOLS_UNSORTED)
end
