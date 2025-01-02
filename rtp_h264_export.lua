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
    -- lua>=5.4 直接使用位操作
	-- 使用bit32进行位操作
	if (version_num >= 5.4) then
	   local function band(a,b)
		  return(a&b)
	   end

	   local function bor(a,b)
		  return(a|b)
	   end

	   local function lshift(a,b)
		  return(a<<b)
	   end
	else
	   local bit = (version_num >= 5.2) and require("bit32") or require("bit")
	end

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
    local f_rtp_payload = Field.new("rtp.payload")

    local filter_string = nil

    local function and_filter(proto)
        local list_filter = ''
        if filter_string == nil or filter_string == '' then
            list_filter = proto
        elseif string.find(filter_string, proto) ~= nil then
            list_filter = filter_string
        else
            list_filter = proto .. " && " .. filter_string
        end
        return list_filter
    end

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
        local rtp_seq_base = 0
        local last_rtp_seq = -1

        local rtx_pkts = {}
        local osn_base = 0
        local last_osn = -1

        -- trigered by all h264 packats
        local list_filter = and_filter("h264")
        twappend("Listener filter: " .. list_filter .. "\n")
        local my_h264_tap = Listener.new("frame", list_filter)

        local rtx_tap = Listener.new("frame", and_filter("rtx"))

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
        local function write_to_file(pkts, stream_info, rtp_seq, str_bytes, begin_with_nalu_hdr, end_of_nalu)
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
                        twappend("discard pkt " .. tostring(pkts[rtp_seq]["pkt_num"]) .. " rtp seq " .. tostring(rtp_seq))
                        return
                    end
                end
                
                if stream_info.counter2 == 0 then
                    local nalu_type = bit.band(str_bytes:byte(0,1), 0x1F)
                    if nalu_type ~= 7 then
                        -- write SPS and PPS to file header first
                        if stream_info.sps then
                            pkts[rtp_seq]["stream_data"] = pkts[rtp_seq]["stream_data"].."\x00\x00\x00\x01"..stream_info.sps
                        else
                            twappend("Not found SPS for [" .. stream_info.filename .. "], it might not be played!")
                        end
                        if stream_info.pps then
                            pkts[rtp_seq]["stream_data"] = pkts[rtp_seq]["stream_data"].."\x00\x00\x00\x01"..stream_info.pps
                        else
                            twappend("Not found PPS for [" .. stream_info.filename .. "], it might not be played!")
                        end
                    end
                end

                if begin_with_nalu_hdr then
                    -- *.264 raw file format seams that every nalu start with 0x00000001
                    pkts[rtp_seq]["stream_data"] = pkts[rtp_seq]["stream_data"].."\x00\x00\x00\x01"
                end
                pkts[rtp_seq]["stream_data"] = pkts[rtp_seq]["stream_data"]..str_bytes
                stream_info.counter2 = stream_info.counter2 + 1

                -- update progress window's progress bar
                if stream_info.counter > 0 and stream_info.counter2 < stream_info.counter then
                    pgtw:update(stream_info.counter2 / stream_info.counter)
                end
            end
        end
        
        -- read RFC3984 about single nalu/stap-a/fu-a H264 payload format of rtp
        -- single NALU: one rtp payload contains only NALU
        local function process_single_nalu(pkts, stream_info, rtp_seq, h264tvb)
            write_to_file(pkts, stream_info, rtp_seq, h264tvb:raw(), true, true)
        end
        
        -- STAP-A: one rtp payload contains more than one NALUs
        local function process_stap_a(pkts, stream_info, rtp_seq, h264tvb)
            local offset = 1
            repeat
                local size = h264tvb(offset,2):uint()
                write_to_file(pkts, stream_info, rtp_seq, h264tvb:raw(offset+2, size), true, true)
                offset = offset + 2 + size
            until offset >= h264tvb:len()
        end
        
        -- FU-A: one rtp payload contains only one part of a NALU (might be begin, middle and end part of a NALU)
        local function process_fu_a(pkts, stream_info, rtp_seq, h264tvb)
            local fu_idr = h264tvb:bytes(0, 2):get_index(0)
            local fu_hdr = h264tvb:bytes(0, 2):get_index(1)
            local end_of_nalu =  (bit.band(fu_hdr, 0x40) ~= 0)
            if bit.band(fu_hdr, 0x80) ~= 0 then
                -- start bit is set then save nalu header and body
                local nalu_hdr = bit.bor(bit.band(fu_idr, 0xE0), bit.band(fu_hdr, 0x1F))
                write_to_file(pkts, stream_info, rtp_seq, string.char(nalu_hdr) .. h264tvb:raw(2), true, end_of_nalu)
            else
                -- start bit not set, just write part of nalu body
                write_to_file(pkts, stream_info, rtp_seq, h264tvb:raw(2), false, end_of_nalu)
            end
        end
        
        -- call this function if a packet contains h264 payload
        function my_h264_tap.packet(pinfo,tvb)
            if stream_infos == nil then
                -- not triggered by button event, so do nothing.
                return
            end
            local h264s = { f_h264() } -- using table because one packet may contains more than one RTP

            -- we will create a new dict here, so if packets are duplicated, only the last one would be saved
            local rtp_pkt = {}
            rtp_pkt["rtp_timestamp"] = f_rtp_timestamp().value
            rtp_pkt["stream_info_key"] = get_stream_info_key(pinfo)
            rtp_pkt["pkt_num"] = pinfo.number
            rtp_pkt["stream_data"] = ""
            local rtp_seq = f_rtp_seq().value

            if last_rtp_seq ~= -1 and last_rtp_seq - rtp_seq > 50000 then
                rtp_seq_base = rtp_seq_base + 65536
            end
            last_rtp_seq = rtp_seq
            rtp_seq = rtp_seq + rtp_seq_base

            if min_rtp_seq == -1 or rtp_seq < min_rtp_seq then
                min_rtp_seq = rtp_seq
            end
            if max_rtp_seq == -1 or rtp_seq > max_rtp_seq then
                max_rtp_seq = rtp_seq
            end
            if first_run and rtp_pkts[rtp_seq] ~= nil then
                twappend("dup rtp seq " .. tostring(rtp_seq) .. ", pkt num " .. tostring(pinfo.number) .. ", prev pkt num " .. tostring(rtp_pkts[rtp_seq]["pkt_num"]))
            end
            rtp_pkts[rtp_seq] = rtp_pkt

            for i,h264_f in ipairs(h264s) do
                if i > 1 then
                    -- stap-a will contain more than 1 h264_f, but the first one will contain all data
                    return
                end
                local h264 = h264_f.range:bytes() 
                local hdr_type = bit.band(h264:get_index(0), 0x1F)
                local stream_info = get_stream_info(pinfo)
                
                if hdr_type > 0 and hdr_type < 24 then
                    -- Single NALU
                    process_single_nalu(rtp_pkts, stream_info, rtp_seq, h264:tvb())
                elseif hdr_type == 24 then
                    -- STAP-A Single-time aggregation
                    process_stap_a(rtp_pkts, stream_info, rtp_seq, h264:tvb())
                elseif hdr_type == 28 then
                    -- FU-A
                    process_fu_a(rtp_pkts, stream_info, rtp_seq, h264:tvb())
                else
                    twappend("Error: No.=" .. tostring(pinfo.number) .. " unknown type=" .. hdr_type .. " ; we only know 1-23(Single NALU),24(STAP-A),28(FU-A)!")
                end
            end
        end

        -- call this function if a packet contains rtx payload
        function rtx_tap.packet(pinfo, tvb)
            local f_num = pinfo.number
            local payload = f_rtp_payload().range:bytes():tvb()
            local osn = payload(0, 2):uint()

            if last_osn ~= -1 and last_osn - osn > 50000 then
                osn_base = osn_base + 65536
            end
            last_osn = osn
            osn = osn + osn_base

            local rtp_pkt = {}
            rtp_pkt["rtp_timestamp"] = f_rtp_timestamp().value
            rtp_pkt["stream_info_key"] = get_stream_info_key(pinfo)
            rtp_pkt["pkt_num"] = pinfo.number
            rtp_pkt["stream_data"] = ""

            rtx_pkts[osn] = rtp_pkt

            local h264tvb = payload(2, payload:len() - 2)
            local hdr_type = bit.band(h264tvb:bytes(0, 1):get_index(0), 0x1F)
            local stream_info = get_stream_info(pinfo)

            if hdr_type > 0 and hdr_type < 24 then
                -- Single NALU
                process_single_nalu(rtx_pkts, stream_info, osn, h264tvb)
            elseif hdr_type == 24 then
                -- STAP-A Single-time aggregation
                process_stap_a(rtx_pkts, stream_info, osn, h264tvb)
            elseif hdr_type == 28 then
                -- FU-A
                process_fu_a(rtx_pkts, stream_info, osn, h264tvb)
            else
                twappend("Error: No.=" .. tostring(pinfo.number) .. " unknown type=" .. hdr_type .. " ; we only know 1-23(Single NALU),24(STAP-A),28(FU-A)!")
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

        function rtx_tap.reset()
            -- do nothing now
        end

        tw:set_atclose(function ()
            my_h264_tap:remove()
            rtx_tap:remove()
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

            for rtp_seq = min_rtp_seq, max_rtp_seq do
                local rtp_pkt = rtp_pkts[rtp_seq]
                if rtp_pkt ~= nil then
                    local stream_info = stream_infos[rtp_pkt["stream_info_key"]]
                    stream_info.file:write(rtp_pkt["stream_data"])
                else
                    local rtx_pkt = rtx_pkts[rtp_seq]
                    if rtx_pkt ~= nil then
                        twappend("rtp packet lost but got rtx " .. tostring(rtp_seq))
                        local stream_info = stream_infos[rtx_pkt["stream_info_key"]]
                        stream_info.file:write(rtx_pkt["stream_data"])
                    else
                        twappend("rtp packet lost " .. tostring(rtp_seq))
                    end
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
