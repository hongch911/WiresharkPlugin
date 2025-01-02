-- Dump RTP h.265 payload to raw h.265 file (*.265)
-- According to RFC7798 to dissector H265 payload of RTP to NALU, and write it
-- to from<sourceIp_sourcePort>to<dstIp_dstPort>.265 file. 
-- By now, we support Single NAL Unit Packets, Aggregation Packets (APs)
-- and Fragmentation Units (FUs) format RTP payload for H.265.
-- You can access this feature by menu "Tools"
-- Reference from Huang Qiangxiong (qiangxiong.huang@gmail.com)
-- Author: Yang Xing (hongch_911@126.com)
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

    -- for geting h265 data (the field's value is type of ByteArray)
    local f_h265 = Field.new("h265") 
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

    -- menu action. When you click "Tools->Export H265 to file" will run this function
    local function export_h265_to_file()
        -- window for showing information
        local tw = TextWindow.new("Export H265 to File Info Win")
        local pgtw;
        
        -- add message to information window
        function twappend(str)
            tw:append(str)
            tw:append("\n")
        end
        
        local ffmpeg_path = get_ffmpeg_path()
        -- temp path
        local temp_path = get_temp_path()
        
        -- running first time for counting and finding vps+sps+pps, second time for real saving (to string),
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

        -- trigered by all h265 packats
        local list_filter = and_filter("h265")
        twappend("Listener filter: " .. list_filter .. "\n")
        local my_h265_tap = Listener.new("frame", list_filter)

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
                stream_info.filename = key.. ".265"
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
                stream_info.counter = 0 -- counting h265 total NALUs
                stream_info.counter2 = 0 -- for second time running
                stream_infos[key] = stream_info
                twappend("Ready to export H.265 data (RTP from " .. tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port) 
                         .. " to " .. tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port) .. " write to file:[" .. stream_info.filename .. "] ...")
            end
            return stream_info
        end
        
        -- write a NALU or part of NALU to file.
        local function write_to_file(pkts, stream_info, rtp_seq, str_bytes, begin_with_nalu_hdr, end_of_nalu)
            if first_run then
                stream_info.counter = stream_info.counter + 1
                
                if begin_with_nalu_hdr then
                    -- save VPS SPS PPS
                    local nalu_type = bit.rshift(bit.band(str_bytes:byte(0,1), 0x7e),1)
                    if not stream_info.vps and nalu_type == 32 then
                        stream_info.vps = str_bytes
                    elseif not stream_info.sps and nalu_type == 33 then
                        stream_info.sps = str_bytes
                    elseif not stream_info.pps and nalu_type == 34 then
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
                    local nalu_type = bit.rshift(bit.band(str_bytes:byte(0,1), 0x7e),1)
                    if nalu_type ~= 32 then
                        -- write VPS SPS and PPS to file header first
                        if stream_info.vps then
                            pkts[rtp_seq]["stream_data"] = pkts[rtp_seq]["stream_data"].."\x00\x00\x00\x01"..stream_info.vps
                        else
                            twappend("Not found VPS for [" .. stream_info.filename .. "], it might not be played!")
                        end
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
                    -- *.265 raw file format seams that every nalu start with 0x00000001
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
        
        -- read RFC3984 about single nalu/ap/fu H265 payload format of rtp
        -- single NALU: one rtp payload contains only NALU
        local function process_single_nalu(pkts, stream_info, rtp_seq, h265tvb)
            write_to_file(pkts, stream_info, rtp_seq, h265tvb:raw(), true, true)
        end
        
        -- APs: one rtp payload contains more than one NALUs
        local function process_ap(pkts, stream_info, rtp_seq, h265tvb)
            local offset = 2
            repeat
                local size = h265tvb(offset,2):uint()
                write_to_file(pkts, stream_info, rtp_seq, h265tvb:raw(offset+2, size), true, true)
                offset = offset + 2 + size
            until offset >= h265tvb:len()
        end
        
        -- FUs: one rtp payload contains only one part of a NALU (might be begin, middle and end part of a NALU)
        local function process_fu(pkts, stream_info, rtp_seq, h265tvb)
            local start_of_nalu = (h265tvb:range(2, 1):bitfield(0, 1) ~= 0)
            local end_of_nalu =  (h265tvb:range(2, 1):bitfield(1, 1) ~= 0)
            if start_of_nalu then
                -- start bit is set then save nalu header and body
                local nalu_hdr_0 = bit.bor(bit.band(h265tvb:bytes(0, 3):get_index(0), 0x81), bit.lshift(bit.band(h265tvb:bytes(0, 3):get_index(2), 0x3F), 1))
                local nalu_hdr_1 = h265tvb:bytes(0, 3):get_index(1)
                write_to_file(pkts, stream_info, rtp_seq, string.char(nalu_hdr_0, nalu_hdr_1) .. h265tvb:raw(3), start_of_nalu, end_of_nalu)
            else
                -- start bit not set, just write part of nalu body
                write_to_file(pkts, stream_info, rtp_seq, h265tvb:raw(3), start_of_nalu, end_of_nalu)
            end
        end
        
        -- call this function if a packet contains h265 payload
        function my_h265_tap.packet(pinfo,tvb)
            if stream_infos == nil then
                -- not triggered by button event, so do nothing.
                return
            end
            local h265s = { f_h265() } -- using table because one packet may contains more than one RTP
            
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

            for i,h265_f in ipairs(h265s) do
                if h265_f.len < 5 then
                    return
                end
                local h265 = h265_f.range:bytes() 
                local hdr_type = h265_f.range(0,1):bitfield(1,6)
                local stream_info = get_stream_info(pinfo)

                if hdr_type > 0 and hdr_type < 48 then
                    -- Single NALU
                    process_single_nalu(rtp_pkts, stream_info, rtp_seq, h265:tvb())
                elseif hdr_type == 48 then
                    -- APs
                    process_ap(rtp_pkts, stream_info, rtp_seq, h265:tvb())
                elseif hdr_type == 49 then
                    -- FUs
                    process_fu(rtp_pkts, stream_info, rtp_seq, h265:tvb())
                else
                    twappend("Error: No.=" .. tostring(pinfo.number) .. " unknown type=" .. hdr_type .. " ; we only know 1-47(Single NALU),48(APs),49(FUs)!")
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

            local h265tvb = payload(2, payload:len() - 2)
            local hdr_type = h265tvb:range(0, 1):bitfield(1, 6)
            local stream_info = get_stream_info(pinfo)

            if hdr_type > 0 and hdr_type < 48 then
                -- Single NALU
                process_single_nalu(rtx_pkts, stream_info, osn, h265tvb)
            elseif hdr_type == 48 then
                -- APs
                process_ap(rtx_pkts, stream_info, osn, h265tvb)
            elseif hdr_type == 49 then
                -- FUs
                process_fu(rtx_pkts, stream_info, osn, h265tvb)
            else
                twappend("Error: No.=" .. tostring(pinfo.number) .. " unknown type=" .. hdr_type .. " ; we only know 1-47(Single NALU),48(APs),49(FUs)!")
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
                    twappend("Not found any H.265 over RTP streams!")
                else
                    tw:add_button("Browser", function () browser_open_data_file(temp_path) end)
                end
            end
        end
        
        function my_h265_tap.reset()
            -- do nothing now
        end

        function rtx_tap.reset()
            -- do nothing now
        end

        tw:set_atclose(function ()
            my_h265_tap:remove()
            rtx_tap:remove()
            if Dir.exists(temp_path) then
                Dir.remove_all(temp_path)
            end
        end)
        
        local function export_h265()
            pgtw = ProgDlg.new("Export H265 to File Process", "Dumping H265 data to file...")
            first_run = true
            stream_infos = {}
            -- first time it runs for counting h.265 packets and finding SPS and PPS
            retap_packets()
            first_run = false
            -- second time it runs for saving h265 data to target file.
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
            export_h265()
        end)

        tw:add_button("Set Filter", function ()
            tw:close()
            dialog_menu()
        end)
    end

    local function dialog_func(str)
        filter_string = str
        export_h265_to_file()
    end

    function dialog_menu()
        new_dialog("Filter Dialog",dialog_func,"Filter")
    end

    local function dialog_default()
        filter_string = get_filter()
        export_h265_to_file()
    end
    
    -- Find this feature in menu "Tools"
    register_menu("Video/Export H265", dialog_default, MENU_TOOLS_UNSORTED)
end
