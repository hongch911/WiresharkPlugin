-- Dissector for rtp payload PS
-- According to RFC2250 to dissector payload of RTP to NALU
-- Author: yangxing (hongch_911@126.com)
------------------------------------------------------------------------------------------------
do
    local version_str = string.match(_VERSION, "%d+[.]%d*")
	local version_num = version_str and tonumber(version_str) or 5.1
    local bit = (version_num >= 5.2) and require("bit32") or require("bit")

    local ps_stream_type_vals = {
        [0x0f] = "AAC",
        [0x10] = "MPEG-4 Video",
        [0x1b] = "H.264",
        [0x24] = "H.265",
        [0x80] = "SVAC Video",
        [0x90] = "G.711A",
        [0x91] = "G.711U",
        [0x92] = "G.722.1",
        [0x93] = "G.723.1",
        [0x99] = "G.729",
        [0x9b] = "SVAC Audio",
    }
    local ps_stream_id_vals = {
        [0xbc] = "Program Stream Map",
        [0xbd] = "Private Stream-1",
        [0xbe] = "Padding Stream",
        [0xbf] = "Private Stream-2",
        -- [0xc0 .. 0xdf] = "Audio stream",
        -- [0xe0 .. 0xef] = "Video stream",
        [0xf0] = "ECM Stream",
        [0xf1] = "EMM Stream",
        [0xf2] = "DSMCC Stream",
        [0xf3] = "ISO/IEC 13522 Stream",
        [0xf4] = "ITU-T Rec. H.222.1 Type A",
        [0xf5] = "ITU-T Rec. H.222.1 Type B",
        [0xf6] = "ITU-T Rec. H.222.1 Type C",
        [0xf7] = "ITU-T Rec. H.222.1 Type D",
        [0xf8] = "ITU-T Rec. H.222.1 Type E",
        [0xf9] = "Ancillary Stream",
        [0xff] = "Program Stream Directory",
    }
    for i=0xc0,0xdf do
        ps_stream_id_vals[i] = "Audio stream"
    end
    for i=0xe0,0xef do
        ps_stream_id_vals[i] = "Video stream"
    end
    
    local function get_enum_name(list, index)
        local value = list[index]
        return value and value or string.format("Unknown (%d)",index)
    end
    
    local function get_int64_string(high_int32, low_int32)
        return string.format("%x%x",high_int32,low_int32)
    end
    
    local proto_ps = Proto("ps", "PS")
    
    local ps_hdr = ProtoField.none("ps.pack_header", "PS Header")
    local ps_start_code = ProtoField.bytes("ps.pack_start_code", "Start code", base.SPACE)
    local ps_scr_base = ProtoField.none("ps.scr_base", "SCR base")
    local ps_scr_ext = ProtoField.none("ps.scr_ext", "SCR extension")
    local ps_multiplex_rate = ProtoField.new("Multiplex rate", "ps.multiplex_rate", ftypes.UINT24, nil, base.DEC, 0xfffffc)
    local ps_stuffing_length = ProtoField.new("Stuffing length", "ps.stuffing_length", ftypes.UINT8, nil, base.DEC, 0x07)
    local ps_stuffing_bytes = ProtoField.bytes("ps.stuffing_bytes", "Stuffing bytes")
    
    local ps_system_header = ProtoField.none("ps.system_header", "System Header")
    local ps_system_header_start_code = ProtoField.bytes("ps.system_header.start_code", "Start code", base.SPACE)
    local ps_system_header_length = ProtoField.new("Header length", "ps.system_header.header_length", ftypes.UINT16, nil, base.DEC)
    local ps_system_header_rate_bound = ProtoField.new("Rate bound", "ps.system_header.rate_bound", ftypes.UINT24, nil, base.DEC, 0x7ffffe)
    local ps_system_header_audio_bound = ProtoField.new("Audio bound", "ps.system_header.audio_bound", ftypes.UINT8, nil, base.DEC, 0xfc)
    local ps_system_header_fixed_flag = ProtoField.new("Fixed flag", "ps.system_header.fixed_flag", ftypes.UINT8, nil, base.DEC, 0x02)
    local ps_system_header_CSPS_flag = ProtoField.new("CSPS flag", "ps.system_header.csps_flag", ftypes.UINT8, nil, base.DEC, 0x01)
    local ps_system_header_system_audio_lock_flag = ProtoField.new("System audio lock flag", "ps.system_header.system_audio_lock_flag", ftypes.UINT8, nil, base.DEC, 0x80)
    local ps_system_header_system_video_lock_flag = ProtoField.new("System video lock flag", "ps.system_header.system_video_lock_flag", ftypes.UINT8, nil, base.DEC, 0x40)
    local ps_system_header_vedio_bound = ProtoField.new("Vedio bound", "ps.system_header.vedio_bound", ftypes.UINT8, nil, base.DEC, 0x1f)
    local ps_system_header_packet_rate_restriction_flag = ProtoField.new("Packet rate restriction flag", "ps.system_header.packet_rate_restriction_flag", ftypes.UINT8, nil, base.DEC, 0x80)
    local ps_system_header_stream_id = ProtoField.new("Stream ID", "ps.system_header.stream_id", ftypes.UINT8, ps_stream_id_vals, base.HEX)
    local ps_system_header_P_STD_scale = ProtoField.new("P-STD buffer bound scale", "ps.system_header.buffer_bound_scale", ftypes.UINT16, nil, base.DEC, 0x2000)
    local ps_system_header_P_STD_bound = ProtoField.new("P-STD buffer size bound", "ps.system_header.buffer_size_bound", ftypes.UINT16, nil, base.DEC, 0x1fff)

    local ps_program_stream = ProtoField.none("ps.program_map", "Program Stream Map")
    local ps_program_stream_start_code = ProtoField.bytes("ps.program_map.start_code", "Start code", base.SPACE)
    local ps_program_stream_id = ProtoField.new("Stream ID", "ps.program_map.stream_id", ftypes.UINT8, ps_stream_id_vals, base.HEX)
    local ps_program_stream_length = ProtoField.new("Header length", "ps.program_map.header_length", ftypes.UINT16, nil, base.DEC)
    local ps_program_stream_current_next_indicator = ProtoField.new("Current next indicator", "ps.program_map.current_next_indicator", ftypes.UINT8, nil, base.DEC, 0x80)
    local ps_program_stream_map_version = ProtoField.new("Version", "ps.program_map.version", ftypes.UINT8, nil, base.DEC, 0x1f)
    local ps_program_stream_info_length = ProtoField.new("Info length", "ps.program_map.info_length", ftypes.UINT16, nil, base.DEC)
    local ps_program_stream_map_length = ProtoField.new("Map length", "ps.program_map.map_length", ftypes.UINT16, nil, base.DEC)
    local ps_program_stream_map_stream_type = ProtoField.new("Elementary Stream type", "ps.program_map.map.stream_type", ftypes.UINT8, ps_stream_type_vals, base.DEC)
    local ps_program_stream_map_stream_id = ProtoField.new("Elementary Stream ID", "ps.program_map.map.stream_id", ftypes.UINT8, ps_stream_id_vals, base.HEX)
    local ps_program_stream_map_info_length = ProtoField.new("Elementary Stream info length", "ps.program_map.map.stream_info_length", ftypes.UINT16, nil, base.DEC)
    local ps_program_stream_CRC = ProtoField.bytes("ps.program_map.crc", "CRC", base.SPACE)
    
    local ps_pes = ProtoField.none("ps.pes", "PES Packet")
    local ps_pes_start_code = ProtoField.bytes("ps.pes.start_code", "Start code", base.SPACE)
    local ps_pes_stream_id = ProtoField.new("Stream ID", "ps.pes.stream_id", ftypes.UINT8, ps_stream_id_vals, base.HEX)
    local ps_pes_length = ProtoField.new("Length", "ps.pes.packet_length", ftypes.UINT16, nil, base.DEC)
    local ps_pes_scrambing_control = ProtoField.new("Scrambing control", "ps.pes.scrambing_control", ftypes.UINT8, nil, base.DEC, 0x30)
    local ps_pes_priority = ProtoField.new("Priority", "ps.pes.priority", ftypes.UINT8, nil, base.DEC, 0x08)
    local ps_pes_alignment = ProtoField.new("Alignment", "ps.pes.alignment", ftypes.UINT8, nil, base.DEC, 0x04)
    local ps_pes_copyright = ProtoField.new("Copyright", "ps.pes.copyright", ftypes.UINT8, nil, base.DEC, 0x02)
    local ps_pes_original = ProtoField.new("Original", "ps.pes.original", ftypes.UINT8, nil, base.DEC, 0x01)
    local ps_pes_pts_dts_flag = ProtoField.new("PTS DTS flag", "ps.pes.pts_dts_flag", ftypes.UINT8, nil, base.DEC, 0xc0)
    local ps_pes_escr_flag = ProtoField.new("ESCR flag", "ps.pes.escr_flag", ftypes.UINT8, nil, base.DEC, 0x20)
    local ps_pes_es_rate_flag = ProtoField.new("ES rate flag", "ps.pes.es_rate_flag", ftypes.UINT8, nil, base.DEC, 0x10)
    local ps_pes_dsm_trick_mode_flag = ProtoField.new("DSM trick mode flag", "ps.pes.dsm_trick_mode_flag", ftypes.UINT8, nil, base.DEC, 0x08)
    local ps_pes_additional_info_flag = ProtoField.new("Additional info flag", "ps.pes.additional_info_flag", ftypes.UINT8, nil, base.DEC, 0x04)
    local ps_pes_crc_flag = ProtoField.new("CRC flag", "ps.pes.crc_flag", ftypes.UINT8, nil, base.DEC, 0x02)
    local ps_pes_extension_flag = ProtoField.new("Extension flag", "ps.pes.extension_flag", ftypes.UINT8, nil, base.DEC, 0x01)
    local ps_pes_header_data_length = ProtoField.new("Header Data Length", "ps.pes.header_data_length", ftypes.UINT8, nil, base.DEC)
    local ps_pes_header_data_bytes = ProtoField.bytes("ps.pes.header_data_bytes", "Header Data bytes", base.SPACE)
    local ps_pes_pts = ProtoField.none("ps.pes.pts", "PTS")
    local ps_pes_dts = ProtoField.none("ps.pes.dts", "DTS")
    local ps_pes_escr = ProtoField.none("ps.pes.escr", "ESCR")
    local ps_pes_es_rate = ProtoField.none("ps.pes.es_rate", "ES rate")
    local ps_pes_dsm_trick_mode = ProtoField.new("DSM trick mode", "ps.pes.dsm_trick_mode", ftypes.UINT8, nil, base.HEX)
    local ps_pes_additional_info = ProtoField.new("Copyright Info", "ps.pes.additional_info", ftypes.UINT8, nil, base.HEX)
    local ps_pes_crc = ProtoField.new("CRC", "ps.pes.crc", ftypes.UINT16, nil, base.HEX)
    local ps_pes_extension = ProtoField.new("Extension", "ps.pes.extension", ftypes.UINT8, nil, base.HEX)
    local ps_pes_data_bytes = ProtoField.bytes("ps.pes.data_bytes", "Data bytes")
    -- local ps_data = ProtoField.bytes("ps.data", "Data")
    
    proto_ps.fields = {
        ps_hdr,ps_start_code,ps_scr_base,ps_scr_ext,ps_multiplex_rate,ps_stuffing_length,ps_stuffing_bytes,
        ps_system_header,ps_system_header_start_code,ps_system_header_length,ps_system_header_rate_bound,ps_system_header_audio_bound,ps_system_header_fixed_flag,ps_system_header_CSPS_flag,ps_system_header_system_audio_lock_flag,ps_system_header_system_video_lock_flag,ps_system_header_vedio_bound,ps_system_header_packet_rate_restriction_flag,ps_system_header_stream_id,ps_system_header_P_STD_scale,ps_system_header_P_STD_bound,
        ps_program_stream,ps_program_stream_start_code,ps_program_stream_id,ps_program_stream_length,ps_program_stream_current_next_indicator,ps_program_stream_map_version,ps_program_stream_info_length,ps_program_stream_map_length,ps_program_stream_map_stream_type,ps_program_stream_map_stream_id,ps_program_stream_map_info_length,ps_program_stream_CRC,
        ps_pes,ps_pes_start_code,ps_pes_stream_id,ps_pes_length,ps_pes_scrambing_control,ps_pes_priority,ps_pes_alignment,ps_pes_copyright,ps_pes_original,ps_pes_pts_dts_flag,ps_pes_escr_flag,ps_pes_es_rate_flag,ps_pes_dsm_trick_mode_flag,ps_pes_additional_info_flag,ps_pes_crc_flag,ps_pes_extension_flag,
        ps_pes_header_data_length,ps_pes_header_data_bytes,ps_pes_pts,ps_pes_dts,ps_pes_escr,ps_pes_es_rate,ps_pes_dsm_trick_mode,ps_pes_additional_info,ps_pes_crc,ps_pes_extension,ps_pes_data_bytes,
        -- ps_data
    }

    function isInTable(item, tbl)
        for k,v in ipairs(tbl) do
            if v == item then
                return true
            end
        end
        return false
    end

    -- local frame_num = Field.new("frame.number")
    local h264_dis = Dissector.get("h264")
    local h265_dis = Dissector.get("h265")
    local pcma_dis = nil
    local pcmu_dis = nil
    if isInTable("pcma", Dissector.list()) then
        pcma_dis = Dissector.get("pcma")
    end
    if isInTable("pcmu", Dissector.list()) then
        pcmu_dis = Dissector.get("pcmu")
    end
    -- variable for storing stream info
    local stream_info_map = {}

    function is_ps_header(tvb, offset)
        if (tvb:len() < (offset+4)) then
            return false
        end
        
        if ((tvb:range(offset, 1):uint() == 0x00) and (tvb:range(offset+1, 1):uint() == 0x00)
            and (tvb:range(offset+2, 1):uint() == 0x01) and (tvb:range(offset+3, 1):uint() == 0xba)) then
            return true
        else
            return false
        end
    end
    function is_system_header(tvb, offset)
        if (tvb:len() < (offset+4)) then
            return false
        end
        
        --print(string.format("start code %x %x %x %x",tvb:range(offset, 1):uint(),tvb:range(offset+1, 1):uint(),tvb:range(offset+2, 1):uint(),tvb:range(offset+3, 1):uint()))
        if ((tvb:range(offset, 1):uint() == 0x00) and (tvb:range(offset+1, 1):uint() == 0x00)
            and (tvb:range(offset+2, 1):uint() == 0x01) and (tvb:range(offset+3, 1):uint() == 0xbb)) then
            return true
        else
            return false
        end
    end
    function is_pes_header(tvb, offset)
        if (tvb:len() < (offset+4)) then
            return false
        end
        if ((tvb:range(offset, 1):uint() == 0x00) and (tvb:range(offset+1, 1):uint() == 0x00)
            and (tvb:range(offset+2, 1):uint() == 0x01)) then
            return true
        else
            return false
        end
    end
    function is_raw_start(tvb, offset)
        if (tvb:len() < (offset+4)) then
            return false
        end
        if ((tvb:range(offset, 1):uint() == 0x00) and (tvb:range(offset+1, 1):uint() == 0x00)
            and (tvb:range(offset+2, 1):uint() == 0x00) and (tvb:range(offset+3, 1):uint() == 0x01)) then
            return true
        else
            return false
        end
    end
    function dis_ps_packet_header(tvb, tree, offset)
        -- PS packet header
        local stuffing_size = tvb:range(offset+13,1):bitfield(5, 3)
        local ps_hdr_tree = tree:add(ps_hdr, tvb:range(offset,14+stuffing_size))
        ps_hdr_tree:add(ps_start_code, tvb:range(offset,4))
        
        local scr_1 = tvb:range(offset+4,1):bitfield(2,3)
        local scr_2 = tvb:range(offset+4,3):bitfield(6,15)
        local scr_3 = tvb:range(offset+6,3):bitfield(6,15)
        local scr_e = tvb:range(offset+8,2):bitfield(6,9)
        local scr = bit.lshift(scr_1,30)+bit.lshift(scr_2,15)+scr_3
        ps_hdr_tree:add(ps_scr_base, tvb:range(offset+4,6)):append_text(string.format(": %u",scr))
        ps_hdr_tree:add(ps_scr_ext, tvb:range(offset+4,6)):append_text(string.format(": %u",scr_e))
        ps_hdr_tree:add(ps_multiplex_rate, tvb:range(offset+10,3))
        ps_hdr_tree:add(ps_stuffing_length, tvb:range(offset+13,1))
        if (stuffing_size > 0) then
            ps_hdr_tree:add(ps_stuffing_bytes, tvb:range(offset+14,stuffing_size))
        end
    end
    function dis_system_header(tvb, tree, offset)
        -- System header
        local system_header_length = tvb:range(offset+4, 2):uint()
        local ps_system_header_tree = tree:add(ps_system_header, tvb:range(offset,system_header_length+4+2))
        ps_system_header_tree:add(ps_system_header_start_code, tvb:range(offset,4))
        ps_system_header_tree:add(ps_system_header_length, tvb:range(offset+4,2))
        ps_system_header_tree:add(ps_system_header_rate_bound, tvb:range(offset+6,3))
        ps_system_header_tree:add(ps_system_header_audio_bound, tvb:range(offset+9,1))
        ps_system_header_tree:add(ps_system_header_fixed_flag, tvb:range(offset+9,1))
        ps_system_header_tree:add(ps_system_header_CSPS_flag, tvb:range(offset+9,1))
        ps_system_header_tree:add(ps_system_header_system_audio_lock_flag, tvb:range(offset+10,1))
        ps_system_header_tree:add(ps_system_header_system_video_lock_flag, tvb:range(offset+10,1))
        ps_system_header_tree:add(ps_system_header_vedio_bound, tvb:range(offset+10,1))
        ps_system_header_tree:add(ps_system_header_packet_rate_restriction_flag, tvb:range(offset+11,1))
        if (system_header_length>6) then
            local remain_length = system_header_length-6
            local shif = offset+12
            repeat
                ps_system_header_tree:add(ps_system_header_stream_id, tvb:range(shif,1))
                ps_system_header_tree:add(ps_system_header_P_STD_scale, tvb:range(shif+1,2))
                ps_system_header_tree:add(ps_system_header_P_STD_bound, tvb:range(shif+1,2))
                shif = shif+3
                remain_length = remain_length-3
            until(remain_length<=0)
        end
    end
    function dis_stream_map(tvb, tree, offset)
        -- Program stream map
        local program_map_length = tvb:range(offset+4, 2):uint()
        local ps_program_map_tree = tree:add(ps_program_stream, tvb:range(offset,program_map_length+4+2))
        ps_program_map_tree:add(ps_program_stream_start_code, tvb:range(offset,3))
        ps_program_map_tree:add(ps_program_stream_id, tvb:range(offset+3,1))
        ps_program_map_tree:add(ps_program_stream_length, tvb:range(offset+4,2))
        ps_program_map_tree:add(ps_program_stream_current_next_indicator, tvb:range(offset+6,1))
        ps_program_map_tree:add(ps_program_stream_map_version, tvb:range(offset+6,1))
        ps_program_map_tree:add(ps_program_stream_info_length, tvb:range(offset+8,2))
        local info_len = tvb:range(offset+8, 2):uint()

        ps_program_map_tree:add(ps_program_stream_map_length, tvb:range(offset+10+info_len,2)) --10 = 8+2(info len)
        local map_len = tvb:range(offset+10+info_len, 2):uint()
        local remain_length = map_len
        local shif = offset+12+info_len
        repeat
            ps_program_map_tree:add(ps_program_stream_map_stream_type, tvb:range(shif,1))
            ps_program_map_tree:add(ps_program_stream_map_stream_id, tvb:range(shif+1,1))
            local stream_type = tvb:range(shif,1):uint()
            local stream_id = tvb:range(shif+1,1):uint()
            stream_info_map[stream_id] = get_enum_name(ps_stream_type_vals, stream_type)
            ps_program_map_tree:add(ps_program_stream_map_info_length, tvb:range(shif+2,2))
            local map_info_len = tvb:range(shif+2, 2):uint()
            shif = shif+4+map_info_len
            remain_length = remain_length-4-map_info_len
        until(remain_length<=0)

        ps_program_map_tree:add(ps_program_stream_CRC, tvb:range(offset+12+info_len+map_len,4)) --12 = 8+2(info len)+2(map len)
    end
    function dis_pes(tvb, tree, offset, pinfo)
        -- PES header
        local pes_length = tvb:range(offset+4, 2):uint()
        local tvb_len = tvb:len()
        local complete_packet = tvb_len>=(offset+pes_length+6)
        local ps_pes_tree = tree:add(ps_pes, tvb:range(offset,complete_packet and (pes_length+4+2) or (tvb_len-offset)))
        ps_pes_tree:add(ps_pes_start_code, tvb:range(offset,3))
        ps_pes_tree:add(ps_pes_stream_id, tvb:range(offset+3,1))
        local pes_length_tree = ps_pes_tree:add(ps_pes_length, tvb:range(offset+4,2))

        ps_pes_tree:add(ps_pes_scrambing_control, tvb:range(offset+6,1))
        ps_pes_tree:add(ps_pes_priority, tvb:range(offset+6,1))
        ps_pes_tree:add(ps_pes_alignment, tvb:range(offset+6,1))
        ps_pes_tree:add(ps_pes_copyright, tvb:range(offset+6,1))
        ps_pes_tree:add(ps_pes_original, tvb:range(offset+6,1))

        ps_pes_tree:add(ps_pes_pts_dts_flag, tvb:range(offset+7,1))
        ps_pes_tree:add(ps_pes_escr_flag, tvb:range(offset+7,1))
        ps_pes_tree:add(ps_pes_es_rate_flag, tvb:range(offset+7,1))
        ps_pes_tree:add(ps_pes_dsm_trick_mode_flag, tvb:range(offset+7,1))
        ps_pes_tree:add(ps_pes_additional_info_flag, tvb:range(offset+7,1))
        ps_pes_tree:add(ps_pes_crc_flag, tvb:range(offset+7,1))
        ps_pes_tree:add(ps_pes_extension_flag, tvb:range(offset+7,1))

        local pes_header_data_len = tvb:range(offset+8, 1):uint()
        local header_data_tree = ps_pes_tree:add(ps_pes_header_data_length, tvb:range(offset+8,1))
        if complete_packet then
            pes_length_tree:append_text(string.format(" (Data Len: %u)",pes_length-pes_header_data_len-3))
        else
            pes_length_tree:append_text(string.format(" (Data Len: %u|Actual Len: %u)",pes_length-pes_header_data_len-3,tvb_len-offset-9-pes_header_data_len))
        end
        
        if pes_header_data_len>0 then
            header_data_tree:add(ps_pes_header_data_bytes, tvb:range(offset+9,pes_header_data_len))

            local index = offset+9
            local pts_dts_flag = tvb:range(offset+7,1):bitfield(0,2)
            if pts_dts_flag == 0x2 then
                -- local pts_1 = tvb:range(index,1):bitfield(4,3)
                local pts_high = tvb:range(index,1):bitfield(4,1)
                local pts_1 = tvb:range(index,1):bitfield(5,2)
                local pts_2 = tvb:range(index+1,2):bitfield(0,15)
                local pts_3 = tvb:range(index+3,2):bitfield(0,15)
                local pts = bit.lshift(pts_1,30)+bit.lshift(pts_2,15)+pts_3
                -- ps_pes_tree:add(ps_pes_pts, tvb:range(index,5)):append_text(string.format(": %u",pts))
                ps_pes_tree:add(ps_pes_pts, tvb:range(index,5)):append_text(string.format(": 0x%s",get_int64_string(pts_high,pts)))
                index = index + 5
            elseif pts_dts_flag == 0x3 then
                -- local pts_1 = tvb:range(index,1):bitfield(4,3)
                local pts_high = tvb:range(index,1):bitfield(4,1)
                local pts_1 = tvb:range(index,1):bitfield(5,2)
                local pts_2 = tvb:range(index+1,2):bitfield(0,15)
                local pts_3 = tvb:range(index+3,2):bitfield(0,15)
                local pts = bit.lshift(pts_1,30)+bit.lshift(pts_2,15)+pts_3
                ps_pes_tree:add(ps_pes_pts, tvb:range(index,5)):append_text(string.format(": 0x%s",get_int64_string(pts_high,pts)))

                -- local dts_1 = tvb:range(index+5,1):bitfield(4,3)
                local dts_high = tvb:range(index+5,1):bitfield(4,1)
                local dts_1 = tvb:range(index+5,1):bitfield(5,2)
                local dts_2 = tvb:range(index+6,2):bitfield(0,15)
                local dts_3 = tvb:range(index+8,2):bitfield(0,15)
                local dts = bit.lshift(dts_1,30)+bit.lshift(dts_2,15)+dts_3
                ps_pes_tree:add(ps_pes_dts, tvb:range(index+5,5)):append_text(string.format(": 0x%s",get_int64_string(dts_high,dts)))
                index = index + 10
            end
            local escr_flag = tvb:range(offset+7,1):bitfield(2,1)
            if escr_flag == 1 then
                -- local escr_1 = tvb:range(index,1):bitfield(2,3)
                local escr_high = tvb:range(index,1):bitfield(2,1)
                local escr_1 = tvb:range(index,1):bitfield(3,2)
                local escr_2 = tvb:range(index,3):bitfield(6,15)
                local escr_3 = tvb:range(index+2,3):bitfield(6,15)
                local escr_e = tvb:range(index+4,2):bitfield(6,9)
                local escr = bit.lshift(escr_1,30)+bit.lshift(escr_2,15)+escr_3
                ps_pes_tree:add(ps_pes_escr, tvb:range(index,6)):append_text(string.format(": 0x%s, extension: %u",get_int64_string(escr_high,escr),escr_e))
                index = index + 6
            end
            local es_rate_flag = tvb:range(offset+7,1):bitfield(3,1)
            if es_rate_flag == 1 then
                local es_rate = tvb:range(index,3):bitfield(1,22)
                ps_pes_tree:add(ps_pes_es_rate, tvb:range(index,3)):append_text(string.format(": %u",dts))
                index = index + 3
            end
            local dsm_trick_mode_flag = tvb:range(offset+7,1):bitfield(4,1)
            if dsm_trick_mode_flag == 1 then
                ps_pes_tree:add(ps_pes_dsm_trick_mode, tvb:range(index,1))
                index = index + 1
            end
            local additional_info_flag = tvb:range(offset+7,1):bitfield(5,1)
            if additional_info_flag == 1 then
                ps_pes_tree:add(ps_pes_additional_info, tvb:range(index,1))
                index = index + 1
            end
            local crc_flag = tvb:range(offset+7,1):bitfield(6,1)
            if crc_flag == 1 then
                ps_pes_tree:add(ps_pes_crc, tvb:range(index,2))
                index = index + 2
            end
            local extension_flag = tvb:range(offset+7,1):bitfield(7,1)
            if extension_flag == 1 then
                ps_pes_tree:add(ps_pes_extension, tvb:range(index,1))
                index = index + 1
            end
        end

        local stream_id = tvb:range(offset+3,1):uint()
        local stream_id_name = stream_info_map[stream_id]

        -- Start code 3, stream id 1, packet length 2, scrambing|PTS 2, Header length 1
        if offset+9+pes_header_data_len>=tvb_len then
            return
        end

        local date_len = complete_packet and (pes_length-3-pes_header_data_len) or (tvb_len-offset-9-pes_header_data_len)
        local shif = offset+9+pes_header_data_len
        local dec_tvb = tvb:bytes(shif,date_len):tvb()
        if "H.264" == stream_id_name then
            -- h264/h265 not contain start code 00 00 00 01
            h264_dis:call(dec_tvb:bytes(4):tvb(), pinfo, ps_pes_tree)
        elseif "H.265" == stream_id_name then
            h265_dis:call(dec_tvb:bytes(4):tvb(), pinfo, ps_pes_tree)
        elseif "G.711A" == stream_id_name and pcma_dis ~= nil then
            pcma_dis:call(dec_tvb, pinfo, ps_pes_tree)
        elseif "G.711U" == stream_id_name and pcmu_dis ~= nil then
            pcmu_dis:call(dec_tvb, pinfo, ps_pes_tree)
        else
            local media_raw_tree = ps_pes_tree:add(ps_pes_data_bytes, tvb:range(offset+9+pes_header_data_len, date_len))
            if stream_id_name then
                media_raw_tree:set_text(stream_id_name)
                media_raw_tree:append_text(string.format(" (%d)",date_len))
            else
                media_raw_tree:set_text(string.format("0x%x",stream_id))
                media_raw_tree:append_text(string.format(" (%d)",date_len))
            end
        end
        
    end

    local lastNumber = 0
    local tempArray = nil
    local completeRTP = {}

    -- PS dissector for rtp payload
    function proto_ps.dissector(tvb, pinfo, tree)
        -- local frame_seqs = frame_num()
        -- if (frame_seqs.value == 1)
        
        if pinfo.visited == false then
            if (is_ps_header(tvb, 0)) then
                tempArray = nil
            end
            if (tempArray == nil) then
                tempArray = ByteArray.new()
                tempArray:append(tvb:bytes())
            else
                tempArray:append(tvb:bytes())
            end
            completeRTP[pinfo.number] = tempArray
            -- clean not complete buffer
            if (is_ps_header(tvb, 0) == false) then
                if (lastNumber > 0) then
                    completeRTP[lastNumber] = nil
                end
            end
            lastNumber = pinfo.number

            return
        end

        -- add proto item to tree
        if (completeRTP[pinfo.number] ~= nil) then
            local rtp_tvb = completeRTP[pinfo.number]:tvb()
            local proto_tree = tree:add(proto_ps, rtp_tvb:range())
            local offset = 0

            if (is_ps_header(rtp_tvb, offset)) then
                local stuffing_size = rtp_tvb:range(offset+13,1):bitfield(5, 3)
                dis_ps_packet_header(rtp_tvb, proto_tree, offset)
                offset = offset + 14 + stuffing_size

                if (is_system_header(rtp_tvb, offset)) then
                    local system_header_length = rtp_tvb:range(offset+4, 2):uint()
                    dis_system_header(rtp_tvb, proto_tree, offset)
                    offset = offset + 4 + 2 + system_header_length
                    
                    -- program stream map
                    local program_map_length = rtp_tvb:range(offset+4, 2):uint()
                    dis_stream_map(rtp_tvb, proto_tree, offset)
                    offset = offset + 4 + 2 + program_map_length
                end
                
                while (is_pes_header(rtp_tvb, offset))
                do
                    local pes_length = rtp_tvb:range(offset+4, 2):uint()
                    dis_pes(rtp_tvb, proto_tree, offset, pinfo)
                    offset = offset + 4 + 2 + pes_length
                end
            else
                while (is_pes_header(rtp_tvb, offset))
                do
                    local pes_length = rtp_tvb:range(offset+4, 2):uint()
                    dis_pes(rtp_tvb, proto_tree, offset, pinfo)
                    offset = offset + 4 + 2 + pes_length
                end
            end
            
            pinfo.columns.protocol = "PS"
        else
            pinfo.columns.protocol = "PS"
        end
    end

    -- set this protocal preferences
    local prefs = proto_ps.prefs
    prefs.dyn_pt = Pref.range("PS dynamic payload type", "", "Dynamic payload types which will be interpreted as PS; Values must be in the range 96 - 127", 127)

    -- register this dissector to dynamic payload type dissectorTable
    local dyn_payload_type_table = DissectorTable.get("rtp_dyn_payload_type")
    dyn_payload_type_table:add("ps", proto_ps)

    -- register this dissector to specific payload type (specified in preferences windows)
    local payload_type_table = DissectorTable.get("rtp.pt")
    local old_dyn_pt = nil
    local old_dissector = nil
    
    function proto_ps.init()
        if (prefs.dyn_pt ~= old_dyn_pt) then
            -- reset old dissector
            if (old_dyn_pt ~= nil and string.len(old_dyn_pt) > 0) then
                local pt_numbers = getArray(tostring(old_dyn_pt))
                for index,pt_number in pairs(pt_numbers) do
                    -- replace this proto with old proto on old payload type
                    if old_dissector ~= nil and old_dissector[index] ~= nil then
                        payload_type_table:add(pt_number, old_dissector[index])
                    else -- just remove this proto
                        payload_type_table:remove(pt_number, proto_ps)
                    end
                end
            end
            
            old_dyn_pt = prefs.dyn_pt  -- save current payload type's dissector
            
            if (prefs.dyn_pt ~= nil and string.len(prefs.dyn_pt) > 0) then
                local pt_numbers = getArray(tostring(prefs.dyn_pt))
                old_dissector = {}
                for index,pt_number in pairs(pt_numbers) do
                    local dissector = payload_type_table:get_dissector(pt_number)
                    -- table.insert(old_dissector,index,dissector)
                    old_dissector[index] = dissector
                    payload_type_table:add(pt_number, proto_ps)
                end
            end
        end
    end

    function getArray(str)
        local strList = {}
        string.gsub(str, '[^,]+',function (w)
            local pos = string.find(w,'-')
            if not pos then
                table.insert(strList,tonumber(w))
            else
                local begin_index = string.sub(w,1,pos-1)
                local end_index = string.sub(w,pos+1,#w)
                for index = begin_index,end_index do
                    table.insert(strList,index)
                end
            end
        end)
        return strList
    end
end
