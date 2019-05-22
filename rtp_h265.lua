-- Dissector for rtp payload H265
-- According to RFC7798 to dissector H265 payload of RTP to NALU
-- Author: Yang Xing (hongch_911@126.com)
------------------------------------------------------------------------------------------------
do
    local proto_h265 = Proto("h265", "H.265")
    
    local h265_f_bit_vals = {
        [1] = "Bit errors or other syntax violations",
        [0] = "No bit errors or other syntax violations"
    }
    local h265_start_bit_vals = {
        [1] = "the first packet of FU picture",
        [0] = "Not the first packet of FU picture"
    }
    local h265_end_bit_vals = {
        [1] = "the last packet of FU picture",
        [0] = "Not the last packet of FU picture"
    }
    local h265_hdr_type_vals = {
        [0] = "NAL unit - Coded slice segment of a non-TSA, non-STSA trailing picture",
        [1] = "NAL unit - Coded slice segment of a non-TSA, non-STSA trailing picture",
        [2] = "NAL unit - Coded slice segment of a TSA picture",
        [3] = "NAL unit - Coded slice segment of a TSA picture",
        [4] = "NAL unit - Coded slice segment of an STSA picture",
        [5] = "NAL unit - Coded slice segment of an STSA picture",
        [6] = "NAL unit - Coded slice segment of a RADL picture",
        [7] = "NAL unit - Coded slice segment of a RADL picture",
        [8] = "NAL unit - Coded slice segment of a RASL picture",
        [9] = "NAL unit - Coded slice segment of a RASL picture",
        [10] = "NAL unit - Reserved non-IRAP SLNR VCL NAL unit types",
        [11] = "NAL unit - Reserved non-IRAP sub-layer reference VCL NAL unit types",
        [12] = "NAL unit - Reserved non-IRAP SLNR VCL NAL unit types",
        [13] = "NAL unit - Reserved non-IRAP sub-layer reference VCL NAL unit types",
        [14] = "NAL unit - Reserved non-IRAP SLNR VCL NAL unit types",
        [15] = "NAL unit - Reserved non-IRAP sub-layer reference VCL NAL unit types",
        [16] = "NAL unit - Coded slice segment of a BLA picture",
        [17] = "NAL unit - Coded slice segment of a BLA picture",
        [18] = "NAL unit - Coded slice segment of a BLA picture",
        [19] = "NAL unit - Coded slice segment of an IDR picture",
        [20] = "NAL unit - Coded slice segment of an IDR picture",
        [21] = "NAL unit - Coded slice segment of a CRA picture",
        [22] = "NAL unit - Reserved IRAP VCL NAL unit types",
        [23] = "NAL unit - Reserved IRAP VCL NAL unit types",
        [24 .. 31] = "NAL unit - Reserved non-IRAP VCL NAL unit types",
        [32] = "NAL unit - Video parameter set",
        [33] = "NAL unit - Sequence parameter set",
        [34] = "NAL unit - Picture parameter set",
        [35] = "NAL unit - Access unit delimiter",
        [36] = "NAL unit - End of sequence",
        [37] = "NAL unit - End of bitstream",
        [38] = "NAL unit - Filler data",
        [39] = "NAL unit - Prefix Supplemental enhancement information",
        [40] = "NAL unit - Suffix Supplemental enhancement information",
        [40 .. 47] = "NAL unit - Reserved",
        [48] = "Aggregation packet (AP)",
        [49] = "Fragmentation unit (FU)",
        [50] = "PACI packet"
    }
    local nal_unit_type_vals = {
        [0] = "Coded slice segment of a non-TSA, non-STSA trailing picture",
        [1] = "Coded slice segment of a non-TSA, non-STSA trailing picture",
        [2] = "Coded slice segment of a TSA picture",
        [3] = "Coded slice segment of a TSA picture",
        [4] = "Coded slice segment of an STSA picture",
        [5] = "Coded slice segment of an STSA picture",
        [6] = "Coded slice segment of a RADL picture",
        [7] = "Coded slice segment of a RADL picture",
        [8] = "Coded slice segment of a RASL picture",
        [9] = "Coded slice segment of a RASL picture",
        [10] = "Reserved non-IRAP SLNR VCL NAL unit types",
        [11] = "Reserved non-IRAP sub-layer reference VCL NAL unit types",
        [12] = "Reserved non-IRAP SLNR VCL NAL unit types",
        [13] = "Reserved non-IRAP sub-layer reference VCL NAL unit types",
        [14] = "Reserved non-IRAP SLNR VCL NAL unit types",
        [15] = "Reserved non-IRAP sub-layer reference VCL NAL unit types",
        [16] = "Coded slice segment of a BLA picture",
        [17] = "Coded slice segment of a BLA picture",
        [18] = "Coded slice segment of a BLA picture",
        [19] = "Coded slice segment of an IDR picture",
        [20] = "Coded slice segment of an IDR picture",
        [21] = "Coded slice segment of a CRA picture",
        [22] = "Reserved IRAP VCL NAL unit types",
        [23] = "Reserved IRAP VCL NAL unit types",
        [24 .. 31] = "Reserved non-IRAP VCL NAL unit types",
        [32] = "Video parameter set",
        [33] = "Sequence parameter set",
        [34] = "Picture parameter set",
        [35] = "Access unit delimiter",
        [36] = "End of sequence",
        [37] = "End of bitstream",
        [38] = "Filler data",
        [39] = "Prefix Supplemental enhancement information",
        [40] = "Suffix Supplemental enhancement information",
        [40 .. 47] = "Reserved",
        [48 .. 63] = "Unspecified"
    }
    
    local h265_payload_hdr = ProtoField.none("h265.payload_hdr", "Payload Hdr")
    local h265_nal_unit_header = ProtoField.none("h265.nal_unit_header", "NAL unit header")
    
    local h265_f_bit = ProtoField.new("F bit", "h265.f", ftypes.UINT16, h265_f_bit_vals, base.DEC, 0x8000)
    local h265_hdr_type = ProtoField.new("Type", "h265.nal_unit_hdr", ftypes.UINT16, h265_hdr_type_vals, base.DEC, 0x7E00)
    local h265_hdr_layer_id = ProtoField.new("Layer ID", "h265.layerid", ftypes.UINT16, nil, base.DEC, 0x01F8)
    local h265_hdr_temporal_id = ProtoField.new("TID", "h265.tid", ftypes.UINT16, nil, base.DEC, 0x0007)
    
    local h265_fu_header = ProtoField.none("h265.fu_header", "FU header")
    local h265_start = ProtoField.new("Start bit", "h265.start.bit", ftypes.UINT8, h265_start_bit_vals, base.DEC, 0x80)
    local h265_end = ProtoField.new("End bit", "h265.end.bit", ftypes.UINT8, h265_end_bit_vals, base.DEC, 0x40)
    local h265_nal_unit_type = ProtoField.new("Nal_unit_Type", "h265.nal_unit_type", ftypes.UINT8, nal_unit_type_vals, base.DEC, 0x3F)
    
    local h265_nal_unit_payload = ProtoField.bytes("h265.nalu_payload", "Raw")
    
    proto_h265.fields = {
        h265_payload_hdr,h265_nal_unit_header,
        h265_f_bit,h265_hdr_type,h265_hdr_layer_id,h265_hdr_temporal_id,
        h265_fu_header,h265_start,h265_end,h265_nal_unit_type,
        h265_nal_unit_payload
    }
    
    function dissect_h265_fu(tvb, pinfo, tree)
        local payload_hdr_tree = tree:add(h265_payload_hdr, tvb:range(0,2))
        payload_hdr_tree:add(h265_f_bit, tvb:range(0,2))
        payload_hdr_tree:add(h265_hdr_type, tvb:range(0,2))
        payload_hdr_tree:add(h265_hdr_layer_id, tvb:range(0,2))
        payload_hdr_tree:add(h265_hdr_temporal_id, tvb:range(0,2))
        
        local pu_header_tree = tree:add(h265_fu_header, tvb:range(2,1))
        pu_header_tree:add(h265_start, tvb:range(2,1))
        pu_header_tree:add(h265_end, tvb:range(2,1))
        pu_header_tree:add(h265_nal_unit_type, tvb:range(2,1))
        
        local payload_tree = tree:add("H265 NAL Unit Payload")
        payload_tree:add(h265_nal_unit_payload, tvb:range(3))
    end
    function dissect_h265_ap(tvb, pinfo, tree)
        local offset = 0
        
        local payload_hdr_tree = tree:add(h265_payload_hdr, tvb:range(0,2))
        payload_hdr_tree:add(h265_f_bit, tvb:range(0,2))
        payload_hdr_tree:add(h265_hdr_type, tvb:range(0,2))
        payload_hdr_tree:add(h265_hdr_layer_id, tvb:range(0,2))
        payload_hdr_tree:add(h265_hdr_temporal_id, tvb:range(0,2))
        offset = offset + 2
        
        -- print(string.format("tvb len %d",tvb:len()))
        while(offset < tvb:len())
        do
            local nalu_size = tvb:range(offset,2):bitfield(0, 16)
            -- print(string.format("nalu_size %d", nalu_size))
            offset = offset + 2
            dissect_h265_nal_unit(tvb, pinfo, tree, offset, nalu_size)
            offset = offset + nalu_size
        end
        
    end
    function dissect_h265_nal_unit(tvb, pinfo, tree, offset, size)
        -- local nalu_type = tvb:range(offset,1):bitfield(1, 6)
        local nalu_header_tree = tree:add(h265_nal_unit_header, tvb:range(offset,2))
        nalu_header_tree:add(h265_f_bit, tvb:range(offset,2))
        nalu_header_tree:add(h265_hdr_type, tvb:range(offset,2))
        nalu_header_tree:add(h265_hdr_layer_id, tvb:range(offset,2))
        nalu_header_tree:add(h265_hdr_temporal_id, tvb:range(offset,2))
        
        local payload_tree = tree:add("H265 NAL Unit Payload")
        payload_tree:add(h265_nal_unit_payload, tvb:range(offset+2, size-2))
    end

    -- Wireshark对每个相关数据包调用该函数
    -- tvb:Testy Virtual Buffer报文缓存; pinfo:packet infomarmation报文信息; treeitem:解析树节点
    function proto_h265.dissector(tvb, pinfo, tree)
        -- add proto item to tree
        local proto_tree = tree:add(proto_h265, tvb())
        
        local nalu_type = tvb:range(0,1):bitfield(1, 6)
        if (nalu_type < 48) then
            dissect_h265_nal_unit(tvb, pinfo, proto_tree, 0, tvb:len())
            
        elseif (nalu_type == 49) then
            dissect_h265_fu(tvb, pinfo, proto_tree)
            
            pinfo.cols.info:append(" FU")
        elseif (nalu_type == 48) then
            dissect_h265_ap(tvb, pinfo, proto_tree)
            
            pinfo.cols.info:append(" AP")
        end
        
        pinfo.columns.protocol = "H265"
    end

    -- set this protocal preferences
    local prefs = proto_h265.prefs
    prefs.dyn_pt = Pref.uint("H265 dynamic payload types", 0, "The value > 95")

    -- register this dissector to dynamic payload type dissectorTable
    local dyn_payload_type_table = DissectorTable.get("rtp_dyn_payload_type")
    dyn_payload_type_table:add("h265", proto_h265)

    -- register this dissector to specific payload type (specified in preferences windows)
    local payload_type_table = DissectorTable.get("rtp.pt")
    local old_dissector = nil
    local old_dyn_pt = 0
    function proto_h265.init()
        if (prefs.dyn_pt ~= old_dyn_pt) then
            if (old_dyn_pt > 0) then -- reset old dissector
                if (old_dissector == nil) then -- just remove this proto
                    payload_type_table:remove(old_dyn_pt, proto_h265)
                else  -- replace this proto with old proto on old payload type
                    payload_type_table:add(old_dyn_pt, old_dissector)
                end
            end
            old_dyn_pt = prefs.dyn_pt  -- save current payload type's dissector
            old_dissector = payload_type_table:get_dissector(old_dyn_pt)
            if (prefs.dyn_pt > 0) then
                payload_type_table:add(prefs.dyn_pt, proto_h265)
            end
        end
    end
end
