-- credit: https://blog.csdn.net/qq_40421919/article/details/103516694

local NAME1 = "red"

local f_bit_error = nil

local red = Proto(NAME1, "RED protocol")

-- create fields of red
fields_F = ProtoField.uint8(NAME1 .. ".F", "F", base.HEX, Payload_type, 0x80)
fields_pt = ProtoField.uint8(NAME1 .. ".PT", "PT", base.DEC, Payload_type, 0x7F)

red.fields = { fields_F, fields_pt }

-- dissect packet
function red.dissector(tvb, pinfo, tree)
    length = tvb:len()
    if length == 0 then
        return
    end

    -- decode red header
    local subtree = tree:add(red, tvb(0, 1))
    subtree:add(fields_F, tvb(0, 1))
    subtree:add(fields_pt, tvb(0, 1))

    local red_header = tvb(0, 1):uint()
    local f_bit = bit.band(red_header, 0x80)
    if f_bit ~= 0 then
        if f_bit_error == nil then
            f_bit_error = TextWindow.new("Error")
        end
        f_bit_error:append("Currently only support one red header, bad packet: " .. tostring(pinfo.number) .. "\n")
        return
    end

    -- show protocol name in protocol column
    pinfo.cols.protocol = red.name

    -- dissect with actual protocol
    local pt = bit.band(red_header, 0x7F)
    local pt_name = tostring(DissectorTable.get("rtp.pt"):get_dissector(pt))
    if pt_name == "H.264" then
        Dissector.get("h264"):call(tvb(1):tvb(), pinfo, tree)
    elseif pt_name == "H.265" then
        Dissector.get("h265"):call(tvb(1):tvb(), pinfo, tree)
    elseif pt_name == "AAC" then
        Dissector.get("aac"):call(tvb(1):tvb(), pinfo, tree)
    end
end

-- register this dissector
DissectorTable.get("rtp.pt"):add_for_decode_as(red)
