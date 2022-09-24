local NAME1 = "rtx"

local f_bit_error = nil

local rtx = Proto(NAME1, "RTX protocol")

-- create fields of rtx
fields_OSN = ProtoField.uint16(NAME1 .. ".OSN", "OSN", base.DEC)

rtx.fields = { fields_OSN }

-- dissect packet
function rtx.dissector(tvb, pinfo, tree)
    length = tvb:len()
    if length == 0 then
        return
    end

    -- decode rtx header
    local subtree = tree:add(rtx, tvb(0, 2))
    subtree:add(fields_OSN, tvb(0, 2))

    -- show protocol name in protocol column
    pinfo.cols.protocol = rtx.name

    local osn = tvb(0, 2):uint()
    pinfo.cols['info'] = tostring(pinfo.cols['info']) .. ", OSN " .. tostring(osn)
end

-- register this dissector
DissectorTable.get("rtp.pt"):add_for_decode_as(rtx)
