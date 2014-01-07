function cmhSMS_cpyDeliver (state, plg)
          --00000000 T_TP_DELIVER    struc ; (sizeof=0x22D)
          --00000000 tp_vt_mti       DCB ?                   ; Virtual TP Message Type
          --00000001 tp_rp           DCB ?                   ; TP Reply Path
          --00000002 tp_udhi         DCB ?                   ; TP User Data Header Indicator
          --00000003 tp_sri          DCB ?                   ; TP Status Report Indication
          --00000004 tp_mms          DCB ?                   ; TP More Messages To Send
          --00000005 tp_mmi          DCB ?                   ; TP Message Type Indicator
          --00000006 _align0         DCB ?
          --00000007 _align1         DCB ?
          --00000008 tp_oa           T_tp_da                 ; TP Originating Address
          --00000020 tp_pid          DCB ?                   ; TP Protocol Identifier
          --00000021 tp_dcs          DCB ?
          --00000022 _align2         DCB ?
          --00000023 _align3         DCB ?
          --00000024 tp_scts         T_tp_vp_abs ?
          --00000034 _align4         DCB ?
          --00000035 _align5         DCB ?
          --00000036 _align6         DCB ?
          --00000037 v_tp_ud         DCB ?
          --00000038 tp_ud           DCB 164 dup(?)
          --000000DC _align7         DCB ?
          --000000DD _align8         DCB ?
          --000000DE _align9         DCB ?
          --000000DF _align10        DCB ?
          --000000E0 v_tp_udh_inc    DCB ?
          --000000E1 tp_udh_inc      DCB 332 dup(?)
          --0000022D T_TP_DELIVER    ends
        
        p_sms_deliver =  state:readRegister("r5");
        print(string.format("injecting at 0x%08x", p_sms_deliver))
        struct_size = 0x22D;
        
        offset = 0x00000024;
        sizeof = 0x00000010;
        --sizeof = struct_size - offset;
        
        base = p_sms_deliver + offset;
        for i = 0, sizeof-1, 1 do
          print(string.format("putting symbolic sym%d at 0x%08x", i, base+i))
          state:writeMemorySymb("sym".. i, base + i, 1, true);
        end

end

function unused (state, plg)
        --[[
          --00000000 T_tp_da         struc ; (sizeof=0x18)
          --00000000 digits          DCB ?
          --00000001 ton             DCB ?
          --00000002 npi             DCB ?
          --00000003 c_num           DCB ?
          --00000004 num             DCB 20 dup(?)
          --00000018 T_tp_da         ends
        p_tp_oa = p_sms_deliver + 0x08;
        state:writeMemorySymb("oa.digits", p_tp_oa, 8);
        state:writeMemorySymb("oa.ton", p_tp_oa + 1, 8);
        state:writeMemorySymb("oa.npi", p_tp_oa + 2, 8);
        state:writeMemorySymb("oa.c_num", p_tp_oa + 3, 8);
        for i = 4, 1, 0x17 do
          state:writeMemorySymb("oa.num".. (i-4), p_tp_oa + i, 8);
        end
        
        --]]
end


function cmhSMS_cpyMsgInd (state, plg)
        p_sms_deliver =  state:readRegister("r4");
        print(string.format("SMS is at 0x%08x", p_sms_deliver));
        base=p_sms_deliver+4+8;
        sizeof=56;
        print("Dumping SMS: ");
        for i = 0, sizeof-1, 1 do
          io.write(string.format("%02x", state:readMemory(base + i, 1)));
        end
        print("");
        offset=0;
        for i = 0, sizeof-1, 1 do
          print(string.format("putting symbolic sym%d at 0x%08x", i, base+i))
          state:writeMemorySymb("sym".. i, base + offset + i, 1, true);
        end
end

