function make_pkt_symbolic (state, plg)
   print ("making pkt symbolic\n")
   --buff = 0x4033aa
   buff = 0x4033D6 -- DataRX +2
   for i = 0,32 do
      state:writeMemorySymb("pkt_buff", buff+i, 1)
   end
end
