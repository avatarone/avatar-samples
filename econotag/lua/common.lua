function end_analysis_region (state, plg)
   print ("exiting function, stopping here !\n")
   plg:setGenerateTestcase(true)
   plg:generate_testcase_on_kill(false)
   plg:setKill(true)
end

function end_analysis_region (state, plg)
   print ("exiting function, stopping here !\n")
   plg:setGenerateTestcase(true)
   plg:setKill(true)
end

function reset (state, plg)
   print ("reset  !!!!\n")
   plg:setGenerateTestcase(true)
   plg:generate_testcase_on_kill(true)
   plg:setKill(true)
end

function undef_instr (state, plg)
   print ("Oups hit undef instr at ".. string.format("%x", state:readRegister("lr")).."!!\n")  
   plg:setKill(true)
end


function skip_uart (state, plg)
   if plg:isCall() then 
      print("skipping uart code")
      --plg:setSkip(true)
      
   end
end
