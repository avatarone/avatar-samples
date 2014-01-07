function kill_state (state, plg)
          plg:setGenerateTestcase(false)
          id=state:getID()
          print("Terminating state " .. id);
          plg:setKill(true)
end

function kill_loop (state, plg)
          pc=state:readRegister("pc");
          name=string.format("0x%08x", pc);          
          c=plg:getValue(name);
          if c >= 20 then
               plg:setGenerateTestcase(false)
               id=state:getID()
               print("Killing looping state " .. id .. " at " .. name );
               plg:setKill(true)
          else
               c = c+1
               c=plg:setValue(name, c);
          end
end

function nop (state, plg)
end
