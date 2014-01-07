function end_state(state, plg)
   print ("exit function!\n")
   plg:setGenerateTestcase(true)
   plg:setKill(true)
end

function make_env_symbolic_buggy(state, plg)
	print ("marking env symbolic [buggy]!\n")
	count = 2 -- number of bytes marked symbolical
	-- grep default_environment System.map + relocation offset
	env_buf = 0x8001d5a5+0x03fb7000
	for i = 0,count-1 do
		state:writeMemorySymb("env_buf", env_buf+i, 1)
	end
	-- write nul byte, it's a parser!
	-- we want to parse only the symbolic values
	state:writeMemory(env_buf+count, 1, 0)
end

function make_env_symbolic(state, plg)
	print ("marking env symbolic!\n")
	count = 2 -- number of bytes marked symbolical
	-- grep default_environment System.map + relocation offset
	env_buf = 0x8001d5dd+0x03fb7000
	for i = 0,count-1 do
		state:writeMemorySymb("env_buf", env_buf+i, 1)
	end
	-- write nul byte, it's parser
	-- we want to parse only the symbolic values
	state:writeMemory(env_buf+count, 1, 0)
end
