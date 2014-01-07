set $FLASH_FILE = "/home/zaddach/projects/eurecom-s2e/avatar/avatar/configurations/hdd/JC49_flash.raw"
set arm force-mode thumb
set disassemble-next-line yes
target remote localhost:1234

define load_from_flash
    set $ram_addr = $arg0
    set $flash_addr = $arg1
    set $len_in_words = $arg2
    set $ram_offset = $ram_addr - $flash_addr

    printf "loading 0x%x bytes of data from flash address 0x%x to ram address 0x%x\n", $len_in_words * 4, $flash_addr, $ram_addr

    if $len_in_words > 0
        restore JC49_flash.raw binary $ram_offset $flash_addr ($flash_addr + 4 * $len_in_words)
    end
end 

define arm_return
    set $pc = $lr & ~1
    set $cpsr = ($cpsr & ~0x20) | (($lr & 1) << 5)
end


break *0x1008f8
commands
    silent
    echo Initialization done, loading firmware from flash/showing boot menu\n
    cont
end



break *0x100aae
commands
    silent
    printf "loading data from flash with function load_data_from_flash_and_checksum(ram_addr = 0x%08x, flash_addr = 0x%08x, len_in_words = 0x%08x) at 0x%08x\n", $r1, $r2, $r3, $lr
    load_from_flash $r1 $r2 $r3

    arm_return
    cont
end

break *0x1004e8
commands
    silent
    echo display_boot_menu()\n
    cont
end

tbreak *0x10087c
commands
    silent
    echo Entering flash code\n
    tbreak *0x23e
    commands
        silent
        echo Entering flash boot FW from flash loader stub\n
        break *0x301e
        commands
            silent
            printf "loading data from flash with function load_data_from_flash_with_CS(ram_addr = 0x%08x, flash_addr = 0x%08x, len_in_words = 0x%08x)\n", $r1, $r2, $r3
            load_from_flash $r1 $r2 $r3
            arm_return
            cont
        end
        cont
    end
    cont
end
