
    rule win32_stage_boot_winsock_conn_udp_lgetprocaddress_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_boot_winsock_conn_udp::lgetprocaddress"
    
        /*
            53                   | S                    | push ebx
            55                   | U                    | push ebp
            56                   | V                    | push esi
            57                   | W                    | push edi
            8B6C2418             | .l$.                 | mov ebp, [esp + 24]
            8B453C               | .E<                  | mov eax, [ebp + 0x3c]
            8B540578             | .T.x                 | mov edx, [ebp + eax + 120]
            01EA                 | ..                   | add edx, ebp
            8B4A18               | .J.                  | mov ecx, [edx + 24]
            8B5A20               | .Z                   | mov ebx, [edx + 32]
            01EB                 | ..                   | add ebx, ebp
        */
    
        strings:
            $a   = { 53 55 56 57 8b 6c 24 18 8b 45 3c 8b 54 05 78 01 ea 8b 4a 18 8b 5a 20 01 eb }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_boot_winsock_conn_udp_lfnlp_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_boot_winsock_conn_udp::lfnlp"
    
        /*
            E332                 | .2                   | jecxz lntfnd
            49                   | I                    | dec ecx
            8B348B               | .4.                  | mov esi, [ebx + ecx * 4]
            01EE                 | ..                   | add esi, ebp
            31FF                 | 1.                   | xor edi, edi
            FC                   | .                    | cld
        */
    
        strings:
            $a   = { e3 32 49 8b 34 8b 01 ee 31 ff fc }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_boot_winsock_conn_udp_lhshlp_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_boot_winsock_conn_udp::lhshlp"
    
        /*
            31C0                 | 1.                   | xor eax, eax
            AC                   | .                    | lodsb
            38E0                 | 8.                   | cmp al, ah
            7407                 | t.                   | je lfnd
            C1CF0D               | ...                  | ror edi, 13
            01C7                 | ..                   | add edi, eax
            EBF2                 | ..                   | jmp short lhshlp
        */
    
        strings:
            $a   = { 31 c0 ac 38 e0 74 07 c1 cf 0d 01 c7 eb f2 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_boot_winsock_conn_udp_lfnd_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_boot_winsock_conn_udp::lfnd"
    
        /*
            3B7C2414             | ;|$.                 | cmp edi, [esp + 20]
            75E1                 | u.                   | jnz lfnlp
            8B5A24               | .Z$                  | mov ebx, [edx + 36]
            01EB                 | ..                   | add ebx, ebp
            668B0C4B             | f..K                 | mov cx, [ebx + 2 * ecx]
            8B5A1C               | .Z.                  | mov ebx, [edx + 28]
            01EB                 | ..                   | add ebx, ebp
            8B048B               | ...                  | mov eax, [ebx + 4 * ecx]
            01E8                 | ..                   | add eax, ebp
            EB02                 | ..                   | jmp short ldone
        */
    
        strings:
            $a   = { 3b 7c 24 14 75 e1 8b 5a 24 01 eb 66 8b 0c 4b 8b 5a 1c 01 eb 8b 04 8b 01 e8 eb 02 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_boot_winsock_conn_udp_ldone_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_boot_winsock_conn_udp::ldone"
    
        /*
            5F                   | _                    | pop edi
            5E                   | ^                    | pop esi
            5D                   | ]                    | pop ebp
            5B                   | [                    | pop ebx
            C20800               | ...                  | ret 8
        */
    
        strings:
            $a   = { 5f 5e 5d 5b c2 08 00 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_boot_winsock_conn_udp_lkernel32base_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_boot_winsock_conn_udp::lkernel32base"
    
        /*
            5E                   | ^                    | pop esi
            6A30                 | j0                   | push byte 0x30
            59                   | Y                    | pop ecx
            648B19               | d..                  | mov ebx, [fs:ecx]
            8B5B0C               | .[.                  | mov ebx, [ebx + 0x0c]
            8B5B1C               | .[.                  | mov ebx, [ebx + 0x1c]
            8B1B                 | ..                   | mov ebx, [ebx]
            8B5B08               | .[.                  | mov ebx, [ebx + 0x08]
            53                   | S                    | push ebx
            688E4E0EEC           | h.N..                | push 0xec0e4e8e
            FFD6                 | ..                   | call esi
            89C7                 | ..                   | mov edi, eax
            53                   | S                    | push ebx
            6854CAAF91           | hT...                | push 0x91afca54
            FFD6                 | ..                   | call esi
            81EC00010000         | ......               | sub esp, 0x100
            50                   | P                    | push eax
            57                   | W                    | push edi
            56                   | V                    | push esi
            53                   | S                    | push ebx
            89E5                 | ..                   | mov ebp, esp
            E81F000000           | .....                | call lloadwinsock
        */
    
        strings:
            $a   = { 5e 6a 30 59 64 8b 19 8b 5b 0c 8b 5b 1c 8b 1b 8b 5b 08 53 68 8e 4e 0e ec ff d6 89 c7 53 68 54 ca af 91 ff d6 81 ec 00 01 00 00 50 57 56 53 89 e5 e8 1f 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_boot_winsock_conn_udp_lloadwinsock_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_boot_winsock_conn_udp::lloadwinsock"
    
        /*
            5B                   | [                    | pop ebx
            8D4B18               | .K.                  | lea ecx, [ebx + 24]
            51                   | Q                    | push ecx
            FFD7                 | ..                   | call edi
            89DF                 | ..                   | mov edi, ebx
            89C3                 | ..                   | mov ebx, eax
            8D7514               | .u.                  | lea esi, [ebp + 20]
            6A05                 | j.                   | push byte 0x05
            59                   | Y                    | pop ecx
        */
    
        strings:
            $a   = { 5b 8d 4b 18 51 ff d7 89 df 89 c3 8d 75 14 6a 05 59 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_boot_winsock_conn_udp_looper_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_boot_winsock_conn_udp::looper"
    
        /*
            51                   | Q                    | push ecx
            53                   | S                    | push ebx
            FF348F               | .4.                  | push dword [edi + ecx * 4]
            FF5504               | .U.                  | call [ebp + 4]
            59                   | Y                    | pop ecx
            89048E               | ...                  | mov [esi + ecx * 4], eax
            E2F2                 | ..                   | loop looper
        */
    
        strings:
            $a   = { 51 53 ff 34 8f ff 55 04 59 89 04 8e e2 f2 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_boot_winsock_conn_udp_lwsastartup_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_boot_winsock_conn_udp::lwsastartup"
    
        /*
            2B27                 | +'                   | sub esp, [edi]
            54                   | T                    | push esp
            FF37                 | .7                   | push dword [edi]
            FF5528               | .U(                  | call [ebp + 40]
            31C0                 | 1.                   | xor eax, eax
        */
    
        strings:
            $a   = { 2b 27 54 ff 37 ff 55 28 31 c0 }
    
        condition:
            any of them
    }
    
    
    rule win32_stage_boot_winsock_conn_udp_lwsasocketa_x86
    {
        meta:
            desc = "Metasploit::windows::x86::win32_stage_boot_winsock_conn_udp::lwsasocketa"
    
        /*
            50                   | P                    | push eax
            50                   | P                    | push eax
            50                   | P                    | push eax
            50                   | P                    | push eax
            40                   | @                    | inc eax
            40                   | @                    | inc eax
            50                   | P                    | push eax
            50                   | P                    | push eax
            FF5524               | .U$                  | call [ebp + 36]
            89C7                 | ..                   | mov edi, eax
        */
    
        strings:
            $a   = { 50 50 50 50 40 40 50 50 ff 55 24 89 c7 }
    
        condition:
            any of them
    }
    
    