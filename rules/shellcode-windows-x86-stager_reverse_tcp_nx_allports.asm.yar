
    rule stager_reverse_tcp_nx_allports___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_tcp_nx_allports::__start0__"
    
        /*
            FC                   | .                    | cld
            E88C000000           | .....                | call start
        */
    
        strings:
            $a   = { fc e8 8c 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_tcp_nx_allports_api_call_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_tcp_nx_allports::api_call"
    
        /*
            60                   | `                    | pushad
            89E5                 | ..                   | mov ebp, esp
            31D2                 | 1.                   | xor edx, edx
            648B5230             | d.R0                 | mov edx, [fs:edx+0x30]
            8B520C               | .R.                  | mov edx, [edx+0xc]
            8B5214               | .R.                  | mov edx, [edx+0x14]
        */
    
        strings:
            $a   = { 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_tcp_nx_allports_next_mod_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_tcp_nx_allports::next_mod"
    
        /*
            8B7228               | .r(                  | mov esi, [edx+0x28]
            0FB74A26             | ..J&                 | movzx ecx, word [edx+0x26]
            31FF                 | 1.                   | xor edi, edi
        */
    
        strings:
            $a   = { 8b 72 28 0f b7 4a 26 31 ff }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_tcp_nx_allports_loop_modname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_tcp_nx_allports::loop_modname"
    
        /*
            31C0                 | 1.                   | xor eax, eax
            AC                   | .                    | lodsb
            3C61                 | <a                   | cmp al, 'a'
            7C02                 | |.                   | jl not_lowercase
            2C20                 | ,                    | sub al, 0x20
        */
    
        strings:
            $a   = { 31 c0 ac 3c 61 7c 02 2c 20 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_tcp_nx_allports_not_lowercase_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_tcp_nx_allports::not_lowercase"
    
        /*
            C1CF0D               | ...                  | ror edi, 0xd
            01C7                 | ..                   | add edi, eax
            49                   | I                    | dec ecx
            75EF                 | u.                   | jnz loop_modname
            52                   | R                    | push edx
            57                   | W                    | push edi
            8B5210               | .R.                  | mov edx, [edx+0x10]
            8B423C               | .B<                  | mov eax, [edx+0x3c]
            01D0                 | ..                   | add eax, edx
            8B4078               | .@x                  | mov eax, [eax+0x78]
            85C0                 | ..                   | test eax, eax
            744C                 | tL                   | jz get_next_mod1
            01D0                 | ..                   | add eax, edx
            50                   | P                    | push eax
            8B4818               | .H.                  | mov ecx, [eax+0x18]
            8B5820               | .X                   | mov ebx, [eax+0x20]
            01D3                 | ..                   | add ebx, edx
        */
    
        strings:
            $a   = { c1 cf 0d 01 c7 49 75 ef 52 57 8b 52 10 8b 42 3c 01 d0 8b 40 78 85 c0 74 4c 01 d0 50 8b 48 18 8b 58 20 01 d3 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_tcp_nx_allports_get_next_func_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_tcp_nx_allports::get_next_func"
    
        /*
            85C9                 | ..                   | test ecx, ecx
            743C                 | t<                   | jz get_next_mod
            49                   | I                    | dec ecx
            8B348B               | .4.                  | mov esi, [ebx+ecx*4]
            01D6                 | ..                   | add esi, edx
            31FF                 | 1.                   | xor edi, edi
        */
    
        strings:
            $a   = { 85 c9 74 3c 49 8b 34 8b 01 d6 31 ff }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_tcp_nx_allports_loop_funcname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_tcp_nx_allports::loop_funcname"
    
        /*
            31C0                 | 1.                   | xor eax, eax
            AC                   | .                    | lodsb
            C1CF0D               | ...                  | ror edi, 0xd
            01C7                 | ..                   | add edi, eax
            38E0                 | 8.                   | cmp al, ah
            75F4                 | u.                   | jne loop_funcname
            037DF8               | .}.                  | add edi, [ebp-8]
            3B7D24               | ;}$                  | cmp edi, [ebp+0x24]
            75E0                 | u.                   | jnz get_next_func
            58                   | X                    | pop eax
            8B5824               | .X$                  | mov ebx, [eax+0x24]
            01D3                 | ..                   | add ebx, edx
            668B0C4B             | f..K                 | mov cx, [ebx+2*ecx]
            8B581C               | .X.                  | mov ebx, [eax+0x1c]
            01D3                 | ..                   | add ebx, edx
            8B048B               | ...                  | mov eax, [ebx+4*ecx]
            01D0                 | ..                   | add eax, edx
        */
    
        strings:
            $a   = { 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e0 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_tcp_nx_allports_finish_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_tcp_nx_allports::finish"
    
        /*
            89442424             | .D$$                 | mov [esp+0x24], eax
            5B                   | [                    | pop ebx
            5B                   | [                    | pop ebx
            61                   | a                    | popad
            59                   | Y                    | pop ecx
            5A                   | Z                    | pop edx
            51                   | Q                    | push ecx
            FFE0                 | ..                   | jmp eax
        */
    
        strings:
            $a   = { 89 44 24 24 5b 5b 61 59 5a 51 ff e0 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_tcp_nx_allports_get_next_mod1_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_tcp_nx_allports::get_next_mod1"
    
        /*
            5F                   | _                    | pop edi
            5A                   | Z                    | pop edx
            8B12                 | ..                   | mov edx, [edx]
            EB83                 | ..                   | jmp next_mod
        */
    
        strings:
            $a   = { 5f 5a 8b 12 eb 83 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_tcp_nx_allports_reverse_tcp_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_tcp_nx_allports::reverse_tcp"
    
        /*
            6833320000           | h32..                | push 0x00003233
            687773325F           | hws2_                | push 0x5f327377
            54                   | T                    | push esp
            684C772607           | hLw&.                | push 0x0726774c	; LoadLibraryA
            FFD5                 | ..                   | call ebp
            B890010000           | .....                | mov eax, 0x0190
            29C4                 | ).                   | sub esp, eax
            54                   | T                    | push esp
            50                   | P                    | push eax
            6829806B00           | h).k.                | push 0x006b8029	; WSAStartup
            FFD5                 | ..                   | call ebp
            50                   | P                    | push eax
            50                   | P                    | push eax
            50                   | P                    | push eax
            50                   | P                    | push eax
            40                   | @                    | inc eax
            50                   | P                    | push eax
            40                   | @                    | inc eax
            50                   | P                    | push eax
            68EA0FDFE0           | h....                | push 0xe0df0fea	; WSASocketA
            FFD5                 | ..                   | call ebp
            97                   | .                    | xchg edi, eax
        */
    
        strings:
            $a   = { 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 50 50 50 50 40 50 40 50 68 ea 0f df e0 ff d5 97 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_tcp_nx_allports_set_address_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_tcp_nx_allports::set_address"
    
        /*
            68????????           | h....                | push 0x0100007f	; Host
            680200????           | h...\                | push 0x5c110002	; Port
            89E6                 | ..                   | mov esi, esp
        */
    
        strings:
            $a   = { 68 ?? ?? ?? ?? 68 02 00 ?? ?? 89 e6 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_tcp_nx_allports_try_connect_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_tcp_nx_allports::try_connect"
    
        /*
            6A10                 | j.                   | push byte 16
            56                   | V                    | push esi
            57                   | W                    | push edi
            6899A57461           | h..ta                | push 0x6174a599	; connect
            FFD5                 | ..                   | call ebp
            85C0                 | ..                   | test eax,eax
            740F                 | t.                   | jz short connected
        */
    
        strings:
            $a   = { 6a 10 56 57 68 99 a5 74 61 ff d5 85 c0 74 0f }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_tcp_nx_allports_port_bump_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_tcp_nx_allports::port_bump"
    
        /*
            668B4602             | f.F.                 | mov word ax, [esi+2]
            86E0                 | ..                   | xchg ah,al
            40                   | @                    | inc eax
            86E0                 | ..                   | xchg ah,al
            66894602             | f.F.                 | mov word [esi+2], ax
            EBE2                 | ..                   | jmp short try_connect
        */
    
        strings:
            $a   = { 66 8b 46 02 86 e0 40 86 e0 66 89 46 02 eb e2 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_tcp_nx_allports_recv_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_tcp_nx_allports::recv"
    
        /*
            6A00                 | j.                   | push byte 0
            6A04                 | j.                   | push byte 4
            56                   | V                    | push esi
            57                   | W                    | push edi
            6802D9C85F           | h..._                | push 0x5fc8d902	; recv
            FFD5                 | ..                   | call ebp
            8B36                 | .6                   | mov esi, [esi]
            6A40                 | j@                   | push byte 0x40
            6800100000           | h....                | push 0x1000
            56                   | V                    | push esi
            6A00                 | j.                   | push byte 0
            6858A453E5           | hX.S.                | push 0xe553a458	; VirtualAlloc
            FFD5                 | ..                   | call ebp
            93                   | .                    | xchg ebx, eax
            53                   | S                    | push ebx
        */
    
        strings:
            $a   = { 6a 00 6a 04 56 57 68 02 d9 c8 5f ff d5 8b 36 6a 40 68 00 10 00 00 56 6a 00 68 58 a4 53 e5 ff d5 93 53 }
    
        condition:
            any of them
    }
    
    
    rule stager_reverse_tcp_nx_allports_read_more_x86
    {
        meta:
            desc = "Metasploit::windows::x86::stager_reverse_tcp_nx_allports::read_more"
    
        /*
            6A00                 | j.                   | push byte 0
            56                   | V                    | push esi
            53                   | S                    | push ebx
            57                   | W                    | push edi
            6802D9C85F           | h..._                | push 0x5fc8d902	; recv
            FFD5                 | ..                   | call ebp
            01C3                 | ..                   | add ebx, eax
            29C6                 | ).                   | sub esi, eax
            75EE                 | u.                   | jnz read_more
            C3                   | .                    | ret
        */
    
        strings:
            $a   = { 6a 00 56 53 57 68 02 d9 c8 5f ff d5 01 c3 29 c6 75 ee c3 }
    
        condition:
            any of them
    }
    
    