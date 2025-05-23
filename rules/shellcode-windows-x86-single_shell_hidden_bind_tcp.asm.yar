
    rule single_shell_hidden_bind_tcp___start0___x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_hidden_bind_tcp::__start0__"
    
        /*
            FC                   | .                    | cld
            E88C000000           | .....                | call start
        */
    
        strings:
            $a   = { fc e8 8c 00 00 00 }
    
        condition:
            any of them
    }
    
    
    rule single_shell_hidden_bind_tcp_api_call_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_hidden_bind_tcp::api_call"
    
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
    
    
    rule single_shell_hidden_bind_tcp_next_mod_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_hidden_bind_tcp::next_mod"
    
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
    
    
    rule single_shell_hidden_bind_tcp_loop_modname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_hidden_bind_tcp::loop_modname"
    
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
    
    
    rule single_shell_hidden_bind_tcp_not_lowercase_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_hidden_bind_tcp::not_lowercase"
    
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
    
    
    rule single_shell_hidden_bind_tcp_get_next_func_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_hidden_bind_tcp::get_next_func"
    
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
    
    
    rule single_shell_hidden_bind_tcp_loop_funcname_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_hidden_bind_tcp::loop_funcname"
    
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
    
    
    rule single_shell_hidden_bind_tcp_finish_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_hidden_bind_tcp::finish"
    
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
    
    
    rule single_shell_hidden_bind_tcp_get_next_mod1_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_hidden_bind_tcp::get_next_mod1"
    
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
    
    
    rule single_shell_hidden_bind_tcp_bind_tcp_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_hidden_bind_tcp::bind_tcp"
    
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
            31DB                 | 1.                   | xor ebx, ebx
            53                   | S                    | push ebx
            680200????           | h...\                | push 0x5c110002	; Port
            89E6                 | ..                   | mov esi, esp
            6A10                 | j.                   | push byte 16
            56                   | V                    | push esi
            57                   | W                    | push edi
            68C2DB3767           | h..7g                | push 0x6737dbc2	; bind
            FFD5                 | ..                   | call ebp
            6A01                 | j.                   | push 0x1
            54                   | T                    | push esp
            6802300000           | h.0..                | push 0x3002
            68FFFF0000           | h....                | push 0xffff
            57                   | W                    | push edi
            68F1A27729           | h..w)                | push 0x2977a2f1	; setsockopt
            FFD5                 | ..                   | call ebp
            53                   | S                    | push ebx
            57                   | W                    | push edi
            68B7E938FF           | h..8.                | push 0xff38e9b7	; listen
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 50 50 50 50 40 50 40 50 68 ea 0f df e0 ff d5 97 31 db 53 68 02 00 ?? ?? 89 e6 6a 10 56 57 68 c2 db 37 67 ff d5 6a 01 54 68 02 30 00 00 68 ff ff 00 00 57 68 f1 a2 77 29 ff d5 53 57 68 b7 e9 38 ff ff d5 }
    
        condition:
            any of them
    }
    
    
    rule single_shell_hidden_bind_tcp_condition_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_hidden_bind_tcp::condition"
    
        /*
            53                   | S                    | push ebx
            E817000000           | .....                | call wsaaccept
            8B442404             | .D$.                 | mov eax, dword [esp+4]
            8B4004               | .@.                  | mov eax, dword [eax+4]
            8B4004               | .@.                  | mov eax, dword [eax+4]
            2DC0A80121           | -...!                | sub eax, 0x2101a8c0
            7403                 | t.                   | jz return
            31C0                 | 1.                   | xor eax, eax
            40                   | @                    | inc eax
        */
    
        strings:
            $a   = { 53 e8 17 00 00 00 8b 44 24 04 8b 40 04 8b 40 04 2d c0 a8 01 21 74 03 31 c0 40 }
    
        condition:
            any of them
    }
    
    
    rule single_shell_hidden_bind_tcp_wsaaccept_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_hidden_bind_tcp::wsaaccept"
    
        /*
            53                   | S                    | push ebx
            53                   | S                    | push ebx
            57                   | W                    | push edi
            6894ACBE33           | h...3                | push 0x33beac94	; WSAAccept
            FFD5                 | ..                   | call ebp
            40                   | @                    | inc eax
            74D6                 | t.                   | jz condition
            48                   | H                    | dec eax
            57                   | W                    | push edi
            97                   | .                    | xchg edi, eax
            68756E4D61           | hunMa                | push 0x614d6e75	; closesocket
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 53 53 57 68 94 ac be 33 ff d5 40 74 d6 48 57 97 68 75 6e 4d 61 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule single_shell_hidden_bind_tcp_shell_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_hidden_bind_tcp::shell"
    
        /*
            68636D6400           | hcmd.                | push 0x00646d63
            89E3                 | ..                   | mov ebx, esp
            57                   | W                    | push edi
            57                   | W                    | push edi
            57                   | W                    | push edi
            31F6                 | 1.                   | xor esi, esi
            6A12                 | j.                   | push byte 18
            59                   | Y                    | pop ecx
        */
    
        strings:
            $a   = { 68 63 6d 64 00 89 e3 57 57 57 31 f6 6a 12 59 }
    
        condition:
            any of them
    }
    
    
    rule single_shell_hidden_bind_tcp_push_loop_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_hidden_bind_tcp::push_loop"
    
        /*
            56                   | V                    | push esi
            E2FD                 | ..                   | loop push_loop
            66C744243C0101       | f.D$<..              | mov word [esp + 60], 0x0101
            8D442410             | .D$.                 | lea eax, [esp + 16]
            C60044               | ..D                  | mov byte [eax], 68
            54                   | T                    | push esp
            50                   | P                    | push eax
            56                   | V                    | push esi
            56                   | V                    | push esi
            56                   | V                    | push esi
            46                   | F                    | inc esi
            56                   | V                    | push esi
            4E                   | N                    | dec esi
            56                   | V                    | push esi
            56                   | V                    | push esi
            53                   | S                    | push ebx
            56                   | V                    | push esi
            6879CC3F86           | hy.?.                | push 0x863fcc79	; CreateProcessA
            FFD5                 | ..                   | call ebp
            89E0                 | ..                   | mov eax, esp
            4E                   | N                    | dec esi
            56                   | V                    | push esi
            46                   | F                    | inc esi
            FF30                 | .0                   | push dword [eax]
            6808871D60           | h...`                | push 0x601d8708	; WaitForSingleObject
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 56 e2 fd 66 c7 44 24 3c 01 01 8d 44 24 10 c6 00 44 54 50 56 56 56 46 56 4e 56 56 53 56 68 79 cc 3f 86 ff d5 89 e0 4e 56 46 ff 30 68 08 87 1d 60 ff d5 }
    
        condition:
            any of them
    }
    
    
    rule single_shell_hidden_bind_tcp_exitfunk_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_hidden_bind_tcp::exitfunk"
    
        /*
            BBE01D2A0A           | ...*.                | mov ebx, 0x0a2a1de0
            68A695BD9D           | h....                | push 0x9dbd95a6	; GetVersion
            FFD5                 | ..                   | call ebp
            3C06                 | <.                   | cmp al, byte 6
            7C0A                 | |.                   | jl short goodbye
            80FBE0               | ...                  | cmp bl, 0xe0
            7505                 | u.                   | jne short goodbye
            BB4713726F           | .G.ro                | mov ebx, 0x6f721347
        */
    
        strings:
            $a   = { bb e0 1d 2a 0a 68 a6 95 bd 9d ff d5 3c 06 7c 0a 80 fb e0 75 05 bb 47 13 72 6f }
    
        condition:
            any of them
    }
    
    
    rule single_shell_hidden_bind_tcp_goodbye_x86
    {
        meta:
            desc = "Metasploit::windows::x86::single_shell_hidden_bind_tcp::goodbye"
    
        /*
            6A00                 | j.                   | push byte 0
            53                   | S                    | push ebx
            FFD5                 | ..                   | call ebp
        */
    
        strings:
            $a   = { 6a 00 53 ff d5 }
    
        condition:
            any of them
    }
    
    