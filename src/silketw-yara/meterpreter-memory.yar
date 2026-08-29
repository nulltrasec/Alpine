/*
  Alpine Project - Meterpreter Memory & Reflective DLL Injection Signatures
  Purpose: Detects fileless in-memory Meterpreter stagers and Reflective DLL loaders
           in process memory (e.g. injected into explorer.exe or powershell.exe).
*/

rule Meterpreter_Reflective_Loader_x64
{
    meta:
        description = "Detects x64 Meterpreter position-independent shellcode and PEB traversal"
        author = "Alpine Detection Engineering Team"
        reference = "MITRE ATT&CK T1055.002 - Portable Executable Injection"
        threat_score = "100"
    strings:
        // 1. Position Independent Shellcode initiation: CLD instruction
        $cld = { FC }

        // 2. Accessing TEB / PEB via GS register on x64:
        //    mov rax, gs:[60h] (PEB) or mov rax, gs:[30h] (TEB)
        $peb_lookup_1 = { 65 48 8B 04 25 60 00 00 00 }
        $peb_lookup_2 = { 65 48 8B 14 25 60 00 00 00 }
        $peb_lookup_3 = { 65 48 8B (00|01|02|03|04|05|06|07) 60 00 00 00 }

        // 3. Known Metasploit ROR-13 API Hashing Constants:
        //    LoadLibraryA:           0xEC0E4E8E -> 8E 4E 0E EC
        //    GetProcAddress:         0x7C0DFCAA -> AA FC 0D 7C
        //    VirtualAlloc:           0x91AFCA54 -> 54 CA AF 91
        //    NtFlushInstructionCache:0x534C0AB8 -> B8 0A 4C 53
        $hash_LoadLibraryA            = { 8E 4E 0E EC }
        $hash_GetProcAddress          = { AA FC 0D 7C }
        $hash_VirtualAlloc            = { 54 CA AF 91 }
        $hash_NtFlushInstructionCache = { B8 0A 4C 53 }

        // 4. Critical DLL strings queried dynamically
        $dll1 = "ws2_32.dll" ascii wide nocase
        $dll2 = "kernel32.dll" ascii wide nocase
        $dll3 = "ntdll.dll" ascii wide nocase

    condition:
        $cld and
        any of ($peb_lookup_*) and
        (2 of ($hash_*)) and
        (any of ($dll*))
}

rule Meterpreter_Fileless_Memory_RWX
{
    meta:
        description = "Detects characteristic stager call/pop and socket initialization markers"
        author = "Alpine Detection Engineering Team"
        threat_score = "90"
    strings:
        // Call $+5 followed by pop reg to obtain RIP/EIP
        $call_pop = { E8 00 00 00 00 (58|59|5A|5B|5C|5D|5E|5F) }

        // Standard Metasploit reverse TCP payload socket connection preamble
        $sock_init = { 68 02 00 } // AF_INET constant (AF_INET=2) in sockaddr structure
    condition:
        $call_pop and $sock_init
}
