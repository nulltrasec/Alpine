# Reverse Engineering Meterpreter: In-Memory Reflective DLL Injection

## 1. Executive Summary

As part of the Alpine threat analysis pipeline, the malicious PowerShell stager payload dropped during the initial foothold phase was extracted, formatted into pure raw shellcode, and analyzed through static disassembly in **Ghidra** and dynamic debugging in **x64dbg** via **BlobRunner**.

The objective of this analysis was to uncover the evasion mechanisms used by the fileless stager, map how it interacts with low-level Windows kernel structures, and derive high-fidelity YARA signatures for in-memory memory inspection.

---

## 2. Static Behavioral Analysis (Ghidra Disassembly)

### Initial Shellcode Preamble
Upon loading the extracted binary into Ghidra, the entry point revealed characteristic markers of position-independent shellcode (PIC):

```assembly
cld                         ; Clear Direction Flag (DF=0) ensuring string operations increment
call    fn_get_rip          ; Call immediate next instruction
fn_get_rip:
pop     rbx                 ; Pop return address off the stack to determine runtime base RIP
```

* **`CLD` Instruction**: Ensures string processing instructions (`LODSD`, `MOVSB`) iterate forward. Position-independent shellcode standardizes the direction flag immediately to avoid crashing on unpredictable host register states.
* **`CALL / POP` Primitive**: Because shellcode is injected into arbitrary memory locations without relocation tables, it must establish its own Instruction Pointer (`RIP`/`EIP`). Popping the return address off the stack provides the dynamic memory anchor.

---

## 3. Dynamic Analysis & Kernel Structure Traversal (x64dbg / BlobRunner)

When inspecting the binary in x64dbg under BlobRunner, the debugger revealed that strings were absent except for `ws2_32.dll`. Instead of standard Windows API calls, the binary performed manual runtime dependency resolution using **ROR-13 hashing** and user-mode kernel structures.

### Step 1: Accessing the Process Environment Block (PEB)
Because shellcode cannot safely call Win32 APIs before finding where the libraries reside, it leverages CPU segment registers:
* In 64-bit Windows, the `GS` segment register points directly to the **Thread Environment Block (TEB)**.
* At offset `0x60` within the TEB resides the pointer to the **Process Environment Block (PEB)**:
  ```assembly
  mov     rax, gs:[0x60]    ; rax = Pointer to PEB
  ```

### Step 2: Traversing `InMemoryOrderModuleList`
Within the PEB, the shellcode accesses `PEB_LDR_DATA` at offset `0x18`, which points to the `InMemoryOrderModuleList` doubly linked list:
```assembly
mov     rax, [rax + 0x18]   ; rax = PEB->Ldr
mov     rsi, [rax + 0x20]   ; rsi = InMemoryOrderModuleList (Flink)
```
In modern Windows operating systems, the traversal order of this linked list is rigidly consistent:
1. First node: The host executable image (`explorer.exe`).
2. Second node: `ntdll.dll`.
3. Third node: `kernel32.dll`.

### Step 3: Export Address Table (EAT) Parsing & ROR-13 Hash Resolution
Once the base address of `kernel32.dll` is located, the stager parses its Portable Executable (PE) headers to locate the **Export Address Table (EAT)**. It extracts each exported function name, computes a 13-bit right-rotation hash (`ROR-13`), and compares it against pre-computed constants shipped in the payload:

| Target Win32 API Function | ROR-13 Hash Constant | Purpose in Stager |
|---|---|---|
| **`LoadLibraryA`** | `0xEC0E4E8E` | Dynamically load `ws2_32.dll` for C2 socket communication |
| **`GetProcAddress`** | `0x7C0DFCAA` | Resolve additional network and memory manipulation symbols |
| **`VirtualAlloc`** | `0x91AFCA54` | Allocate `PAGE_EXECUTE_READWRITE` (RWX) memory region |
| **`NtFlushInstructionCache`** | `0x534C0AB8` | Synchronize instruction pipeline after copying payload |

---

## 4. Evasion Rationale: Why Adversaries Bypass the Windows PE Loader

Standard Windows applications depend on the operating system's built-in **PE Loader** (`ntdll!LdrLoadDll`), which automatically parses the executable's Import Address Table (IAT) and resolves dependencies at launch.

Adversaries deliberately avoid the standard loader because:
1. **EDR Hooking**: Modern Endpoint Detection and Response (EDR) sensors place inline API hooks on `ntdll.dll` and `kernel32.dll` loader functions to detect suspicious library loading.
2. **IAT Invisibility**: Injected shellcode has no disk backing and no standard IAT. Resolving addresses directly from the EAT completely bypasses API monitoring and leaves standard forensic tools blind.

---

## 5. Defensive Engineering & YARA Rule Derivation

From this reverse-engineering walkthrough, two custom YARA rules were developed to detect fileless in-memory injection in Project Alpine:
* **`Meterpreter_Reflective_Loader_x64`**: Scans for the `cld` opcode, `GS:[0x60]` PEB dereferencing byte sequences, and the specific ROR-13 hashing constants for `LoadLibraryA` and `VirtualAlloc`.
* **`Meterpreter_Fileless_Memory_RWX`**: Identifies anomalous unbacked memory pages allocated with `PAGE_EXECUTE_READWRITE` permissions hosting the characteristic `CALL/POP` pattern.
