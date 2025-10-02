##############################################################################
# Get-ExeInformation.ps1 
# Elizabeth Greene <elizabeth.a.greene@gmail.com>
##############################################################################
<#
.SYNOPSIS
    Extracts architecture and Characteristics flags from a Windows PE executable.
.DESCRIPTION
    Reads a Windows executable file to determine its architecture (e.g., x86, x64, ARM) and parses the PE Characteristics flags, including Large Address Aware (LAA) status. Uses the Microsoft PE format specification.
.PARAMETER FilePath
    Path to the executable file to analyze. Defaults to C:\Windows\System32\notepad.exe.
.EXAMPLE
    .\Get-ExeInformation.ps1 "C:\Windows\SysWOW64\notepad.exe"
    Analyzes the specified executable and outputs its Machine Type and Characteristics.
.NOTES
    Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
#>

# Check for input argument and if not provided, use default path
if ($args.Count -gt 0) {
    $filePath = $args[0]
}
else {
    # Default path if no argument is provided  
    $filePath = "C:\windows\system32\notepad.exe"
}

function Get-MachineTypeDescription {
    param (
        [int]$MachineType
    )

    # Parse Machine Type
    $machineTypes = @{
        0x0    = 'UNKNOWN-Assumed to be applicable to any machine type (This is uncommon and typically indicates a malformed file)'
        0x184  = 'ALPHA-Alpha AXP, 32-bit address space (This is uncommon and typically indicates a malformed file)'
        0x284  = 'ALPHA64-Alpha 64, AKA AXP64-AXP, 64-bit address space (This is uncommon and typically indicates a malformed file)'
        0x1d3  = 'AM33-Matsushita AM33 (This is uncommon and typically indicates a malformed file)'
        0x8664	= 'AMD64-x64 AKA x64'
        0x1c0  = 'ARM-ARM little endian (This is uncommon and typically indicates a malformed file)'
        0xaa64	= 'ARM64-ARM64 little endian'
        0xA641	= 'ARM64EC-ABI that enables interoperability between native ARM64 and emulated x64 code.  (This is uncommon and typically indicates a malformed file)'
        0xA64E	= 'ARM64X-Binary format that allows both native ARM64 and ARM64EC code to coexist in the same file. (This is uncommon and typically indicates a malformed file)'
        0x1c4  = 'ARMNT-ARM Thumb-2 little endian (This is uncommon and typically indicates a malformed file)'
        0xebc  = 'EBC-EFI byte code (This is uncommon and typically indicates a malformed file)'
        0x14c  = 'I386-Intel 386 or later processors and compatible processors AKA x86 32-bit'
        0x200  = 'IA64-Intel Itanium processor family (This is uncommon and typically indicates a malformed file)'
        0x6232	= 'LOONGARCH32-LoongArch 32-bit processor family (This is uncommon and typically indicates a malformed file)'
        0x6264	= 'LOONGARCH64-LoongArch 64-bit processor family (This is uncommon and typically indicates a malformed file)'
        0x9041	= 'M32R-Mitsubishi M32R little endian (This is uncommon and typically indicates a malformed file)'
        0x266  = 'MIPS16-MIPS16 (This is uncommon and typically indicates a malformed file)'
        0x366  = 'MIPSFPU-MIPS with FPU (This is uncommon and typically indicates a malformed file)'
        0x466  = 'MIPSFPU16-MIPS16 with FPU (This is uncommon and typically indicates a malformed file)'
        0x1f0  = 'POWERPC-Power PC little endian (This is uncommon and typically indicates a malformed file)'
        0x1f1  = 'POWERPCFP-Power PC with floating point support (This is uncommon and typically indicates a malformed file)'
        0x160  = 'R3000BE-MIPS I compatible 32-bit big endian (This is uncommon and typically indicates a malformed file)'
        0x162  = 'R3000-MIPS I compatible 32-bit little endian (This is uncommon and typically indicates a malformed file)'
        0x166  = 'R4000-MIPS III compatible 64-bit little endian (This is uncommon and typically indicates a malformed file)'
        0x168  = 'R10000-MIPS IV compatible 64-bit little endian (This is uncommon and typically indicates a malformed file)'
        0x5032	= 'RISCV32-RISC-V 32-bit address space (This is uncommon and typically indicates a malformed file)'
        0x5064	= 'RISCV64-RISC-V 64-bit address space (This is uncommon and typically indicates a malformed file)'
        0x5128	= 'RISCV128-RISC-V 128-bit address space (This is uncommon and typically indicates a malformed file)'
        0x1a2  = 'SH3-Hitachi SH3 (This is uncommon and typically indicates a malformed file)'
        0x1a3  = 'SH3DSP-Hitachi SH3 DSP (This is uncommon and typically indicates a malformed file)'
        0x1a6  = 'SH4-Hitachi SH4 (This is uncommon and typically indicates a malformed file)'
        0x1a8  = 'SH5-Hitachi SH5 (This is uncommon and typically indicates a malformed file)'
        0x1c2  = 'THUMB-Thumb (This is uncommon and typically indicates a malformed file)'
        0x169  = 'WCEMIPSV2-MIPS little-endian WCE v2 (This is uncommon and typically indicates a malformed file)'
    }

    if ($machineTypes.ContainsKey($MachineType)) {
        return $machineTypes[$MachineType]
    }
    else {
        return 'Unknown'
    }
}

function Get-Characteristics {
    param (
        [int]$Characteristics
    )

    # Parse Characteristics
    $characteristicsFlags = @{
        0x0001 = 'Relocations Stripped'
        0x0002 = 'Executable Image'
        0x0004 = 'Line Numbers Stripped (Deprecated) (Should be False)'
        0x0008 = 'Local Symbols Stripped (Deprecated) (Should be False)'
        0x0010 = 'Aggressively Trim Working Set (Deprecated) (Should be False)'
        0x0020 = 'Large Address Aware (Allows 32-bit applications > 2GB of memory on 64-bit Windows)'
        0x0040 = 'Reserved (Should be False)'
        0x0080 = 'Little Endian (Deprecated) (Should be False)'
        0x0100 = '32-bit Machine'
        0x0200 = 'Debug Stripped'
        0x0400 = 'Removable Run From Swap'
        0x0800 = 'Net Run From Swap'
        0x1000 = 'System File'
        0x2000 = 'DLL'
        0x4000 = 'Uniprocessor Only'
        0x8000 = 'Big Endian (Deprecated) (Should be False)'
    }

    foreach ($flag in $characteristicsFlags.Keys | Sort-Object) {
        $isSet = ($Characteristics -band $flag) -eq $flag
        $description = $characteristicsFlags[$flag]
        Write-Output "0x$($flag.ToString('X4')): $isSet - $description"
    }
}
if (-not (Test-Path $filePath -PathType Leaf)) {
    Write-Error "File '$filePath' does not exist or is not a file."
    exit 1
}
try {
    $bytes = [System.IO.File]::ReadAllBytes($filePath)
}
catch {
    Write-Error "Failed to read file '$filePath': $_"
    exit 1
}

Write-Output $filePath
if ($bytes.Length -lt 0x3c) {
    Write-Error "File is too small to contain DOS Signature and PE Header (length: $($bytes.Length) bytes)."
    exit 1
}

# Verify DOS header
$dosSignature = [System.Text.Encoding]::ASCII.GetString($bytes, 0, 2)
if ($dosSignature -ne "MZ") {
    Write-Error  "Invalid PE file: DOS Signature is '$dosSignature' and should be 'MZ'"
    exit
}

# Get PE header offset from 0x3C
$peOffset = [System.BitConverter]::ToUInt32($bytes, 0x3C)
Write-Output "PE Header Offset: 0x$($peOffset.ToString('X8'))"

if ($bytes.Length -lt ($peOffset + 22)) {
    Write-Error "File is too small to contain PE header data and characteristics (length: $($bytes.Length) bytes)."
    exit 1
}

# Verify PE signature
$peSignature = [System.Text.Encoding]::ASCII.GetString($bytes, $peOffset, 4)
if ($peSignature -ne "PE`0`0") {
    Write-Error  "Invalid PE file: Signature is '$peSignature' and should be 'PE(null)(null)'"
    exit
}
Write-Output "PE Signature: $peSignature"

$machineType = [System.BitConverter]::ToUInt16($bytes, $peOffset + 4)
Write-Output "Machine Type: 0x$($machineType.ToString('X4'))"
Write-Output "Machine Type Description: $(Get-MachineTypeDescription -MachineType $machineType)"

# Read Characteristics at peOffset + 4 + 18 (COFF header offset 0x12)
$characteristics = [System.BitConverter]::ToUInt16($bytes, $peOffset + 22)
Write-Output "Characteristics: 0x$($characteristics.ToString('X4'))"
# Call the function

Write-Output "----------------"
Get-Characteristics -Characteristics $characteristics