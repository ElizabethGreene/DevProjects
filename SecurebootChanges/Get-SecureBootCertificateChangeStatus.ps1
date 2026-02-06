##############################################################################
# Get-SecureBootCertificateChangeStatus.ps1
# Retrieves the status of Secure Boot certificate changes on a Windows system.
# Elizabeth Greene <elizabeth.a.greene@gmail.com>
##############################################################################
<#
.SYNOPSIS
Retrieves the status of Secure Boot certificate changes on a Windows system.

.DESCRIPTION
Checks Secure Boot enablement, UEFI trust of the 2023 CA certificate, revocation of the 2011 CA certificate,
SVN presence in dbx, and whether bootmgfw.efi has been updated with the new certificate, and returns these values plus a summary flag value. 
Requires administrative privileges to run.

.EXAMPLE
Get-SecureBootCertificateChangeStatus
#>

#Requires -RunAsAdministrator
function Get-BootLoaderPath {
    # This finds the path to the bootloader. 

    # The authoritative source for this information is the Boot Configuration Data (BCD)
    # There are powershell commands to interact with BCD, but they are Win11 only and blocked by some AV products.
    # So we parse the output of bcdedit to get this data. 
    # It is unknown if this will break with localization.
    # If it does, refactor to read BCD via hklm\BCD00000000 The boot manager guid is {9dea862c-5cdd-4e70-acc1-f32b344d4795}, device is 11000001 and path is 12000002 

    $bcdOutput = bcdedit /enum bootmgr
    $bcdText = $bcdOutput -join "`n"
    # Matches lines like:
    # device                  partition=S:
    # or
    # device                  partition=\Device\HarddiskVolume1
    # path                    \EFI\Microsoft\Boot\bootmgfw.efi

    $deviceMatch = $bcdText -match 'device\s+partition=(.+?)(?:\r?\n|$)'

    if ($deviceMatch) {
        $device = $Matches[1].Trim()
    } else {
        throw "Get-BootloaderPath failed, unable to parse BCDedit device output."
    }

    $pathMatch = $bcdText -match 'path\s+(.+?)(?:\r?\n|$)'

    if ($pathMatch) {
        $path = $Matches[1].Trim()
    } else {
        throw "Get-BootloaderPath failed, unable to parse BCDedit path output."
    }

    $bootLoaderPath  = Join-Path $device $path

    # If the path does not start with a drive letter, then it has to be accessed via the device path.
    # Device paths look like this: \\?\GLOBALROOT\Device\HarddiskVolume1\EFI\Microsoft\Boot\bootmgfw.efi
    # Add on the \\?\GLOBALROOT\ prefix to access the file via the device path.    

    if ($device -notmatch '^[a-zA-Z]:') {
        $bootLoaderPath = Join-Path "\\?\GLOBALROOT\" $bootLoaderPath
    }

    if (-not (Test-Path -LiteralPath $bootLoaderPath -ErrorAction Continue)) {
        throw "Get-BootloaderPath failed, Bootloader '$bootLoaderPath' does not exist or cannot be accessed."
    }

    write-host $bootLoaderPath
    Return $bootLoaderPath
}

function Get-SVNFromDBX {
    <#
.SYNOPSIS

Parses the bootloader SVN information from the UEFI DBX database.

.DESCRIPTION

Author: Elizabeth Greene <elizabeth.a.greene@gmail.com>
https://github.com/ElizabethGreene/UEFITools
License: BSD 3-Clause

Forked from work by Matthew Graeber (@mattifestation)
https://gist.github.com/mattifestation/1a0f93714ddbabdbac4ad6bcc0f311f3


.EXAMPLE

Get-SecureBootUEFI dbx | Get-SVNFromDBX

.INPUTS

Microsoft.SecureBoot.Commands.UEFIEnvironmentVariable

Accepts the output of Get-SecureBootUEFI over the pipeline.

.OUTPUTS

Outputs a PSObject consisting of the SVN GUID and values.
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $Variable
    )

    $Results = @{}

    $SignatureTypeMapping = @{
        'C1C41626-504C-4092-ACA9-41F936934328' = 'EFI_CERT_SHA256_GUID' # Most often used for dbx
        'A5C059A1-94E4-4AA7-87B5-AB155C2BF072' = 'EFI_CERT_X509_GUID'   # Most often used for db
    }

    $SvnOwnerGuid = [Guid]::Parse("9d132b6c-59d5-4388-ab1c-185cfcb2eb92")

    try {
        [System.IO.MemoryStream]$MemoryStream = New-Object System.IO.MemoryStream -ArgumentList @(, $Variable.Bytes)
        [System.IO.BinaryReader]$BinaryReader = New-Object System.IO.BinaryReader -ArgumentList $MemoryStream
    
        # What follows will be an array of EFI_SIGNATURE_LIST structs

        while ($MemoryStream.Position -lt $MemoryStream.Length) {
            $SignatureType = $SignatureTypeMapping[([Guid][Byte[]] $BinaryReader.ReadBytes(16)).Guid]
            $SignatureListSize = $BinaryReader.ReadUInt32()
            $SignatureHeaderSize = $BinaryReader.ReadUInt32()
            $SignatureSize = $BinaryReader.ReadUInt32()

            # Read and discard the signature header, if present
            $SignatureHeader = $BinaryReader.ReadBytes($SignatureHeaderSize)

            # 0x1C is the size of the EFI_SIGNATURE_LIST header
            $SignatureCount = ($SignatureListSize - 0x1C) / $SignatureSize

            1..$SignatureCount | ForEach-Object {
                $SignatureDataBytes = $BinaryReader.ReadBytes($SignatureSize)

                $SignatureOwner = [Guid][Byte[]] $SignatureDataBytes[0..15]

                if ($SignatureType -eq 'EFI_CERT_SHA256_GUID') {
                    if ($SignatureOwner -eq $SvnOwnerGuid) {
                        #After the owner GUID
                        #Byte 0: version (unpacked as a 1-byte unsigned integer with "B").
                        #Bytes 1-16: UUID (16 bytes sliced directly as data[1:17]—Python slicing is end-exclusive, so this captures bytes 1 through 16).
                        #Bytes 17,18. UINT16 minor SVN
                        #Bytes 19-20: UINT16 major SVN
                        #Bytes 21-31: reserved

                        $Version = $SignatureDataBytes[16]
                        if ($Version -ne 1) {
                            throw "Unexpected SVN structure version $Version, an update to the script to support new SVN format is required."
                        }
                        
                        $EntryGuid = New-Object System.Guid -ArgumentList @(, ([Byte[]] $SignatureDataBytes[17..32]))                    
                        # Read numeric SVN parts as integers
                        $MinorSvn = [int][BitConverter]::ToUInt16($SignatureDataBytes, 33)
                        $MajorSvn = [int][BitConverter]::ToUInt16($SignatureDataBytes, 35)                                        
                        $EntryObject = [PSCustomObject]@{
                            Guid  = $EntryGuid
                            Major = $MajorSvn
                            Minor = $MinorSvn
                        }

                        if ($Results.ContainsKey($EntryGuid)) {
                            $Existing = $Results[$EntryGuid]
                            if (($Existing.Major -lt $MajorSvn) -or (($Existing.Major -eq $MajorSvn) -and ($Existing.Minor -lt $MinorSvn))) {
                                $Results[$EntryGuid] = $EntryObject
                            }
                        }
                        else {
                            $Results[$EntryGuid] = $EntryObject
                        }
                    }
                }
            }
        }
    }
    catch {
        throw $_
        return
    }
    finally {
        if ($BinaryReader) { $BinaryReader.Dispose() }
        if ($MemoryStream) { $MemoryStream.Dispose() }
    }
    return $Results.Values | ForEach-Object {
        [PSCustomObject]@{ 
            Guid = [Guid]$_.Guid; 
            Svn  = "{0}.{1}" -f $_.Major, $_.Minor
        } 
    }
}

function Get-SecureBootCertificateChangeStatus {
    <#
    .SYNOPSIS
    Retrieves the status of Secure Boot certificate changes on a Windows system.

    .DESCRIPTION
    This function checks the Secure Boot configuration and retrieves the status of any certificate changes.
    It returns information about whether Secure Boot is enabled and details about any recent certificate changes.

    .EXAMPLE
    PS C:\> Get-SecureBootCertificateChangeStatus

    Retrieves the Secure Boot certificate change status.

    .NOTES
    #>
    [CmdletBinding()]
    param ()

    # Create a custom object to hold the results
    $result = [PSCustomObject]@{
        SecureBootEnabled                = $false
        UEFITrustsNew2023CACertificate   = $false
        UEFIRevokedOld2011CACertificate  = $false
        SVNEnabled                       = $false
        BootloaderUpdated                = $false
        Error                            = $true
        # This is a binary flag value that summarizes the status of all checks.
        # It's for tools that can only handle a single integer value, e.g. like the return value from a compliance script.
        # Bit 0 (1): Secure Boot Enabled
        # Bit 1 (2): UEFI Trusts New 2023 CA Certificate
        # Bit 2 (4): UEFI Revoked Old 2011 CA Certificate
        # Bit 3 (8): SVN Enabled
        # Bit 4 (16): Bootloader Updated
        # Bit 7 (128): Error Occurred
        FlagValue                        = $null
    }

    try {
        # Check if Secure Boot is enabled
        $result.SecureBootEnabled = Confirm-SecureBootUEFI

        $result.UEFITrustsNew2023CACertificate = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023'

        $result.UEFIRevokedOld2011CACertificate = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbx).bytes) -match 'Microsoft Windows Production PCA 2011' 
        
        # SVN Check
        if (Get-SecureBootUEFI dbx | Get-SVNFromDBX) {
            $result.SVNEnabled = $true
        }

        # The most complex of these is determining if the bootloader on the EFI system partition has the new signature.
        $bootManagerSignature = Get-AuthenticodeSignature -LiteralPath (Get-BootLoaderPath)
        
        $result.BootloaderUpdated = ($bootManagerSignature).SignerCertificate.IssuerName -match  'Windows UEFI CA 2023'
        
        # If we got this far without an exception, then we can set Error to false.
        $result.Error = $false
        
    } catch {
        Write-Error "An error occurred retrieving Secure Boot certificate change status: $_"
    }
    # Calculate the FlagValue and return the result
    $flagValue = 0
    if ($result.SecureBootEnabled) { $flagValue += 1 }
    if ($result.UEFITrustsNew2023CACertificate) { $flagValue += 2 }
    if ($result.UEFIRevokedOld2011CACertificate) { $flagValue += 4 }
    if ($result.SVNEnabled) { $flagValue += 8 }
    if ($result.BootloaderUpdated) { $flagValue += 16 }
    if ($result.Error) { $flagValue += 128 }
    $result.FlagValue = $flagValue
    
    return $result
}

Get-SecureBootCertificateChangeStatus

# Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment. THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that. You agree: (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ fees, that arise or result from the use or distribution of the Sample Code