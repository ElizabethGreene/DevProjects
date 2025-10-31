##############################################################################
# Fix-SystemPartition.ps1
# Elizabeth Greene <elizabeth.a.greene@gmail.com> Copyright (C) 2025
# Use this script at your own risk, no warranty is provided or implied
# This script looks for weird system partition placements on GPT disks
# and tries to fix them
##############################################################################

# In this context, weird system partitions are defined as:
# 1) System partition is immeditately after the boot partition (c:\) on GPT disks preventing c from being enlarged.
# 2) If there is a partition that looks like a system partition but is not marked as such at the beginning of the disk.
# 
# Ideally we put the system partition at the beginning of the disk, but if that's not possible, we put it at the end.

# Logging config
$script:LogFile = "C:\Windows\Temp\Fix-SystemPartition.log"
$script:LogToConsole = $true    # set $false to only write to file
$LogFile = $script:LogFile

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR","DEBUG")][string]$Level = "INFO"
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $entry = "$timestamp [$Level] $Message"
    try {
        Add-Content -Path $script:LogFile -Value $entry -ErrorAction Stop
    } catch {
        # If logging to file fails, still write to console
        Write-Host "Failed to write to log file: $($_.Exception.Message)" -ForegroundColor Red
    }
    if ($script:LogToConsole) {
        switch ($Level) {
            "ERROR" { Write-Host $entry -ForegroundColor Red }
            "WARN"  { Write-Host $entry -ForegroundColor Yellow }
            "DEBUG" { Write-Host $entry -ForegroundColor Gray }
            default { Write-Host $entry }
        }
    }
}

function Schedule-OldSystemPartitionRemoval {
    param(
        [Parameter(Mandatory=$true)]$systemPartition,
        [Parameter(Mandatory=$true)]$diskNumber
    )   
{
    

# First, create the commands that diskpart will run.
$partitionNumber = $systemPartition.PartitionNumber

@"
select disk $diskNumber
select partition $partitionNumber
delete partition override
"@  | Out-File -FilePath "c:\windows\temp\DiskPartRemoveSystemPartition$partitionNumber.txt" -Encoding ascii

# Next, we create the script that will run those commands AND remove the scheduled task.
@"
Echo Scheduled Task to remove old system partition initiated >> $LogFile
Date /T >> $LogFile
Time /T >> $LogFile
diskpart.exe /s c:\windows\temp\DiskPartRemoveSystemPartition$partitionNumber.txt >> $LogFile
schtasks.exe /delete /tn "RemoveOldSystemPartition$partitionNumber" /f >> $LogFile
"@ | Out-File -FilePath "c:\windows\temp\RemoveOldSystemPartitionTask$partitionNumber.bat" -Encoding ascii 

Write-Log -Level INFO "Creating Scheduled Task to remove old system partition"
# and finally create the scheduled task to run the script above
$action = New-ScheduledTaskAction -Execute "c:\windows\temp\RemoveOldSystemPartitionTask$partitionNumber.bat"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "RemoveOldSystemPartition$partitionNumber" -Description "Removes the old system partition after reboot" -Force  >> $LogFile
}


function get-DriveDeviceNames {
    # Source Attribution: https://serverfault.com/questions/571354/how-do-i-identify-a-volume-in-wmi-from-a-volume-name-reported-in-the-event-log#:~:text=%23%3E%20%23%20Utilize%20P%2FInvoke%20in%20order%20to%20call,require%20compiling%20C%23%20code.%20%24DynAssembly%20%3D%20New-Object%20System.Reflection.AssemblyName%28%27SysUtils%27%29
    # Build System Assembly in order to call Kernel32:QueryDosDevice. 
    $DynAssembly = New-Object System.Reflection.AssemblyName('SysUtils')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('SysUtils', $False)
 
    # Define [Kernel32]::QueryDosDevice method
    $TypeBuilder = $ModuleBuilder.DefineType('Kernel32', 'Public, Class')
    $PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('QueryDosDevice', 'kernel32.dll', ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static), [Reflection.CallingConventions]::Standard, [UInt32], [Type[]]@([String], [Text.StringBuilder], [UInt32]), [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
    $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, @('kernel32.dll'), [Reflection.FieldInfo[]]@($SetLastError), @($true))
    $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
    $Kernel32 = $TypeBuilder.CreateType()
 
    $Max = 65536
    $StringBuilder = New-Object System.Text.StringBuilder($Max)
 
    $result = @()
    Get-WmiObject Win32_Volume | ? { $_.DriveLetter } | % {
        $ReturnLength = $Kernel32::QueryDosDevice($_.DriveLetter, $StringBuilder, $Max)
 
        if ($ReturnLength) {
            $DriveMapping = @{
                DriveLetter = $_.DriveLetter
                DevicePath  = $StringBuilder.ToString()
            }
 
            $result += New-Object PSObject -Property $DriveMapping
        }
    }
    return $result
}

# Useful constants
$EFI_SYSTEM_PARTITION_GPT_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"

#If the script is not run as an administrator, abort.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log -Level ERROR  "This script must be run as an administrator. Exiting..."
    exit 1
}

#Find the current boot partition
#This partition contains e.g. c:\windows
$bootpartition = get-partition -driveletter c
# TODO: Improve this logic to find the correct partition if this script is run from a WinPE environment
if (-not $bootpartition) {
    Write-Log -Level ERROR  "Could not find the boot partition (c:\). Exiting..."
    exit 1
}

$diskNumber = $bootpartition.DiskNumber

# If the boot disk is not a GPT disk, exit
$disk = get-disk -Number $diskNumber
if ($disk.PartitionStyle -ne "GPT") {
    Write-Log -Level ERROR  "Disk 0 is not a GPT disk. Exiting..."
    exit 1
}

# Get the current Partitions on this disk
$partitions = Get-Partition -disknumber $diskNumber

# Find the system partition(s)
$systemPartition = @()

# That's any partitions marked as System partitions or any FAT32 partitions of size 360MB or less (these are likely mis-marked system partitions)
$partitions | Where-Object { ($_.Size -le 360MB) -or ($_.GptType -eq $EFI_SYSTEM_PARTITION_GPT_TYPE) } | ForEach-Object {
    if ($systemPartition -notcontains $_) {
        $systemPartition += $_
    }
}

# If there is exactly one system partition, and it's at the start of the disk, we don't need to move or create any partitions.
if ($systemPartition.Count -eq 1) {
    if ($systemPartition[0].Offset -le 20MB) {
        # Is the GPT partition ID correct?
        if ($systemPartition[0].GptType -eq $EFI_SYSTEM_PARTITION_GPT_TYPE){ 
            Write-Log -Level INFO "The system partition is at the start of the disk with correct GPT type. No action required. Exiting..."
            exit 0
        }

        # The system partition is in the correct location with the incorrect GPT type. Fix it.
        Write-Log -Level INFO "The system partition is at the start of the disk but has an incorrect GPT type. Fixing..."
        try {
            $systemPartition[0] | Set-Partition -GptType $EFI_SYSTEM_PARTITION_GPT_TYPE
        } catch {
            Write-Log -Level ERROR "Failed to fix GPT type of system partition. Exiting..."
            exit 1
        }
        Write-Log -Level INFO "Successfully fixed GPT type of system partition. Exiting..."
        exit 0
    }
} 

# Now we have to figure out where the system partition should go
$ TargetSystemPartition = $null

# Find the first system partition on the disk.
$FirstPartition = $systemPartition | Sort-Object Offset | Select-Object -First 1

# If it's at the start of the disk, we'll use that one.
if ($FirstPartition.Offset -le 20MB) {
    $TargetSystemPartition = $FirstPartition
}

# Is there space for a new system partition at the start of the disk?
$endOfPreviousPartition = 1048576 # 1MB offset for GPT header and partition table
foreach ($partition in $partitions | Sort-Object Offset) {
    $startofPartition = $partition.Offset
    if ($startofPartition-$endOfPreviousPartition -ge 100MB) {
        # There is enough space for a new system partition before this partition.
        # Create a new system partition at the start of the disk.
            try {
                Write-Log -Level INFO "Creating Target System Partition at end of disk."
                $TargetSystemPartition = New-Partition -DiskNumber $diskNumber -Size 100MB -GptType $EFI_SYSTEM_PARTITION_GPT_TYPE -Offset $endOfPreviousPartition
                # Format the partition
                Write-Log -Level INFO "Formatting Target System Partition." 
                $TargetSystemPartition | Format-Volume -FileSystem FAT32 -NewFileSystemLabel "SYSTEM" -Confirm:$false
            } catch {
                Write-Log -Level ERROR "Failed to create or format Target System Partition. Exiting..."
                exit 1
            }
            
        
        break
    }

    # If we reach the C: partition, stop checking.  We'll need to put the system partition at the end of the disk.
    if ($partition.DriveLetter -eq "C") {
        # Is there space at the end of the disk for a new system partition?
        $lastPartition = $partitions | Sort-Object Offset | Select-Object -Last 1
        if (($disk.Size - ($lastPartition.Offset + $lastPartition.Size)) -ge 100MB) {
            # There is enough space for a new system partition at the end of the disk. Create and format the partition
            try {
                Write-Log -Level INFO "Creating Target System Partition at end of disk."
                $TargetSystemPartition = New-Partition -DiskNumber $diskNumber -Size 100MB -GptType $EFI_SYSTEM_PARTITION_GPT_TYPE -Offset ($lastPartition.Offset + $lastPartition.Size)
                # Format the partition
                Write-Log -Level INFO "Formatting Target System Partition." 
                $TargetSystemPartition | Format-Volume -FileSystem FAT32 -NewFileSystemLabel "SYSTEM" -Confirm:$false
            } catch {
                Write-Log -Level ERROR "Failed to create or format Target System Partition. Exiting..."
                exit 1
            }

            break
        } else {
            Write-Log -Level ERROR "Not enough space at the beginning or end of the disk for a new system partition. Exiting..."
            exit 1
        }
    }
    $endOfPreviousPartition = $partition.Offset + $partition.Size
}

# If we still don't have a target system partition, abort.  This code should be unreachable.
if (-not $TargetSystemPartition) {
    Write-Log -Level ERROR "Could not determine target system partition location. Exiting..."
    exit 1
}

# Now we iterate through all the system-like partitions again and build a list of partitions to remove later.
$PartitionsToRemove = @()

$partitions | Where-Object { ($_.Size -le 360MB) -or ($_.GptType -eq $EFI_SYSTEM_PARTITION_GPT_TYPE) } | ForEach-Object {
    if ($_.Offset -ne $TargetSystemPartition.Offset -and $systemPartition) {
        $PartitionsToRemove += $_
    }
}

# Now we fix the TargetSystemPartition
# Give it a drive letter 
# Is drive T already in use?  If so abort.
if (Get-PSDrive T -ErrorAction SilentlyContinue) {
    Write-Log -Level ERROR "The T Drive is currently in use. Aborting."
    exit 1
}
Write-Log -Level INFO "Mapping T Drive."
try {
    $TargetSystemPartition | Set-Partition -NewDriveLetter T
} catch {
    Write-Log -Level ERROR "Failed to map T Drive. Exiting..."
    exit 1
}

# Use BCDboot to copy the boot files to the target partition
& c:\windows\system32\bcdboot.exe C:\Windows /s T: /f UEFI >> $LogFile
# If this failed, abort.
if ($LASTEXITCODE -ne 0) {
    Write-Log -Level ERROR "Failed BCDboot copying boot files to the target system partition. Exiting..."
    exit 1  
}

# Now we have to set the boot configuration database to point to the new drive.
& c:\windows\system32\bcdedit /set "{bootmgr}" device partition=T: >> $LogFile

# I would like to add logic here to copy any additional files from the old system partition to the new one.  This handles the case
# where there are additional files on the system partition that bcdboot does not copy. e.g. symantec's boot driver
# This is not currently implemented.

# Copy the contents of the S drive to the T drive (This should not be required; bcdboot should handle it)
# Copy-Item -Path S:\* -Destination T:\ -Recurse -Force -ErrorAction SilentlyContinue >> $LogFile

# Removing the old system partition
# Now we loop through all of the partitions we marked for removal and remove them.  We'll create a scheduled task to remove
# any that fail.

$PartitionsToRemove | ForEach-Object {
    Write-Log -Level INFO "Attempting to remove old system partition at offset $($_.Offset)"
    try {
        $_ | Remove-Partition -Confirm:$false -ErrorAction Stop
        Write-Log -Level INFO "Successfully removed old system partition at offset $($_.Offset)"
    } catch {
        Write-Log -Level WARN "Failed to remove old system partition at offset $($_.Offset). Scheduling removal on next reboot."
        Schedule-OldSystemPartitionRemoval -systemPartition $_ -diskNumber
    }
}

