##############################################################################
# Move-SystemPartition.ps1
# Elizabeth Greene <elizabeth.a.greene@gmail.com> Copyright (C) 2025
# Use this script at your own risk, no warranty is provided or implied
# This script moves the system partition to the end of the disk
# IFF there is unallocated space at the end of the disk
# This allows resizing the primary disk partition
##############################################################################

# Logging config
$script:LogFile = "C:\Windows\Temp\Move-SystemPartition.log"
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


#If the script is not run as an administrator, abort.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log -Level ERROR  "This script must be run as an administrator. Exiting..."
    exit 1
}

#Find the current boot partition
#This partition contains e.g. c:\windows
$bootpartition = get-partition -driveletter c

$diskNumber = $bootpartition.DiskNumber

# If the boot disk is not a GPT disk, exit
$disk = get-disk -Number $diskNumber
if ($disk.PartitionStyle -ne "GPT") {
    Write-Log -Level ERROR  "Disk 0 is not a GPT disk. Exiting..."
    exit 1
}

# Get the current Partitions on this disk
$partitions = Get-Partition -disknumber $diskNumber

# find the system partition
$systemPartition = $partitions | Where-Object Type -eq 'System'

# If there is more than one system partition, abort
if ($systemPartition.Count -gt 1) {
    Write-Log -Level ERROR  "There is more than one system partition. Exiting..."
    exit 1
}

# Is the system partition after the boot partition?
if ($systemPartition.Offset -lt ($bootPartition.Offset)) {
    Write-Log -Level INFO "The system partition is not after the boot (c:\) partition. No action required. Exiting..."
    exit
}


$unallocatedSpace = $disk.size - $disk.AllocatedSize

# Is there at least 100MB of free space at the end of the disk?
if ($unallocatedSpace -ge 101MB) {
    Write-Log -Level INFO "There is enough unallocated space at the end of the disk."
}
else {
    Write-Log -Level ERROR "There is not enough unallocated space at the end of the disk. Exiting..."
    exit 1
}

# Abort if there are 4 partitions
# Only 4 primary partitions are allowed
if ($partitions.Count -ge 4) {
    Write-Log -Level ERROR "There are 4 or more partitions. Exiting..."
    exit 1
}

# Abort if the S or T drive are currently in use.
if (Get-PSDrive S -ErrorAction SilentlyContinue) {
    Write-Log -Level ERROR "The S Drive is currently in use. Aborting."
    exit 1
}
if (Get-PSDrive T -ErrorAction SilentlyContinue) {
    Write-Log -Level ERROR "The T Drive is currently in use. Aborting."
    exit 1
}


# Move the system partition to the end of the disk
# Assign a drive letter S: to the current system partition
Write-Log -Level INFO "Mapping S Drive."
try {
    $systemPartition | Set-Partition -NewDriveLetter S
} catch {
    Write-Log -Level ERROR "Failed to map S Drive. Exiting..."
    exit 1
}

# Create a new system partition offset from the end of the disk by -100MB
# First, calculate the starting offset.
$endOffset = $disk.Size - 101MB

# Next, create the new partition as type system and assign it the drive letter T:
#$newSystemPartition = New-Partition -DiskNumber 0 -size 100mb -GptType "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}"
Write-Log -Level INFO "Creating new system partition"
try {
    $newSystemPartition = New-Partition -DiskNumber 0 -OffSet $endOffset -UseMaximumSize -GptType "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}"
} catch {
    Write-Log -Level ERROR "Failed to create new system partition. Exiting..."
    exit 1
}

# Format the new system partition
try {
    $newSystemPartition | Format-Volume -FileSystem FAT32 -NewFileSystemLabel "SYSTEM" -Confirm:$false
} catch {
    Write-Log -Level ERROR "Failed to format new system partition. Exiting..."
    exit 1
}

# Assign the drive letter T: to the new system partition
try {
    $newSystemPartition | Set-Partition -NewDriveLetter "T"
} catch {
    Write-Log -Level ERROR "Failed to assign drive letter T: to the new system partition. Exiting..."
    exit 1
}

# Verify the new partition and, if this fails, abort
if (-not (get-partition -DriveLetter t)) {
    Write-Log -Level ERROR "Failed to Create/Format/Mount the new system partition. Exiting..."
    exit 1
}

# Use BCDboot to copy the boot files to the new partition
& bcdboot.exe C:\Windows /s T: /f UEFI

# If this failed, abort. 
if ($LASTEXITCODE -ne 0) {
    Write-Log -Level ERROR "Failed BCDboot copying boot files to the new system partition. Exiting..."
    exit 1  
}

# Copy the contents of the S drive to the T drive (This should not be required; bcdboot should handle it)
Copy-Item -Path S:\* -Destination T:\ -Recurse -Force -ErrorAction SilentlyContinue >> $LogFile

# Now we have to set the boot configuration database to point to the new drive.
#This will work, but requires us to keep the T: drive letter.
& bcdedit /set "{bootmgr}" device partition=T: >> $LogFile

# We can make this cleaner though, using the new drive's UEFI device name. We call a helper function for this.

$drives = get-DriveDeviceNames
foreach ($drive in $drives) {
    if ($drive.DriveLetter -eq "T:") {
        $DevicePath = $drive.DevicePath

        Write-Log -Level INFO "Updating BCD with $DevicePath"

        #Change the BCD to the new path
        & bcdedit /set "{bootmgr}" device partition=$DevicePath >> $LogFile

        # and make this change on the T drive BCD as well.
        & bcdedit /store t:\boot\BCD /set "{bootmgr}" device partition=$DevicePath >> $LogFile

        # If that succeeded, we can remove the T drive's letter.
        if ($LASTEXITCODE -eq 0) {
            Get-Partition -driveletter T | Remove-PartitionAccessPath -AccessPath "T:\"
        }
    }
}

# Removing the old system partition
# Ideally, we'd remove the partition here, but that isn't allowed until after we reboot.
# To overcome this, create an onreboot scheduled task to remove it with diskpart.

# First, create the commands that diskpart will run.
$partitionNumber = $systemPartition.PartitionNumber

@"
select disk $diskNumber
select partition $partitionNumber
delete partition override
"@  | Out-File -FilePath "c:\windows\temp\DiskPartRemoveSystemPartition.txt" -Encoding ascii

# Next, we create the script that will run those commands AND remove the scheduled task.
@"
Echo Scheduled Task to remove old system partition initiated >> $LogFile
Date /T >> $LogFile
Time /T >> $LogFile
diskpart.exe /s c:\windows\temp\DiskPartRemoveSystemPartition.txt >> $LogFile
schtasks.exe /delete /tn "RemoveOldSystemPartition" /f >> $LogFile
"@ | Out-File -FilePath "c:\windows\temp\RemoveOldSystemPartitionTask.bat" -Encoding ascii 

Write-Log -Level INFO "Creating Scheduled Task to remove old system partition"
# and finally create the scheduled task to run the script above
$action = New-ScheduledTaskAction -Execute "c:\windows\temp\RemoveOldSystemPartitionTask.bat"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "RemoveOldSystemPartition" -Description "Removes the old system partition after reboot" -Force  >> $LogFile
