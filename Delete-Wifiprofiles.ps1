# Delete-Wifiprofiles.ps1
# Elizabeth.a.greene@gmail.com
# MIT License
# This script deletes all WiFi profiles except for the specified SSID.
# It demonstrates how to use Windows Runtime APIs in PowerShell to manage
# WiFi profiles on Windows 10/11 instead of using netsh commands.
# Why? Because netsh does not properly handle SSIDs with unicode characters.
# Many bothans died to bring you this information.

# Define the target SSID
$targetSSID = "CompanyWiFi"

# Log file for debugging
$logPath = "C:\ProgramData\Scripts\Logs\WiFiDeleter.log"

$logDir = Split-Path -Path $logPath -Parent
# Create the log directory if it doesn't exist
if (-not (Test-Path -Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

function Write-Log {
    param ([string]$Message)
    
    # Get the directory path from the log file path
        
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logPath -Append -Encoding UTF8
}

# Ideally you'd want to import the Windows Runtime namespace here like this.
# Add-Type -AssemblyName Windows.Networking.Connectivity
# But this doesn't work to import WinRT assemblies in PowerShell 5.1, so we do this instead.

$wifiProfiles = [Windows.Networking.Connectivity.NetworkInformation,Windows.Web,ContentType=WindowsRuntime]::GetConnectionProfiles() | where-object { ($_.IsWlanConnectionProfile)}

# Iterate through the profiles
foreach ($wifiProfile in $wifiProfiles) {
    Write-Log "Found SSID: $($wifiProfile.ProfileName)"
    if (-not $wifiProfile.CanDelete) {
        Write-Log "Profile is not deletable."
        Continue
    }

    if ($wifiProfile.ProfileName -like $targetSSID) {
        Write-Log "Keeping target profile." 
        Continue
    }

    Write-Log "Attempting to remove profile."
    # Ideally you'd want to await the async call here and get the results for success/failure, but PowerShell doesn't support that.
    # So we just call the async method and ignore the result.
    $wifiProfile.TryDeleteAsync() | out-null
    # Pause for 500 milliseconds
    Start-Sleep -Milliseconds 500

    # Significant attempts were made to properly handle the async call and resulted in failure.
    # Hours Wasted here: 4
    # $result = magicalAwaitFunctionForWinRtInPowerShellThatDoesntExist($wifiProfile.TryDeleteAsync())
    # if ($result.Status -eq "Completed" -and $result.GetResults()) {
    #     Write-Log "Profile removed successfully."
    # } else {
    #     Write-Log "Failed to remove profile."
    # }
}