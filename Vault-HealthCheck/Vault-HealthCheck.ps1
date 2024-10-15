
Import-Module .\Vault-HealthCheck.psm1
$Logfile = ".\Logs\Vault-HeathCheck.log"


#region Pulling the System Info, Installed Apps and Services
try{
    $Systeminfo = Get-SystemInfo
}catch{
    "$(Get-Date -f yyyy-MM-dd) $(Get-Date -f hh:mm:ss) Error - Couldn't pull System Info: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
}
try{
    $InstalledApps = Get-CyberArkInstalledApps
}catch{
    "$(Get-Date -f yyyy-MM-dd) $(Get-Date -f hh:mm:ss) Error - Couldn't pull Installed Apps: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
}
try{
    $Services = Get-CyberArkServices
}catch{
    "$(Get-Date -f yyyy-MM-dd) $(Get-Date -f hh:mm:ss) Error - Couldn't pull Services Info: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
}

# Combine into one variable
$RawHCData = [PSCustomObject]@{
    SystemInfo    = $SystemInfo
    InstalledApps = $InstalledApps
    Services = $Services
}
#endregion


#region Build HCData View

#Check Total Running Services

#Disk Check
$TotalDisks = ($RawHCData.SystemInfo.Disk| Measure-Object).Count
$DisksWithEnoughSpace = ($RawHCData.SystemInfo.Disk | Where-Object {$_.FreeSpaceGB -gt $DiskSpace} | Measure-Object).Count

#Compiling Summary data
$HCSummary = @()

#Check if the PrivateArk service is running then we know its a Primary Vault
if(($RawHCData.Services | Where-Object {$_.DisplayName -eq 'PrivateArk Server'}).Status -eq "Running"){
    $Components = "Primary Vault"
    $totalServices = ($RawHCData.Services | Where-Object {$_.DisplayName -ne 'CyberArk Vault Disaster Recovery'}).Count
    $runningServices = ($RawHCData.Services | Where-Object { $_.DisplayName -ne 'CyberArk Vault Disaster Recovery' -and $_.Status -eq 'Running' }).Count
    #Pull the PSMRecording Safes Information
    $RecordingSafes = Get-RecordingsSafes

}elseif(($RawHCData.Services | Where-Object {$_.DisplayName -eq 'CyberArk Vault Disaster Recovery'}).Status -eq "Running"){
    $Components = "DR Vault"
    $totalServices = ($RawHCData.Services | Where-Object {$_.DisplayName -ne 'PrivateArk Server' -and $_.DisplayName -ne 'Cyber-Ark Event Notification Engine'}).Count
    $runningServices = ($RawHCData.Services | Where-Object { $_.DisplayName -ne 'PrivateArk Server' -and $_.DisplayName -ne 'Cyber-Ark Event Notification Engine' -and $_.Status -eq 'Running' }).Count
}

$HCSummary += [PSCustomObject]@{
    'Components' = $Components
    'RunningServices' = "$runningServices/$totalServices"
    'DiskCheck(+15GB)' = "$TotalDisks/$DisksWithEnoughSpace"
}
$HCData = @()
$HCData += [PSCustomObject]@{
    'Summary' = $HCSummary
    'RawData' = $RawHCData
    'PSMRecordingSafes' = $RecordingSafes
}
$HCData = $HCData | ConvertTo-Json -Depth 3
#endregion

#region Endcode the Data
$EncodedData = Format-HCData -Data $HCData
$SecureString = ConvertTo-SecureString -String $EncodedData -AsPlainText -Force
#endregion

#region Send Data to HC Account
Set-HCPasswordPACLI -SecureString $SecureString
#endregion



