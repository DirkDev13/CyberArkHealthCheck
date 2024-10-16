
Import-Module .\Component-HealthCheck.psm1
$Logfile = ".\Logs\Component-HeathCheck.log"
$DiskSpace = 15


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

#Checking if Backup is installed and if it is, it will go and read the log file
$HasBackup = $InstalledApps | Where-Object { $_.DisplayName -like '*Backup*' }

if($HasBackup){
    $registryPath = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $InstallLocation = (Get-ItemProperty $registryPath | Where-Object { $_.DisplayName -like "*Replicator*" }).InstallLocation

    $BackupInfo = Read-Backuplog -logFilePath "$($InstallLocation)\Replicate\pareplicate.log"

    # Combine into one variable
    $RawHCData = [PSCustomObject]@{
        SystemInfo    = $SystemInfo
        InstalledApps = $InstalledApps
        Services = $Services
        BackupInfo = $BackupInfo
    }

}else{
    # Combine into one variable
    $RawHCData = [PSCustomObject]@{
        SystemInfo    = $SystemInfo
        InstalledApps = $InstalledApps
        Services = $Services
    }
}

#endregion

#region Build HCData View

#Check Total Running Services
$totalServices = $RawHCData.Services.Count
$runningServices = ($RawHCData.Services | Where-Object { $_.Status -eq 'Running' }).Count

#Disk Check
$TotalDisks = ($RawHCData.SystemInfo.Disk| Measure-Object).Count
$DisksWithEnoughSpace = ($RawHCData.SystemInfo.Disk | Where-Object {$_.FreeSpaceGB -gt $DiskSpace} | Measure-Object).Count

#Compiling Summary data
$HCSummary = @()
$HCSummary += [PSCustomObject]@{
    'Components' = $RawHCData.InstalledApps.DisplayName -join ','
    'RunningServices' = "$runningServices/$totalServices"
    'DiskCheck(+15GB)' = "$TotalDisks/$DisksWithEnoughSpace"
}
$HCData = @()
$HCData += [PSCustomObject]@{
    'Summary' = $HCSummary
    'RawData' = $RawHCData
}
$HCData = $HCData | ConvertTo-Json -Depth 4
#endregion

#region Endcode the Data
$EncodedData = Format-HCData -Data $HCData
$SecureString = ConvertTo-SecureString -String $EncodedData -AsPlainText -Force
#endregion

#region Send Data to HC Account
Set-HCPassword -SecureString $SecureString
#endregion



