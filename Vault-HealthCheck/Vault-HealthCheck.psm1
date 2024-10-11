<####################################################################################################################
Function Name: Read-CredFile
Description: Reads the contents of the User.xml file
###################################################################################################################>
function Read-CredFile {
    param (
        [string]$CFPath
    )
    # Check if the config file exists
    if (Test-Path $CFPath) {
        $credential = Import-Clixml -Path $CFPath
        $username = $credential.UserName
        $password = $credential.GetNetworkCredential().Password
        $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        $psCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $securePassword

        return $psCredential
    } else {
        Write-Host "Config file not found."
        return $null
    }
}

<####################################################################################################################
Function Name: Get-SystemInfo
Description: Gets Hostname, IP, Server Uptime, CPU, Memory and Disk Capacity
###################################################################################################################>
function Get-SystemInfo {
    # 1. Getting Hostname
    $Hostname = $env:computerName

    # 2. Getting IP Address
    $IPAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -ne "Loopback Pseudo-Interface 1" }).IPAddress -join ", "

    # 3. OS Version
    $osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption

    # 4. Getting Server Uptime
    $lastBootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $uptime = New-TimeSpan -Start $lastBootTime
    $formattedUptime = [string]::Format("{0}d {1}h {2}m", $uptime.Days, $uptime.Hours, $uptime.Minutes)

    # 5. CPU
    $cpuInfo = Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum
    $totalCPU = $cpuInfo.Sum

    # 6. Memory
    $totalMemory = [math]::round((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)

    # 7. Disk(s) Capacity
    $diskInfo = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 -and $_.Size -gt 0 } | Select-Object DeviceID, @{Name="TotalSpaceGB";Expression={[math]::round($_.Size / 1GB, 2)}}, @{Name="FreeSpaceGB";Expression={[math]::round($_.FreeSpace / 1GB, 2)}}

    # Creating output Array
    $SystemInfo = @()
    $SystemInfo += [PSCustomObject]@{
        'ServerName'   = $Hostname
        'IPAddress'    = $IPAddress
        'OSVersion'    = $osVersion
        'ServerUpTime' = $formattedUptime
        'CPU'          = $totalCPU
        'RAM'          = $totalMemory
        'Disk'         = $diskInfo
    }
    Return $SystemInfo
}

<####################################################################################################################
Function Name: Get-CyberArkInstalledApps
Description: Gets all the CyberArk installed Applications, the version and the install date
###################################################################################################################>
function Get-CyberArkInstalledApps {
    <# SYNOPSIS:
        Get all the CyberArk or Privilege Cloud installed Applications on the Server
    #>

    # Get CyberArk and PrivilegeCloud applications from both 64-bit and 32-bit registry
    $installedApplications64 = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |
        Where-Object { $_.DisplayName -like "*CyberArk*" -or $_.DisplayName -like "*PrivilegeCloud*" } |
        Select-Object DisplayName, DisplayVersion, @{Name="InstallDate";Expression={if ($_.PSObject.Properties['InstallDate']) {([datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null)).ToString('yyyy-MM-dd')} else {"N/A"}}}

    $installedApplications32 = Get-ItemProperty "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
        Where-Object { $_.DisplayName -like "*CyberArk*" -or $_.DisplayName -like "*PrivilegeCloud*" } |
        Select-Object DisplayName, DisplayVersion, @{Name="InstallDate";Expression={if ($_.PSObject.Properties['InstallDate']) {([datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null)).ToString('yyyy-MM-dd')} else {"N/A"}}}

    $installedApplications = $installedApplications64 + $installedApplications32

    # Replace DisplayName with shorter names
    $installedApplications = $installedApplications | ForEach-Object {
        $_.DisplayName = switch -Wildcard ($_.DisplayName) {
            "*CyberArk Central Policy Manager*" { "CPM" }
            "*CyberArk Identity Connector*" { "IC" }
            "*CyberArk Privileged Session Manager*" { "PSM" }
            "*PrivilegeCloudSecureTunnel*" { "PCST" }
            "*CyberArk Digital Vault*" { "Vault" }
            "*CyberArk Vault Disaster Recovery*" { "DR" }
            
        }
        $_
    }

    # Remove duplicate entries based on DisplayName and DisplayVersion
    $installedApplications = $installedApplications | Sort-Object DisplayName, DisplayVersion -Unique
    Return $installedApplications
}

###########################################################################################################################################
# Function Name: Get-CyberArkServiceStatus
# Reads the status of all CyberArk services and how long they've been running
###########################################################################################################################################
function Get-CyberArkServices {
    # Get CyberArk services information and calculate running duration
    $cyberArkServices = Get-Service | Where-Object { 
        ### Vaults ###
        $_.DisplayName -eq "Cyber-Ark Event Notification Engine" -or  
        $_.DisplayName -eq "Cyber-Ark Hardened Windows Firewall" -or  
        $_.DisplayName -eq "CyberArk Logic Container" -or  
        $_.DisplayName -eq "CyberArk Vault Disaster Recovery" -or
        $_.DisplayName -eq "PrivateArk Database" -or
        $_.DisplayName -eq "PrivateArk Remote Control Agent" -or
        $_.DisplayName -eq "PrivateArk Server"

    } | Select-Object Name, Status, DisplayName



    $serviceDurations = @()
    foreach ($service in $cyberArkServices) {
        if ($service.Status -eq 'Running') {
            $runningServicesCount++
            $serviceInfo = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($service.Name)'"
            if ($serviceInfo.ProcessId) {
                $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$($serviceInfo.ProcessId)"
                if ($process) {
                    $startTime = $process.CreationDate
                    $runningDuration = New-TimeSpan -Start $startTime
                    $serviceDurations += [PSCustomObject]@{
                        DisplayName     = $service.DisplayName
                        Status          = $service.Status
                        RunningDuration = [string]::Format("{0}d {1}h {2}m {3}s", $runningDuration.Days, $runningDuration.Hours, $runningDuration.Minutes, $runningDuration.Seconds)
                    }
                } else {
                    $serviceDurations += [PSCustomObject]@{
                        DisplayName     = $service.DisplayName
                        Status          = $service.Status
                        RunningDuration = "N/A"
                    }
                }
            }
        } else {
            $serviceDurations += [PSCustomObject]@{
                DisplayName     = $service.DisplayName
                Status          = $service.Status
                RunningDuration = "N/A"
            }
        }
    }
    Return $serviceDurations
}
###########################################################################################################################################
# Function Name: Foromat-HCData
# Description: This Function will encode and compress the HealthCheck Data 
###########################################################################################################################################
function Format-HCData {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Data
    )

    # Convert the JSON string to bytes
    $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($Data)

    # Compress the JSON bytes
    $compressedStream = New-Object System.IO.MemoryStream
    $gzipStream = New-Object System.IO.Compression.GZipStream($compressedStream, [System.IO.Compression.CompressionLevel]::Optimal)
    $gzipStream.Write($jsonBytes, 0, $jsonBytes.Length)
    $gzipStream.Close()
    $compressedBytes = $compressedStream.ToArray()

    # Encode the compressed bytes to base64
    $encodedContent = [System.Convert]::ToBase64String($compressedBytes)

    return $encodedContent
}
<####################################################################################################################
Function Name: Get-RecordingsSafes
Description: Sets the Accounts Password as the Encoded HCData using PoShPACLI
###################################################################################################################>
Function Get-RecordingsSafes {

    $Hostname = $env:computername
    $SessionID =  Get-Random -Minimum 100 -Maximum 999
    $pscredential = Read-CredFile -CFPath .\Config\User.xml
    $RecordingSafes = @()

    Start-PVPacli -sessionID $SessionID
    New-PVVaultDefinition -vault "VAULT" -address $Hostname
    Connect-PVVault -user $pscredential.UserName -password $pscredential.Password
    $Safes = Get-PVSafeList | Where-Object {$_.Safename -like "PSMRecordings*"}
    foreach($Safe in $Safes){
        $Details = Get-PVSafe -safe $Safe.Safename 

        $RecordingSafes += [PSCustomObject]@{
            'SafeName' = $Safe.Safename
            'MaxSize' = [math]::Round($Details.MaxSize / 1024,2)
            'Used' = [math]::Round($Details.CurrSize / 1048576,2)
            'Free' = [math]::Round((($Details.MaxSize - ($Details.CurrSize/1024)) / ($Details.MaxSize))*100,2)
        }
    }
    Stop-PVPacli
    Return $RecordingSafes
}

<####################################################################################################################
Function Name: Set-HCPasswordPACLI
Description: Sets the Accounts Password as the Encoded HCData using PoShPACLI
###################################################################################################################>
function Set-HCPasswordPACLI {
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$SecureString
    )
    $Hostname = $env:computername
    $SessionID =  Get-Random -Minimum 100 -Maximum 999
    $pscredential = Read-CredFile -CFPath .\Config\User.xml
    $Safe = "CA-HealthCheck"
    
    Start-PVPacli -sessionID $SessionID
    New-PVVaultDefinition -vault "VAULT" -address $Hostname
    Connect-PVVault -user $pscredential.UserName -password $pscredential.Password
    Open-PVSafe -safe $Safe | Out-Null
    $Files = Find-PVFile -safe $Safe -folder Root
    foreach ($File in $Files){
        $Address = Get-PVFileCategory -safe $Safe -folder Root -file $File.Filename -category Address
        if($Address.CategoryValue -eq $Hostname){
            Add-PVPasswordObject -safe $Safe -folder Root -file $File.Filename -password $SecureString  
        }
    }
   Stop-PVPacli
}



