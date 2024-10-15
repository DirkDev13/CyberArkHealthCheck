<####################################################################################################################
Function Name: Test-RequiredModule
Description: Checks if a Required Module is installed based on the Name and the version
###################################################################################################################>
function Test-RequiredModule {
    param(
        [string]$ModuleName,
        [string]$DesiredVersion
    )

    # Check if the module is installed
    $installedModule = Get-Module -Name $ModuleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

    if ($installedModule) {
        $installedVersion = $installedModule.Version.ToString()

        if ($installedVersion -eq $DesiredVersion) {
            return $true
        } else {
            return $false
        }
    } else {
        return $false
    }
}
<####################################################################################################################
Function Name: Confirm-poShPACLI
Description: Confirm if the desired version of psPAS is installed
###################################################################################################################>
function Confirm-poShPACLI {
    Write-Host "Checking poShPACLI module" -ForegroundColor Green 
    $ModuleName = "poShPACLI"
    $DesiredVersion = "2.1.27"
    $psPASCheck = Test-RequiredModule -ModuleName $ModuleName -DesiredVersion $DesiredVersion
    if ($psPASCheck){
        Write-Host "The module $ModuleName is installed with the correct version." -ForegroundColor Green
    }else{
        Write-Host "The module $ModuleName is not installed or the version is incorrect, Installing it now" -ForegroundColor Green
         # Try to install the module
        try {
            Write-Host "Installing $ModuleName version $DesiredVersion..."
            Install-Module -Name $ModuleName -RequiredVersion $DesiredVersion -Force -Scope CurrentUser
            Write-Host "$ModuleName version $DesiredVersion has been installed successfully." -ForegroundColor Green
        } catch {
            Write-Host "Couldn't install $ModuleName from Repo, installing it manually..." -ForegroundColor DarkYellow
            Copy-Item -Path "..\Prerequisites\PoShPACLI" -Destination "C:\Program Files\WindowsPowerShell\Modules\PoShPACLI" -Recurse -Force
        }
    }
    pause
}
<####################################################################################################################
Function Name: Read-Config
Description: Reads the contents from the config.xml file
###################################################################################################################>
function Read-Config {
    param (
        [string]$configFilePath
    )
    # Check if the config file exists
    if (-not (Test-Path $configFilePath)) {
        Write-Host "Config file not found."
        return $null
    }
    # Load the XML file
    [xml]$configXml = Get-Content -Path $configFilePath
    # Extract values from the XML
    $Vault = $configXml.Configuration.VAULT
    # Return the extracted values as a hashtable
    return @{
        VAULT = $Vault
    }
}
<####################################################################################################################
Function Name: New-CredFile
Description: Creates a cred file called User.xml
###################################################################################################################>
function New-CredFile {
    param (
        [string]$ExportFilePath
    )

    # Prompt the user for credentials
    $credential = Get-Credential -Message "Enter your credentials"

    # Export the credentials to the specified XML file
    $credential | Export-Clixml -Path "$($ExportFilePath)\User.xml"
}

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
Function Name: Set-PACLI
Description: Set the PACLI configuration for the executable to be used
###################################################################################################################>
function Set-PACLI{
    $PACLIPath = (Resolve-Path  "..\Prerequisites\PACLI-Rls-v14.2\Pacli.exe").Path 
    Write-Host "Setting the PACLI path to: $($PACLIPath)" -ForegroundColor Green
    try{
        Set-PVConfiguration -ClientPath $PACLIPath
        Write-Host "Path Set Successfully" -ForegroundColor Green
    }catch{
        Write-Host "Error Couldn't set PACLI Executable path, set it manually" -ForegroundColor Red
    }
    $Vault = Read-Host "Specify the Active Vault IP"
    $configXml = @"
    <Configuration>
        <VAULT>$Vault</VAULT>
    </Configuration>
"@
    $configXml | Out-File -FilePath "..\Config\Config.xml" -Encoding utf8
    Write-Host "Configuration File 'Config.xml' has been created successfully" -ForegroundColor Green
    pause
}
<####################################################################################################################
Function Name: Check-HCAccount
Description: Check that there is an existing HCAccount for this Server 
###################################################################################################################>
function Check-HCAccount{
    $config = Read-Config -configFilePath ..\Config\Config.xml
    $Hostname = $env:computername
    $SessionID =  Get-Random -Minimum 100 -Maximum 999
    $pscredential = Read-CredFile -CFPath ..\Config\User.xml
    $Safe = "CA-HealthCheck"
    $Check = $false
    Write-Host "Checking if Health-Check Account exists for $($Hostname)..." -ForegroundColor Green
    try{
        Start-PVPacli -sessionID $SessionID
        New-PVVaultDefinition -vault "VAULT" -address $config.VAULT
        Connect-PVVault -user $pscredential.UserName -password $pscredential.Password

        Open-PVSafe -safe $Safe | Out-Null
        $Files = Find-PVFile -safe $Safe -folder Root
        foreach ($File in $Files){
            $Address = Get-PVFileCategory -safe $Safe -folder Root -file $File.Filename -category Address
            if($Address.CategoryValue -eq $Hostname){
                $Check = $true
            }
        }
        Disconnect-PVVault

        if($Check -eq $true){
            Write-Host "Health Check Account for $($Hostname) exists in Vault" -ForegroundColor Green
        } else {
            Write-Host "Health Check Account for $($Hostname) does not exists in Vault, run the Setup-HCReport.ps1 script to create account or create manually." -ForegroundColor Red
        } 
    }catch{
        Write-Host "Error couldn't check the HC user, do the check manually" -ForegroundColor Red
    }
    pause
}

<####################################################################################################################
Function Name: Set-ScheduledTask
Description: Sets up the Scheduled Task to run the Health Checks once a day
###################################################################################################################>
function Set-ScheduledTask {
    $taskName = "Vault-HealthCheck"

    $xmlFilePath = (Resolve-Path  "..\Prerequisites\Vault-HealthCheck.xml").Path
    $xmlData = [xml](Get-Content -Path "$($xmlFilePath)")

    # Update the Start date of the task
    $currentDate = Get-Date
    $nextDay = $currentDate.AddDays(1).Date.AddHours(5)
    $TargetDate = $nextDay.ToString("yyyy-MM-ddTHH:mm:ss")
    $xmlData.Task.Triggers.CalendarTrigger.InnerText = $TargetDate


    #update the author of the task
    $loggedOnUser = (Get-WmiObject -Class Win32_ComputerSystem).UserName
    $user = New-Object System.Security.Principal.NTAccount($loggedOnUser)
    $sid = $user.Translate([System.Security.Principal.SecurityIdentifier]).Value
    $xmlData.Task.Principals.Principal.UserId = $sid

    #validate the powershell location
    if(Test-Path -Path $($xmlData.Task.Actions.Exec.Command)){
        Write-Host "Powershell path is valid" -ForegroundColor Green
    }else{
        Write-Host "Invalid Powershell Path, update manually and register task" -ForegroundColor Red
        pause
        return
    }

    #Validate Arguments of task
    $arguments = $xmlData.Task.Actions.Exec.Arguments
    $regex = '-File\s+"([^"]+)"'
    $match = [regex]::Match($arguments, $regex)
    if ($match.Success) {
        # Extract the file path
        $filePath = $match.Groups[1].Value

        # Validate if the file exists
        if (Test-Path $filePath) {
            Write-Host "The file path to Vault-HealtCheck.ps1 is valid" -ForegroundColor Green
        } else {
            Write-Host "The file path to Vault-HealtCheck.ps1 is invalid, update manually and register task" -ForegroundColor Red
            pause
            return
        }
    } else {
        Write-Host "No valid file path found in the arguments.manually register task" -ForegroundColor Red
        pause
        return
    }
    
    #Validate Working Directory of task
    if(Test-Path -Path $($xmlData.Task.Actions.Exec.WorkingDirectory)){
        Write-Host "Working Directory path is valid" -ForegroundColor Green
    }else{
        Write-Host "Invalid Working Directory , update manually and register task" -ForegroundColor Red
        pause
        return
    }

    $Cred = Get-Credential -Message "User Linked to Scheduled Task"

    # Use the Register-ScheduledTask cmdlet to import the task
    try{
        Register-ScheduledTask -TaskName $taskName -Xml (Get-Content -Path $xmlFilePath -Raw) -User $Cred.UserName -Password $Cred.GetNetworkCredential().Password | Out-Null
        Write-Host "Scheduled Task has been created successfully" -ForegroundColor Green
    }catch{
        Write-Host "Error Could not create scheduled task, create it manually" -ForegroundColor Red
    }
     
    pause
}
<####################################################################################################################
Function Name: Read-MainMenu
Description: Menu function for the setup of the VaultCheck Prerequisites
###################################################################################################################>
function Read-MainMenu {
    do {
        clear
        Write-Host "`n####################################################################################" -ForegroundColor Yellow
        Write-Host "Main Menu" -ForegroundColor Yellow
        Write-Host "####################################################################################`n" -ForegroundColor Yellow
        Write-Host "1. Check the required modules" -ForegroundColor Yellow
        Write-Host "2. Setup Credential File" -ForegroundColor Yellow
        Write-Host "3. Setup PACLI" -ForegroundColor Yellow
        Write-Host "4. Validate HealthCheck Account for Server" -ForegroundColor Yellow
        Write-Host "5. Setup Scheduled Task" -ForegroundColor Yellow
        Write-Host "6. Perform All Steps" -ForegroundColor Yellow
        Write-Host "0. Exit" -ForegroundColor Yellow
        $choice = Read-Host "Select an option"
        switch ($choice) {
            "1" {Confirm-poShPACLI}
            "2" {New-CredFile -ExportFilePath ..\Config}
            "3" {Set-PACLI}
            "4" {Check-HCAccount}
            "5" {Set-ScheduledTask}
            "6" {
                Confirm-poShPACLI
                Confirm-psPAS
                New-CredFile -ExportFilePath ..\Config
                Set-PACLI
                Check-HCAccount
                Set-ScheduledTask                
            }
            "0" {}
            default { Write-Host "Invalid selection, please try again."-ForegroundColor Red }
        }
    } until ($choice -eq "0")
}