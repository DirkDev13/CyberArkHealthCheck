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
Function Name: Check-psPAS
Description: Check if the desired version of psPAS is installed
###################################################################################################################>
function Confirm-psPAS {
    Write-Host "Checking psPAS module" -ForegroundColor Green 
    $ModuleName = "psPAS"
    $DesiredVersion = "6.4.85"
    $psPASCheck = Test-RequiredModule -ModuleName $ModuleName -DesiredVersion $DesiredVersion
    if ($psPASCheck){
        Write-Host "The module $ModuleName is installed with the correct version." -ForegroundColor Green
    }else{
        Read-Host "The module $ModuleName is not installed or the version is incorrect, installing it now"
         # Try to install the module
        try {
            Write-Host "Installing $ModuleName version $DesiredVersion..."
            Install-Module -Name $ModuleName -RequiredVersion $DesiredVersion -Force -Scope CurrentUser
            Write-Host "$ModuleName version $DesiredVersion has been installed successfully." -ForegroundColor Green
        } catch {
            Write-Host "Couldn't install $ModuleName from Repo, installing it manually..." -ForegroundColor DarkYellow
            Copy-Item -Path "..\prerequisites\psPAS" -Destination "C:\Program Files\WindowsPowerShell\Modules\psPAS" -Recurse -Force
            Copy-Item -Path "..\Prerequisites\IdentityCommand" -Destination "C:\Program Files\WindowsPowerShell\Modules\IdentityCommand" -Recurse -Force
        }
    }
    pause
}
<####################################################################################################################
Function Name: Create-ConfigFile
Description: Creates the config file that will be used 
###################################################################################################################>
# Prompt for user inputs
function New-ConfigFile{
    $CustomerName = Read-Host "Specify the Customer Name"
    $PVWAURL = Read-Host "Specify the PVWAURL"
    $AuthenticationType = Read-Host "Specify the Authentication Method (Case-sensitive; e.g., CyberArk, LDAP, RADIUS, Windows, PKI, PKIPN)"
    $CPMUser = Read-Host "Specify the Name of the CPMUser (PasswordManager)"
    $Servers = Read-Host "List the servers (separate each server with a comma, e.g., server1,server2,server3)"
    $Servers = $Servers -split ","

    # Validate the Authentication Method
    $validAuthMethods = @("CyberArk", "LDAP", "RADIUS", "Windows", "PKI", "PKIPN")
    if ($validAuthMethods -notcontains $AuthenticationType) {
        Write-Host "Invalid Authentication Method. Please specify one of the following: CyberArk, LDAP, RADIUS, Windows, PKI, PKIPN" -ForegroundColor Red
        exit
    }
    # Convert servers to XML format
    $serversXml = ""
    foreach ($server in $Servers) {
        $serversXml += "    <Server>$server</Server>`n"
    }
    # Create the Config.xml file
    $configXml = @"
    <Configuration>
        <CustomerName>$CustomerName</CustomerName>
        <PVWAURL>$PVWAURL</PVWAURL>
        <AuthenticationType>$AuthenticationType</AuthenticationType>
        <CPMUser>$CPMUser</CPMUser>
        <Servers>
    $serversXml    </Servers>
    </Configuration>
"@
    $configXml | Out-File -FilePath "..\Config\Config.xml" -Encoding UTF8
    Write-Host "Configuration file 'Config.xml' has been created successfully." -ForegroundColor Green
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
    $CustomerName = $configXml.Configuration.CustomerName
    $PVWAURL = $configXml.Configuration.PVWAURL
    $AuthenticationType = $configXml.Configuration.AuthenticationType
    $CPMUser = $configXml.Configuration.CPMUser
    $Servers = $configXml.Configuration.Servers.Server
    # Return the extracted values as a hashtable
    return @{
        CustomerName = $CustomerName
        PVWAURL = $PVWAURL
        AuthenticationType = $AuthenticationType
        CPMUser = $CPMUser
        Servers = $Servers
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
        Write-Host "Credential file 'User.xml' has been created successfully." -ForegroundColor Green
    pause

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
Function Name: Import-HCPlatform
Description: Import the HC Platform to CyberArk
###################################################################################################################>
function Import-HCPlatform {
    $config = Read-Config -configFilePath ..\Config\Config.xml
    if ($null -eq $config) {
        Write-Host "Exiting due to missing config file."
        return
    }
    $psCredential = Read-CredFile -CFPath ..\Config\User.xml
    try{
        Write-Host "Logging onto $($config.PVWAURL)/PasswordVault as $($psCredential.UserName)" -ForegroundColor Green
        New-PASSession -Credential $psCredential -type $config.AuthenticationType -BaseURI $config.PVWAURL -concurrentSession $true -SkipCertificateCheck -SkipVersionCheck
        Write-Host "Importing Health Check Platform" -ForegroundColor Green
        Import-PASPlatform -ImportFile "..\Prerequisites\CyberArk-HealthCheck.zip" | Out-Null
        Close-PASSession
        Write-Host "The Health Check Platform was imported Successfully"
    }catch{
        Write-Host "Error Importing Platform, Import Manually" -ForegroundColor Red
    }
    pause 
}
<####################################################################################################################
Function Name: Add-HCSafe
Description: Add the Health Check Safe and Safe Members
###################################################################################################################>
Function Add-HCSafe {
    $config = Read-Config -configFilePath ..\Config\Config.xml
    if ($null -eq $config) {
        Write-Host "Exiting due to missing config file."
        return
    }
    $psCredential = Read-CredFile -CFPath ..\Config\User.xml
    #Defining the Safe Role
    $AdminRole = [PSCustomObject]@{
      UseAccounts                               = $true
      ListAccounts                              = $true
      RetrieveAccounts			                = $true
      addAccounts                               = $true
      updateAccountContent                      = $true
      updateAccountProperties                   = $true
      initiateCPMAccountManagementOperations    = $true
      specifyNextAccountContent                 = $true
      renameAccounts                            = $true
      deleteAccounts                            = $true
      unlockAccounts                            = $true
      manageSafe                                = $true
      manageSafeMembers                         = $true
      backupSafe                                = $true
      viewAuditLog                              = $true
      viewSafeMembers                           = $true
      accessWithoutConfirmation                 = $true
      createFolders                             = $true
      deleteFolders                             = $true
      moveAccountsAndFolders                    = $true
      requestsAuthorizationLevel1               = $true
      requestsAuthorizationLevel2               = $false
    }
    try{
        Write-Host "Logging onto $($config.PVWAURL)/PasswordVault as $($psCredential.UserName)" -ForegroundColor Green
        New-PASSession -Credential $psCredential -type $config.AuthenticationType -BaseURI $config.PVWAURL -concurrentSession $true -SkipCertificateCheck -SkipVersionCheck
        Write-Host "Creating the CA-HealthCheck Safe" -ForegroundColor Green
        Add-PASSafe -SafeName "CA-HealthCheck" -Description "Safe for the Storage of the HealthCheck Accounts" -NumberOfVersionsRetention 5 -ManagingCPM $config.CPMUser | Out-Null
        Write-Host "Adding Vault Admins as a Member" -ForegroundColor Green
        $AdminRole | Add-PASSafeMember -SafeName "CA-HealthCheck" -MemberName "Vault Admins" -SearchIn "Vault" -memberType Group | Out-Null
        Close-PASSession
    }catch{
        Write-Host "Error Creating Safe and Adding Safe Member, Create Manually" -ForegroundColor Red
    }
    pause
}
<####################################################################################################################
Function Name: Add-HCAccounts
Description: Onboarding a HC Account for each server specified in the config file 
###################################################################################################################>
Function Add-HCAccounts{
    $config = Read-Config -configFilePath ..\Config\Config.xml
    if ($null -eq $config) {
        Write-Host "Exiting due to missing config file."
        return
    }
    $psCredential = Read-CredFile -CFPath ..\Config\User.xml
    #Validate that the serverlist is correct before onboarding
    Clear-Host
    Write-Host "Creating an account of each server in the list below:"
    $config.Servers
    $CreateAccounts = Read-Host "Do you want to continue (yes\no)"
    if ($CreateAccounts  -eq "yes" -or $CreateAccounts  -eq "y") {
            try{
        Write-Host "Logging onto $($config.PVWAURL)/PasswordVault as $($psCredential.UserName)" -ForegroundColor Green
        New-PASSession -Credential $psCredential -type $config.AuthenticationType -BaseURI $config.PVWAURL -concurrentSession $true -SkipCertificateCheck -SkipVersionCheck
        foreach($Server in $config.Servers){
            try{
                Write-Host "Onboarding $($Server)..." -ForegroundColor Green
                $Account = Add-PASAccount -userName "Health-Check" -address $Server -platformID "CyberArk-HealthCheck" -SafeName "CA-HealthCheck" 
                Write-Host "$($Account.UserName) for $($Account.address) has been onboarded successfully" -ForegroundColor Green
            }catch{
                Write-Host "Error Onboarding $($Server), Onboard them Manually" -ForegroundColor Red
            }
        }
        pause
        Close-PASSession
    }catch{
        Write-Host "Error Onboarding the accounts, Onboard them Manually" -ForegroundColor Red
    }
    }else{
        return
    }
    pause
}
<####################################################################################################################
Function Name: New-HCUser
Description: Create the user that will be used to push and pull the Health Check Data
###################################################################################################################>
function New-HCUser{
    $config = Read-Config -configFilePath ..\Config\Config.xml
    if ($null -eq $config) {
        Write-Host "Exiting due to missing config file."
        return
    }
    $psCredential = Read-CredFile -CFPath ..\Config\User.xml
    
    $SecurePassword = Get-Credential -UserName "HealthCheckUser" -Message "Set the Password for the HealthCheckUser"
    try{
        Write-Host "Logging onto $($config.PVWAURL)/PasswordVault as $($psCredential.UserName)" -ForegroundColor Green
        New-PASSession -Credential $psCredential -type $config.AuthenticationType -BaseURI $config.PVWAURL -concurrentSession $true -SkipCertificateCheck -SkipVersionCheck
        Write-Host "Creating the HealthCheck-user" -ForegroundColor Green
        $User = New-PASUser -UserName "HealthCheckUser" -InitialPassword $SecurePassword.Password -vaultAuthorization ManageServerFileCategories,ActivateUsers,AddNetworkAreas,AddUpdateUsers,AddSafes,AuditUsers,BackupAllSafes -passwordNeverExpires $true -ChangePassOnNextLogon $false
        $HCSafe = Get-PASSafe -SafeName "CA-HealthCheck"
        if($HCSafe){
            try{
                $AdminRole = [PSCustomObject]@{
                  UseAccounts                               = $true
                  ListAccounts                              = $true
                  RetrieveAccounts			                = $true
                  addAccounts                               = $true
                  updateAccountContent                      = $true
                  updateAccountProperties                   = $true
                  initiateCPMAccountManagementOperations    = $true
                  specifyNextAccountContent                 = $true
                  renameAccounts                            = $true
                  deleteAccounts                            = $true
                  unlockAccounts                            = $true
                  manageSafe                                = $true
                  manageSafeMembers                         = $true
                  backupSafe                                = $true
                  viewAuditLog                              = $true
                  viewSafeMembers                           = $true
                  accessWithoutConfirmation                 = $true
                  createFolders                             = $true
                  deleteFolders                             = $true
                  moveAccountsAndFolders                    = $true
                  requestsAuthorizationLevel1               = $true
                  requestsAuthorizationLevel2               = $false
                }
                Write-Host "Adding HealthCheckUser to the CA-HealthCheck safe" -ForegroundColor Green
                $AdminRole | Add-PASSafeMember -SafeName "CA-HealthCheck" -MemberName "HealthCheckUser" -SearchIn "Vault" -memberType User | Out-Null
                Write-Host "Adding HealthCheckUser to Auditors Group" -ForegroundColor Green
                $AuditorsID = (Get-PASGroup -groupName Auditors).id
                Add-PASGroupMember -groupId $AuditorsID -memberId $User.username -memberType vault | Out-Null
                Write-Host "HealthCheckUser has been setup Successfully" -ForegroundColor Green
            }catch{
                Write-Host "Error Couldn't add HealthCheckuser to the HealthCheck Safe or the Auditors Group, Add Manually" -ForegroundColor Red
            }
        }
    }catch{
        Write-Host "Error Creating HealthCheckUser, Create Manually" -ForegroundColor Red
    }
    Write-Host "Updating User.xml file with HealthCheckUser"
    $SecurePassword | Export-Clixml -Path ..\Config\User.xml
    pause
    
}


<####################################################################################################################
Function Name: Read-HCAccountMenu
Description: Menu function to setup the Health Check Accounts in CyberArk
###################################################################################################################>
function Read-HCAccountMenu{
    do {
        Clear-Host
        Write-Host "`nMenu" -ForegroundColor Cyan
        Write-Host "1. Import the Health Check Platform" -ForegroundColor Cyan
        Write-Host "2. Setup the Health Check Safe & Safe Members" -ForegroundColor Cyan
        Write-Host "3. Create Health Check Accounts for each server" -ForegroundColor Cyan
        Write-Host "4. Perform All Steps" -ForegroundColor Cyan
        Write-Host "0. Exit" -ForegroundColor Cyan
        $choice = Read-Host "Select an option"
        
        switch ($choice) {
            "1" {Import-HCPlatform}
            "2" {Add-HCSafe}
            "3" {Add-HCAccounts}
            "4" {
                Clear-Host
                Write-Host "Performing All steps"-ForegroundColor Green
                Import-HCPlatform
                Add-HCSafe
                Add-HCAccounts
            }
            "0" {}
            default { Write-Host "Invalid selection, please try again."-ForegroundColor Red }
        }
    } until ($choice -eq "0")
}

<####################################################################################################################
Function Name: Set-HCTemplate
Description: Setup the Health Check Template Report
###################################################################################################################>
function Set-HCTemplate{
    # Load the HTML template
    Write-Host "Reading config file and creating template..." -ForegroundColor Green
    try{
    $config = Read-Config -configFilePath ..\Config\Config.xml
    $templatePath = "..\Prerequisites\HCTemplate.html"
    $template = Get-Content -Path $templatePath -Raw
    $outputPath = "..\Reports\Template\$($config.CustomerName)-HCReport.html"
    $htmlContent = @()

    $htmlReport = $template -replace '<!--CustomerName-->', $config.CustomerName

    foreach ($server in $config.servers) {
    # Add the collapsible button and table for each server
    $htmlContent += @"
<div class="server">
    <button class='collapsible'>$server</button>
    <div class='content'>
        <h3>System information</h3>
        <table>
            <thead>
                <tr>
                    <th>IPAddress</th>
                    <th>OSVersion</th>
                    <th>ServerUptime</th>
                    <th>CPU</th>
                    <th>RAM</th>
                </tr>
            </thead>
            <tbody>
                <!--$($server)_SystemInfo-->
            </tbody>
        </table>
        <h3>Disk Info</h3>
        <table>
            <thead>
                <tr>
                    <th>Disk</th>
                    <th>Total Space GB</th>
                    <th>Free Space GB</th>
                </tr>
            </thead>
            <tbody>
                <!--$($server)_Disks-->
            </tbody>
        </table>
        <h3>Installed Components</h3>
        <table>
            <thead>
                <tr>
                    <th>Component</th>
                    <th>Version</th>
                    <th>Install Date</th>
                </tr>
            </thead>
            <tbody>
                <!--$($server)_Components-->
            </tbody>
        </table>
        <h3>Services</h3>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Status</th>
                    <th>Running Duration</th>
                </tr>
            </thead>
            <tbody>
                <!--$($server)_Services-->
            </tbody>
        </table>
    </div>
</div>
"@
    }

    #Add the JavaScript to make the servers collapsible
    $htmlContent += @"
<script>
    var coll = document.getElementsByClassName('collapsible');
    for (var i = 0; i < coll.length; i++) {
        coll[i].addEventListener('click', function() {
            this.classList.toggle('active');
            var content = this.nextElementSibling;
            if (content.style.display === 'block') {
                content.style.display = 'none';
            } else {
                content.style.display = 'block';
            }
        });
    }
</script>
"@
    #Updating the template
    $htmlReport = $htmlReport -replace '<!--ServerDetails-->', $htmlContent
    $htmlReport | Out-File -FilePath $outputPath
    Write-Host "Template for $($config.CustomerName) was created successfully" -ForegroundColor Green
    }catch{
        Write-Host "Error couldn't create template, create it manually" -ForegroundColor Red
    }
    pause
}
<####################################################################################################################
Function Name: Read-MainMenu
Description: Menu function for the setup of the Report Prerequisites
###################################################################################################################>

function Read-MainMenu {
    do {
        Clear-Host
        Write-Host "`n####################################################################################" -ForegroundColor Yellow
        Write-Host "Main Menu" -ForegroundColor Yellow
        Write-Host "####################################################################################`n" -ForegroundColor Yellow
        Write-Host "1. Check the psPAS module" -ForegroundColor Yellow
        Write-Host "2. Setup Credential File" -ForegroundColor Yellow
        Write-Host "3. Setup Config File" -ForegroundColor Yellow
        Write-Host "4. Setup Health Check Accounts in CyberArk" -ForegroundColor Yellow
        Write-Host "5. Create Report User" -ForegroundColor Yellow
        Write-Host "6. Setup Report Template" -ForegroundColor Yellow
        Write-Host "7. Perform All Steps" -ForegroundColor Yellow
        Write-Host "0. Exit" -ForegroundColor Yellow
        $choice = Read-Host "Select an option"
        
        switch ($choice) {
            "1" {Confirm-psPAS}
            "2" {New-CredFile -ExportFilePath ..\Config}
            "3" {New-ConfigFile}
            "4" {Read-HCAccountMenu}
            "5" {New-HCUser}
            "6" {Set-HCTemplate}
            "7" {
                Clear-Host
                Write-Host "Performing All steps"-ForegroundColor Green
                Confirm-psPAS
                New-CredFile -ExportFilePath ..\Config
                New-ConfigFile
                Read-HCAccountMenu
                New-HCUser
                Set-HCTemplate
            }
            "0" {}
            default { Write-Host "Invalid selection, please try again."-ForegroundColor Red }
        }
    } until ($choice -eq "0")
}

