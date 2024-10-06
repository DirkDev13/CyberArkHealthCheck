<#################################################
HCReport_Prerequisites
Installs the prerequisites required to 
1. Install the psPAS module
2. Create Report User
3. Setup Credential File
4. Setup Config File
5. Setup Report Export Location
6. Setup the Health Check Accounts in CyberArk
    6.1 Import the platform
    6.2 Create the Safe and add the Safe Members
    6.3 Create Accounts for each server  
<#################################################>

Import-Module .\Setup-HCReport.psm1
Read-MainMenu

