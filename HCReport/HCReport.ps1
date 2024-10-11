<#
Logon to CyberArk
Get All the Passwords for each account
Build a Summary View
Pull the PSMRecordings Safe information
Pull the System Health Information 
Build an HTML Report
#>

Import-Module .\HCReport.psm1
$pscredential = Read-CredFile -CFPath .\Config\User.xml
$config = Read-Config -configFilePath .\Config\Config.xml
$Safe = "CA-HealthCheck"
$Date = Get-Date
$templatePath = ".\Reports\Template\$($config.CustomerName)-HCReport.html"
$outputPath = ".\Reports\$($config.CustomerName)-CyberArkHCreport-$(Get-Date -f yyyy-MM-dd).html"
$HCData = @()

#region Pull the HC Data
New-PASSession -Credential $pscredential -type $config.AuthenticationType -BaseURI $config.PVWAURL -concurrentSession $true -SkipVersionCheck -SkipCertificateCheck
$Accounts = Get-PASAccount -safeName $Safe
    Foreach($Account in $Accounts){
        #Get the Password for each account object
        $Password = Get-PASAccountPassword -AccountID $Account.id -Reason "Pulling HealthCheck Data for Report"

        #Check that the Passwords are not empty
        if($Password.Password -ne ""){
            try{
                #Decode the HC Data
                $decodedData = Expand-HCData -EncodedData $Password.Password
                $ComponentHCData = $decodedData | ConvertFrom-Json

                #Store all the information
                $HCData += [PSCustomObject]@{
                    'Hostname' = $Account.address
                    'LastHCTime' = Convert-ToDateTime -NumericValue $Account.secretManagement.lastModifiedTime
                    'ComponentData' = $ComponentHCData 
                }
            }catch{
                Write-Host "Couldn't Decode HC Data for $($Account.address)" -ForegroundColor Red
            }

        }else{
            Write-Host "$($Account.address) has no HC Data" -ForegroundColor Yellow
        }
    }
#endregion

#region Build the Report
# Load the HTML template
$template = Get-Content -Path $templatePath -Raw

#loading the Date into the Report
$htmlReport = $template -replace '<!--ReportDate-->', $Date

#Create the summary table
$SummaryTable = @()
Foreach($Server in $HCData){
    $SummaryTable += [PSCustomObject]@{
        "Hostname" = $Server.Hostname
        "LastCheck" = $Server.LastHCTime
        "Components" = $Server.ComponentData.Summary.Components
        "ServicesCheck" = $Server.ComponentData.Summary.RunningServices
        "DiskCheck(+15GB)" = $Server.ComponentData.Summary."DiskCheck(+15GB)"   
    }
    
}
# Convert the $SummaryTable to HTML rows
$htmlRows = $SummaryTable | ForEach-Object {
    "<tr>
        <td>$($_.Hostname)</td>
        <td>$($_.LastCheck)</td>
        <td>$($_.Components)</td>
        <td>$($_.ServicesCheck)</td>
        <td>$($_."DiskCheck(+15GB)")</td>
    </tr>"
}
# Join the rows into a single string
$tableData = $htmlRows -join "`n"
# Replace the placeholder <!--TABLE_DATA--> in the template with actual table data
$htmlReport = $htmlReport -replace '<!--SummaryTable-->', $tableData

#Create the Backup time
$Backup = $HCData | Where-Object{$_.ComponentData.RawData.InstalledApps.DisplayName -eq 'Backup'}
$BackupRows = $Backup.ComponentData.RawData.BackupInfo | ForEach-Object{
    "<tr>
        <td>$($_.BackupType)</td>
        <td>$($_.BackupTime)</td>
    </tr>"    
}
$tableData = $BackupRows -join "`n"
$htmlReport = $htmlReport -replace '<!--BackupTable-->', $tableData

# Create the Recordings Table
$Vault = $HCData | Where-Object{$_.ComponentData.Summary.Components -eq 'Primary Vault'}
$RecordingRows = $Vault.ComponentData.PSMRecordingSafes | ForEach-Object{
    "<tr>
        <td>$($_.SafeName)</td>
        <td>$($_.MaxSize)</td>
        <td>$($_.Used)</td>
        <td>$($_.Free)</td>
    </tr>"
}
$tableData = $RecordingRows -join "`n"
$htmlReport = $htmlReport -replace '<!--RecordingsTable-->', $tableData

# Create the serverinformation tables
Foreach($Server in $HCData){
    #Adding Server Info
    $ServerInfoRows =     
    "<tr>
        <td>$($Server.ComponentData.RawData.SystemInfo.IPAddress)</td>
        <td>$($Server.ComponentData.RawData.SystemInfo.OSVersion)</td>
        <td>$($Server.ComponentData.RawData.SystemInfo.ServerUpTime)</td>
        <td>$($Server.ComponentData.RawData.SystemInfo.CPU)</td>
        <td>$($Server.ComponentData.RawData.SystemInfo.RAM)</td>
    </tr>"
    $tableData = $ServerInfoRows -join "`n"
    $htmlReport = $htmlReport -replace "<!--$($Server.Hostname)_SystemInfo-->", $tableData

    #Adding Disk Info
    $DiskInfoRows = $Server.ComponentData.RawData.SystemInfo.Disk | ForEach-Object{
        "<tr>
        <td>$($_.DeviceID)</td>
        <td>$($_.TotalSpaceGB)</td>
        <td>$($_.FreeSpaceGB)</td>
        </tr>"        
    }
    $tableData = $DiskInfoRows -join "`n"
    $htmlReport = $htmlReport -replace "<!--$($Server.Hostname)_Disks-->", $tableData

    #Adding Installed Components Info
    $InstalledComponentRows = $Server.ComponentData.RawData.InstalledApps | ForEach-Object{
        "<tr>
        <td>$($_.DisplayName)</td>
        <td>$($_.DisplayVersion)</td>
        <td>$($_.InstallDate)</td>
        </tr>"
    }
    $tableData = $InstalledComponentRows -join "`n"
    $htmlReport = $htmlReport -replace "<!--$($Server.Hostname)_Components-->", $tableData

    #Adding Services Info
    $ServicesRows = $Server.ComponentData.RawData.Services | ForEach-Object{
        "<tr>
            <td>$($_.DisplayName)</td>
            <td>$($_.Status)</td>
            <td>$($_.RunningDuration)</td>
        </tr>"        
    }
    $tableData = $ServicesRows -join "`n"
    $htmlReport = $htmlReport -replace "<!--$($Server.Hostname)_Services-->", $tableData
}

# Output the HTML report to a file

$htmlReport | Out-File -FilePath $outputPath

# Optionally, open the file automatically in the browser
Start-Process $outputPath


#endregion



