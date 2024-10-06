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
    $PVWAURL = $configXml.Configuration.PVWAURL
    $AuthenticationType = $configXml.Configuration.AuthenticationType
    # Return the extracted values as a hashtable
    return @{
        PVWAURL = $PVWAURL
        AuthenticationType = $AuthenticationType
    }
}
<####################################################################################################################
Function Name: Expand-HCData
Description: Decompresses and decodes the HealthCheck data
###################################################################################################################>
function Expand-HCData {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EncodedData
    )

    # Decode the base64 string back to compressed bytes
    $compressedBytes = [System.Convert]::FromBase64String($EncodedData)

    # Create a memory stream from the compressed bytes
    $compressedStream = New-Object System.IO.MemoryStream
    $compressedStream.Write($compressedBytes, 0, $compressedBytes.Length)
    $compressedStream.Position = 0

    # Decompress the GZip stream
    $gzipStream = New-Object System.IO.Compression.GZipStream($compressedStream, [System.IO.Compression.CompressionMode]::Decompress)
    $decompressedStream = New-Object System.IO.MemoryStream
    $gzipStream.CopyTo($decompressedStream)
    $gzipStream.Close()

    # Convert decompressed bytes back to a JSON string
    $decompressedBytes = $decompressedStream.ToArray()
    $jsonString = [System.Text.Encoding]::UTF8.GetString($decompressedBytes)

    return $jsonString
}

<####################################################################################################################
Function Name: Convert-ToDateTime
Description: Converts a Numberic Value to a DateTime value
###################################################################################################################>
Function Convert-ToDateTime ($NumericValue) {
    [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($NumericValue))
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
