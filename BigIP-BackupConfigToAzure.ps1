# Force TLS 1.2 if needed
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Define variables
$bigip_hosts = @("bigip.local.domain")
$bigip_username = ""
$bigip_password = ConvertTo-SecureString "plaintext_password" -AsPlainText -Force #converts plaintext password to secure string
$credentials = New-Object System.Management.Automation.PSCredential($bigip_username, $bigip_password)
$StorageAccountName = "" # Azure storage account name
$SasToken = ""

$StorageContext = New-AzStorageContext -StorageAccountName "$StorageAccountName" -SasToken "$SasToken"

# Loop through each WAF in the $bigip_hosts array
foreach  ($hostname in $bigip_hosts){
  
  # Define filename format and ssh session details
  $bigip_config_filename = "$hostname-$(Get-Date -Format 'MM-dd-yyyy-hhmmss')"
  $SessionID = New-SSHSession -ComputerName "$hostname" -Credential $credentials -AcceptKey:$true

  # Save the ucs file
  Write-Host "Saving $hostname ucs file" 
  Invoke-SSHCommand -Index $sessionid.sessionid -Command "tmsh save sys ucs $bigip_config_filename.ucs" -TimeOut 180 

  # Copy the ucs file to the local machine temp directory
  Write-Host "Downloading $hostname ucs file" 
  Get-SCPItem -ComputerName $hostname `
    -Credential $credentials `
    -Path "/var/local/ucs/$bigip_config_filename.ucs" `
    -PathType File `
    -Destination $env:Temp `
    -AcceptKey:$true

  # Upload config to blob storage.
  Write-Host "Uploading $hostname ucs file to blob storage" 
  Set-AzStorageBlobContent `
   -Container "$StorageAccountName" `
   -File "$env:Temp\$bigip_config_filename.ucs" `
   -Properties @{"ContentType" = "application/x-gzip"} `
   -Blob "BigIP\$hostname\$(Get-Date -Format 'MM-MMMM')\$bigip_config_filename.ucs" `
   -Context $StorageContext

  # Delete the local temp files and remove any backups on the WAF older than 2 days
  Write-Host "Deleting $hostname temp files and old backups" 
  Remove-Item "$env:Temp\$bigip_config_filename.ucs" -Force
  Invoke-SSHCommand -Index $sessionid.sessionid -Command "find /var/local/ucs -type f -name '$hostname*' -mtime +2 -exec rm {} \;" 

  # Close ssh session
  Remove-SSHSession -SessionId $sessionid.sessionid

}