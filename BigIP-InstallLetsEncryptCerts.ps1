# This script uses the BigIP API with datagroups to automaticacally respond to the LE HTTP challenge and generate and install certs on F5 load balancers
# Before running this script, you will need to create an internal datagroup. The example irule below uses one named "letsencrypt_http_challenge_dg"

# The corresponding irule for this script has been copied below for the sake of convenience. MAKE SURE TO UNDERSTAND HOW THIS IRULE WORKS BEFORE APPLYING IT.
# Poorly implemented irules have been known to ruin days. 

######################################################

# when HTTP_REQUEST {

#   # If the load balancer recieves a request containing a challenge URL, craft a 200 response containing the auth token

#   if { [string tolower [HTTP::path]] starts_with "/.well-known/acme-challenge/" } {
#       set token [lindex [split [HTTP::path] "/"] end]
#       set http_challenge_response [class lookup $token "/Common/letsencrypt_http_challenge_dg"]
#     HTTP::respond 200 content "$http_challenge_response"
#       event HTTP_REQUEST disable
#       return
#   }
# }

######################################################

$minimumCertAgeDays = "30" # How many days to expiration to wait before renewing
$certificate_subject = "" # Domain that you're generating the certificate for 
$bigip_host = "bigip.local.domain"
$bigip_username = ""
$bigip_password = ConvertTo-SecureString "plain_text_password" -AsPlainText -Force #converts plaintext password to secure string
$credentials = New-Object System.Management.Automation.PSCredential($bigip_username, $bigip_password)

$letsencrypt_environment = "LE_STAGE" # Change this to LE_PROD for production
$letsencrypt_contact = "me@example.com" # The account used to generate the cert

# this is the internal datagroup that will contain the response to the HTTP Challenge
# it needs to exist *prior* to running this script
$letsencrypt_bigip_datagroup = "letsencrypt_http_challenge_dg"
Function Check_Certificate_Status {

#disable the cert validation check just in case a certificate is already expired. 
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# Make a web request to check the status of the existing certificate
$certificate_check_request = [Net.HttpWebRequest]::Create("https://$certificate_subject")
$certificate_check_request.AllowAutoRedirect = $false
try {$certificate_check_request.GetResponse() | Out-Null} catch {throw}

Write-Host "Checking current certificate for https://$certificate_subject"
  #Set variables to check cert expiration
  [datetime]$expiration = [System.DateTime]::Parse($certificate_check_request.ServicePoint.Certificate.GetExpirationDateString())
  [int]$certExpiresIn = ($expiration - $(get-date)).Days

  #Check to see if the cert has passed the renewal threshold 
    if ($certExpiresIn -gt $minimumCertAgeDays ) {
      Write-Host "Cert expires in $certExpiresIn days. It will not be renewed until it's $minimumCertAgeDays days to expiration."
      exit
    }
  else {
    Write-Host "cert expires in $certExpiresIn days. Starting renewal..."
  }

}
Function Request_LetsEncrypt_Cert {
  Set-PAServer $letsencrypt_environment
  # Create a new account only if needed.
  if (-not (Get-PAAccount)) {
      Write-Host "Creating new account"
      New-PAAccount -Contact "$letsencrypt_contact" -AcceptTOS
  }

  Write-Host "Submitting certificate order for $certificate_subject"
  New-PAOrder $certificate_subject -Force | Out-Null
  $Auth_Array = @() # Initializing an empty array to account for one or more certificate subjects
  $script:Authorizations = $Auth_Array += (Get-PAOrder | Get-PAAuthorizations)
  $script:main_domain = $Authorizations[0].fqdn
}
Function Configure_BigIP_HTTP_Challenge_Response { 
  for ($i=0; $i -lt $Authorizations.length; $i++) {
    $cert_fqdn =  $Authorizations[$i].fqdn
    $challenge_token = $Authorizations[$i].http01token
    $challenge_url = "http://$cert_fqdn/.well-known/acme-challenge/$challenge_token"
    $auth_key = Get-KeyAuthorization $challenge_token
    $letsencrypt_authorization_url = $Authorizations[$i].http01url

    Write-Host "Certificate Subject: $cert_fqdn"
    Write-Host "Challenge URL: $challenge_url"
    Write-Host "Authorization Key: $auth_key"
    Write-Host "Using the BigIP API to generate a response to the LetsEncrypt HTTP Challenge" 

    #Update the datagroup with the challenge token and response. 
    $body =  @{
      name = $letsencrypt_bigip_datagroup    
      records = @(  
        @{
          "name" = $challenge_token
          "data" = $auth_key
         }
       ) 
    }

    Invoke-RestMethod `
    -Uri "https://$bigip_host/mgmt/tm/ltm/data-group/internal/~Common~$letsencrypt_bigip_datagroup" `
    -ContentType "application/json" `
    -Method PATCH `
    -Credential $credentials `
    -UseBasicParsing `
    -Body ($body | ConvertTo-Json) | Out-Null  

    Start-Sleep -Seconds 30 #Wait a little bit for the config to be applied
    $letsencrypt_authorization_url | Send-ChallengeAck
    Start-Sleep -Seconds 10
    Write-Host "Sending HTTP domain validation challenge"
  }
  # View certificate validation status
  Get-PAOrder | Get-PAAuthorizations | Format-Table
}
Function Create_LetsEncrypt_Cert{ 
  Write-Host "Creating and renaming the LetsEncrypt certificate"
  $new_certificate = New-PACertificate $certificate_subject -Contact "$letsencrypt_contact" -Force
  $script:certificate_name = "letsencrypt_$main_domain"
  $old_certificate_folder = ($new_certificate.PfxFullChain | Split-Path -Parent)
  $old_certificate_name = ($new_certificate.PfxFullChain | Split-Path -Leaf)

  Move-Item -Path $old_certificate_folder -Destination $env:Temp -Force
  Rename-Item -Path $env:Temp\$main_domain\$old_certificate_name -NewName "$certificate_name.pfx" -Force
}
Function Install_LetsEncrypt_Cert_On_BigIP { 
  # Copy cert to tmp directory on the load balancer using SCP
  Write-Host "Uploading certificate to $bigip_host"
  Set-SCPFile -ComputerName $bigip_host -Credential $credentials `
      -RemotePath "/var/tmp/" `
      -LocalFile "$env:Temp\$main_domain\$certificate_name.pfx" `
      -AcceptKey:$true

  # Install the cert on the load balancer
  Write-Host "Installing certificate $certificate_name to $bigip_host"
 
  $body = @{
    "command"           = "install"
    "name"              = $certificate_name
    "from-local-file"   = "/var/tmp/$certificate_name.pfx"
    "passphrase"        = "poshacme"
  }

  Invoke-RestMethod `
    -Uri https://$bigip_host/mgmt/tm/sys/crypto/pkcs12 `
    -ContentType 'application/json' `
    -Method POST `
    -Credential $credentials `
    -UseBasicParsing `
    -body ($body | ConvertTo-Json) | Out-Null

  Write-Host "Deleting certificate folder from local temp directory"
  Remove-Item $env:Temp\$main_domain -Recurse

  Write-Host "Done!"
}

try { #Necessary since powershell isn't respecting -ErrorAction. Forces the script to stop if there's ANY error
  Check_Certificate_Status
  Request_LetsEncrypt_Cert 
  Configure_BigIP_HTTP_Challenge_Response
  Create_LetsEncrypt_Cert
  Install_LetsEncrypt_Cert_On_BigIP
}
catch {
  throw
}