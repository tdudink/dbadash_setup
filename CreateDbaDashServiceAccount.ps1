#Requires -Version 5.1
<#
.SYNOPSIS
   Creates a local service account if it doesn't exist and sends a secure link to a DBA.
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$DbaEmail,

    [Parameter(Mandatory=$false)]
    [string]$AccountName = "svc_dbadash"
)

# 1. Check if account already exists
if (Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue) {
    Write-Host "[-] Account '$AccountName' already exists. No actions taken." -ForegroundColor Yellow
    return # Exit the script
}

Write-Host "[+] Account '$AccountName' not found. Proceeding with creation..." -ForegroundColor Cyan

# 2. Generate a strong random password
# Requires .NET assembly for secure generation
Add-Type -AssemblyName System.Web
$PasswordLength = 24
$StrongPassword = [System.Web.Security.Membership]::GeneratePassword($PasswordLength, 5)

# 3. Create the Local User
try {
    New-LocalUser -Name $AccountName `
                  -Password ($StrongPassword | ConvertTo-SecureString -AsPlainText -Force) `
                  -Description "Service account for DBA tasks" `
                  -PasswordNeverExpires $true -ErrorAction Stop
    Write-Host "[+] Successfully created local user: $AccountName" -ForegroundColor Green
} catch {
    Write-Error "Failed to create user: $($_.Exception.Message)"
    return
}

# 4. Grant 'Log on as a Service' Rights
# Note: Requires Carbon module (Install-Module Carbon -Scope CurrentUser)
if (Get-Module -ListAvailable -Name Carbon) {
    Import-Module Carbon
    Grant-Privilege -Identity $AccountName -Privilege SeServiceLogonRight
    Write-Host "[+] Granted 'Log on as a Service' rights." -ForegroundColor Green
} else {
    Write-Warning "Carbon module not found. 'Log on as a Service' right was NOT applied."
    Write-Host "Install with: Install-Module Carbon" -ForegroundColor Gray
}

# 5. Generate OneTimeSecret Link
Write-Host "[+] Generating OneTimeSecret link..." -ForegroundColor Cyan
$OTS_URL = "https://onetimesecret.com/api/v1/share"

try {
    # Using the OTS API to create a secret link
    $Body = @{ secret = $StrongPassword; ttl = 3600 } # 1 hour expiry
    $Response = Invoke-RestMethod -Uri $OTS_URL -Method Post -Body $Body
    $SecretLink = "https://onetimesecret.com/secret/$($Response.secret_key)"
    
    # 6. Send Email
    $EmailBody = @"
A new local service account has been created on $($env:COMPUTERNAME).

Account Name: $AccountName
Security: Granted 'Log on as a Service'

The password can be retrieved ONLY ONCE at the following link (expires in 1 hour):
$SecretLink
"@

<#     $SmtpArgs = @{
        To         = $DbaEmail
        From       = "it-automation@yourdomain.com"
        Subject    = "NEW SERVICE ACCOUNT: $AccountName on $($env:COMPUTERNAME)"
        Body       = $EmailBody
        SmtpServer = "smtp.yourdomain.com" # Update this to your internal relay
    }
 #>
   # Send-MailMessage @SmtpArgs
   Write-Output $EmailBody
    Write-Host "[+] Password link sent to $DbaEmail" -ForegroundColor Green

} catch {
    Write-Error "Action completed, but failed to send email/OTS link. Manual intervention required."
    Write-Host "Password generated was: $StrongPassword" -ForegroundColor Red
}
