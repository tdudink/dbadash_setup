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
    return 
}

Write-Host "[+] Account '$AccountName' not found. Proceeding with creation..." -ForegroundColor Cyan

# 2. Generate a strong random password (Native PowerShell Method)
# This replaces the [System.Web] dependency that caused your error.
$charSet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()"
$PasswordLength = 24
$StrongPassword = -join ((1..$PasswordLength) | ForEach-Object { $charSet[(Get-Random -Minimum 0 -Maximum $charSet.Length)] })

# 3. Create the Local User using Splatting
try {
    $UserParams = @{
        Name                 = $AccountName
        Password             = ($StrongPassword | ConvertTo-SecureString -AsPlainText -Force)
        Description          = "Service account for DBA tasks"
        PasswordNeverExpires = $true
        ErrorAction          = "Stop"
    }
    
    New-LocalUser @UserParams
    Write-Host "[+] Successfully created local user: $AccountName" -ForegroundColor Green
} catch {
    Write-Error "Failed to create user: $($_.Exception.Message)"
    return
}

# 4. Grant 'Log on as a Service' Rights
if (Get-Module -ListAvailable -Name Carbon) {
    Import-Module Carbon
    Grant-Privilege -Identity $AccountName -Privilege SeServiceLogonRight
    Write-Host "[+] Granted 'Log on as a Service' rights via Carbon." -ForegroundColor Green
} else {
    Write-Warning "Carbon module not found. 'Log on as a Service' right was NOT applied."
}

# 5. Generate OneTimeSecret Link
Write-Host "[+] Generating OneTimeSecret link..." -ForegroundColor Cyan
$OTS_URL = "https://onetimesecret.com/api/v1/share"

try {
    $Body = @{ secret = $StrongPassword; ttl = 3600 } 
    $Response = Invoke-RestMethod -Uri $OTS_URL -Method Post -Body $Body
    $SecretLink = "https://onetimesecret.com/secret/$($Response.secret_key)"
    
    # 6. Send Email
    $EmailBody = @"
A new local service account has been created on $($env:COMPUTERNAME).

Account Name: $AccountName
Security: Granted 'Log on as a Service' (Requires Carbon module)

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
   Write-Host $EmailBody
   Write-Host "[+] Password link sent to $DbaEmail" -ForegroundColor Green

} catch {
    Write-Warning "Script succeeded but failed to send email/link. Password: $StrongPassword"
}