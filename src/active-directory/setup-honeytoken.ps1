# Simple AD Honeytoken Setup Script
Import-Module ActiveDirectory

$AccountName = "svc_sql_prod_migration"

# Cryptographically random 64-character password (matches
# docs/02-threat-model-and-attack/honeytoken-strategy.md). Nothing needs to
# ever log in as this account, so the password is generated and never
# printed or stored anywhere.
function New-CryptoRandomPassword {
    param([int]$Length = 64)
    $charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+'
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    -join ($bytes | ForEach-Object { $charset[$_ % $charset.Length] })
}

$PlainPassword = New-CryptoRandomPassword -Length 64
$SecurePassword = ConvertTo-SecureString $PlainPassword -AsPlainText -Force
Remove-Variable PlainPassword

Write-Host "Creating honeytoken user $AccountName..."

# Create user with DoesNotRequirePreAuth set to True for AS-REP roasting
New-ADUser -Name $AccountName `
           -SamAccountName $AccountName `
           -AccountPassword $SecurePassword `
           -Enabled $true `
           -PasswordNeverExpires $true `
           -Description "SQL Migration Service Account" `
           -DoesNotRequirePreAuth $true

Write-Host "Adding to Server Operators group to bait attackers..."
Add-ADGroupMember -Identity "Server Operators" -Members $AccountName -ErrorAction SilentlyContinue

Write-Host "Done! Account created and Kerberos pre-auth disabled."
