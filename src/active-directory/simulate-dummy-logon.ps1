# Touch the honeytoken account to simulate background activity
Import-Module ActiveDirectory

$AccountName = "svc_sql_prod_migration"
$CurrentDate = Get-Date

Write-Host "Simulating activity for $AccountName..."

# Simply updating the description touches the AD object and updates its modified timestamps
# This makes it look active to tools like SharpHound/BloodHound
Set-ADUser -Identity $AccountName -Description "SQL Migration Service Account - Last checked: $CurrentDate"

Write-Host "Done! AD metadata updated."
