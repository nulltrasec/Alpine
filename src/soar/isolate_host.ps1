<#
.SYNOPSIS
    Alpine SOAR Endpoint Isolation & Network Quarantine Playbook

.DESCRIPTION
    Applies draconian Windows Defender Firewall rules to completely sever an infected
    endpoint's network connectivity while maintaining a persistent out-of-band management
    channel for the SOC over WinRM (TCP 5985).

.PARAMETER SocAddress
    The IP address of the SOC management gateway allowed to communicate with the host.
    Default: '10.254.2.1' (V.S 2 Gateway VIP)
#>

[CmdletBinding()]
param (
    [string]$SocAddress = "10.254.2.1"
)

Write-Output "[*] Executing Alpine Host Isolation Playbook..."
Write-Output "[*] Target Quarantine Active. Restricting network access..."

try {
    # 1. Block all inbound traffic across all profiles (Domain, Private, Public)
    New-NetFirewallRule -DisplayName "ALPINE-QUARANTINE-BLOCK-IN" `
                        -Direction Inbound `
                        -Action Block `
                        -Profile Any `
                        -Description "Alpine SOAR Automated Containment: Inbound Isolation" | Out-Null

    # 2. Block all outbound traffic across all profiles
    New-NetFirewallRule -DisplayName "ALPINE-QUARANTINE-BLOCK-OUT" `
                        -Direction Outbound `
                        -Action Block `
                        -Profile Any `
                        -Description "Alpine SOAR Automated Containment: Outbound Isolation" | Out-Null

    # 3. Punch hole specifically for the SOC Management Gateway over WinRM Inbound (TCP 5985)
    New-NetFirewallRule -DisplayName "ALPINE-QUARANTINE-ALLOW-WINRM-IN" `
                        -Direction Inbound `
                        -Action Allow `
                        -Protocol TCP `
                        -LocalPort 5985 `
                        -RemoteAddress $SocAddress `
                        -Profile Any `
                        -Description "Alpine SOAR: Preserved SOC Inbound Remote Access" | Out-Null

    # 4. Punch hole specifically for the SOC Management Gateway over WinRM Outbound (TCP 5985)
    New-NetFirewallRule -DisplayName "ALPINE-QUARANTINE-ALLOW-WINRM-OUT" `
                        -Direction Outbound `
                        -Action Allow `
                        -Protocol TCP `
                        -RemotePort 5985 `
                        -RemoteAddress $SocAddress `
                        -Profile Any `
                        -Description "Alpine SOAR: Preserved SOC Outbound Remote Access" | Out-Null

    Write-Output "[+] Host quarantined successfully. All C2 communication severed."
    Write-Output "[+] Out-of-band forensics pinhole established for $SocAddress on TCP 5985."
} catch {
    Write-Error "[-] Failed to apply isolation firewall rules: $_"
    exit 1
}
