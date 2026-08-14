# Share the mounted KAPE volume (H:\C) so SIFT can parse the same bytes.
# Design: Windows owns the mount; SIFT CIFS-mounts it at /mnt/windows_mount.
# Requires elevation for New-SmbShare. SCP is not used.
#
# Usage (elevated PowerShell):
#   .\scripts\lab_share_kape.ps1
#   .\scripts\lab_share_kape.ps1 -SiftHost 192.168.77.135

param(
    [string]$ShareName = "kape",
    [string]$LocalPath = "H:\C",
    [string]$SiftHost = "192.168.77.135",
    [string]$SiftUser = "sansforensics",
    [string]$SiftMount = "/mnt/windows_mount",
    [string]$SshKey = "$env:USERPROFILE\.ssh\cadre-sift-key",
    [switch]$SkipSiftMount
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $LocalPath)) {
    throw "KAPE path not found: $LocalPath (is H: mounted?)"
}

$existing = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Share $ShareName already exists -> $($existing.Path)"
    if ($existing.Path.TrimEnd('\') -ne (Resolve-Path $LocalPath).Path.TrimEnd('\')) {
        throw "Share $ShareName points at $($existing.Path), expected $LocalPath"
    }
} else {
    New-SmbShare -Name $ShareName -Path $LocalPath -ReadAccess "Everyone" -Description "CADRE KAPE triage (read)"
    Write-Host "Created SMB share $ShareName = $LocalPath"
}

$rule = Get-NetFirewallRule -DisplayName "CADRE-KAPE-SMB" -ErrorAction SilentlyContinue
if (-not $rule) {
    New-NetFirewallRule -DisplayName "CADRE-KAPE-SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow -Profile Any | Out-Null
    Write-Host "Opened inbound TCP/445 (CADRE-KAPE-SMB)"
}

$hostIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like "192.168.77.*" -and $_.IPAddress -ne "192.168.77.255" } | Select-Object -First 1).IPAddress
if (-not $hostIp) { $hostIp = "192.168.77.1" }
Write-Host "Windows share UNC: \\$hostIp\$ShareName"
Write-Host "SIFT should mount: $SiftMount  (NEXUS_SIFT_TRIAGE_ROOT=$SiftMount)"

if ($SkipSiftMount) { return }

if (-not (Test-Path $SshKey)) {
    Write-Warning "No SSH key $SshKey — mount SIFT yourself:"
    Write-Host "  sudo mkdir -p $SiftMount"
    Write-Host "  sudo mount -t cifs //$hostIp/$ShareName $SiftMount -o guest,ro,vers=3.0,uid=1000,gid=1000"
    return
}

$remote = @"
sudo mkdir -p $SiftMount
if mountpoint -q $SiftMount; then echo ALREADY_MOUNTED; ls `$SiftMount | head; exit 0; fi
sudo mount -t cifs //$hostIp/$ShareName $SiftMount -o guest,ro,vers=3.0,uid=1000,gid=1000,nounix,iocharset=utf8
echo MOUNT_RC=`$?
ls $SiftMount | head
test -d $SiftMount/Windows && echo WINDOWS_ROOT_OK
"@
ssh -i $SshKey -o BatchMode=yes -o StrictHostKeyChecking=no "${SiftUser}@${SiftHost}" $remote
