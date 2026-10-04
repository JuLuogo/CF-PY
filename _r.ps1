param([Parameter(Mandatory = $true)][string]$ScriptFile)
$tmp = "$env:TEMP\cfip_audit"
if (-not (Test-Path "$tmp\pw.txt")) {
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    [System.IO.File]::WriteAllText("$tmp\pw.txt", 'g23H5T*PU7s^19')
    "@echo off`r`ntype `"$tmp\pw.txt`"" | Set-Content -Encoding ASCII "$tmp\askpass.bat"
}
$env:SSH_ASKPASS = "$tmp\askpass.bat"
$env:SSH_ASKPASS_REQUIRE = "force"
$env:DISPLAY = "localhost:0"
$body = [System.IO.File]::ReadAllText($ScriptFile) -replace "`r`n", "`n"
$b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($body))
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile="$tmp\known_hosts" `
    -o ConnectTimeout=20 -o PreferredAuthentications=password -o PubkeyAuthentication=no `
    -o LogLevel=ERROR -p 30501 root@natde1.bytevirt.net "echo $b64 | base64 -d | bash" 2>&1
