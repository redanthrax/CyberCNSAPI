# Unofficial CyberCNSAPI

This is the unofficial CyberCNS API and is a WIP.

# USAGE

```
Import-Module .\CyberCNSApi.psm1 -Force
$securePw = ConvertTo-SecureString "Password123" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("tech@acme.com", $securePw)
Connect-CyberCNSApi -Url "acme.mycybercns.com" -Credential $credential
$assets = Get-CyberCNSCompany -Name "ClientCompanyName" | Get-CyberCNSAsset
foreach($asset in $assets) {
    Write-Output "Name: $($asset.Name) - Score: $($asset.Risk)"
}
```