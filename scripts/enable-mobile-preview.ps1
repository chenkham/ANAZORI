param(
    [Parameter(Mandatory=$true)][System.Net.IPAddress]$Address,
    [Parameter(Mandatory=$true)][string]$NodePath
)
$ErrorActionPreference = 'Stop'
$previewAddress = $Address.ToString()
if ($Address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or $previewAddress -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') { throw 'Choose the private IPv4 address of the hotspot adapter.' }
$previewNode = (Resolve-Path -LiteralPath $NodePath).Path
if ([System.IO.Path]::GetFileName($previewNode) -ne 'node.exe') { throw 'Choose the Node.js executable used by the preview.' }
$previewRuleName = 'Anazori-Mobile-Preview-8000'
$previewRule = Get-NetFirewallRule -Name $previewRuleName -ErrorAction SilentlyContinue
if ($previewRule) {
    $previewRule | Set-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -Profile Any
    $previewRule | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -LocalAddress $previewAddress -RemoteAddress LocalSubnet
    $previewRule | Get-NetFirewallPortFilter | Set-NetFirewallPortFilter -Protocol TCP -LocalPort 8000
    $previewRule | Get-NetFirewallApplicationFilter | Set-NetFirewallApplicationFilter -Program $previewNode
} else {
    New-NetFirewallRule -Name $previewRuleName -DisplayName 'Anazori mobile preview 8000' -Enabled True -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort 8000 -LocalAddress $previewAddress -RemoteAddress LocalSubnet -Program $previewNode | Out-Null
}
