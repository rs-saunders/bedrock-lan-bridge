$mapping = Get-NetNatStaticMapping -ErrorAction SilentlyContinue |
           Where-Object { $_.ExternalPort -eq 19132 -or $_.InternalPort -eq 19132 }

if ($mapping) { $mapping | Format-Table NatName, Protocol, ExternalIPAddress, ExternalPort, InternalIPAddress, InternalPort }
else { "No NAT mappings found on port 19132." }

Get-NetNat | Get-NetNatSession | Where-Object { $_.ExternalPort -eq 19132 }