$mySid = (whoami /user).Split()[-1]
Get-NetFirewallRule |
  Where-Object { $_.DisplayName -like "*Minecraft*" -and $_.Owner -like "*$mySid" } |
  ForEach-Object {
      $_
      Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $_ | Select Program
      ""
  }
