<#
.Synopsis
Short description
.DESCRIPTION
Long description
.EXAMPLE
Example of how to use this cmdlet
.EXAMPLE
Another example of how to use this cmdlet
#>

Function Get-UsersGroups{
    param (
      $username,
      [switch]$recurse
      )
    #Initialize output variable
    $groups = @()
    #Search AD user and retrieve the groups removing the unwanted characters from the strings.
    ((((get-aduser $username -properties memberof).memberof) | `
        % {$_ -split(",",2)} | `
         select-string -Pattern "CN\=.+" -AllMatches).Matches).Value | `
          ? {$_ -notlike "*,*"} | `
           % {$_ -replace ("CN=","")} | % {
           $groups += New-object psobject -Property @{
            "GroupName" = "$_"
            }

        }
  #if the recurse switch is applied find the groups they are a member of from group nesting.
  if ($recurse){
  Foreach ($item in $groups.GroupName) {
    $subgroups = try {(get-adgroup $item -properties memberof -ErrorAction stop).memberof}
                 catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                 }
   if ($subgroups -ne $null) {(($subgroups | ? {($_ -notlike "")} | `
        % {$_ -split(",",2)} | `
         select-string -Pattern "CN\=.+" -AllMatches).Matches).Value | `
          ? {$_ -notlike "*,*"} | `
           % {$_ -replace ("CN=","")} | % {
             $groups += New-object psobject -Property @{
              "GroupName" = "$_"
              }
            }
          }

        }
  }
  #Output the groups array
  return $groups
}

Function Get-UsersFolderPermissions{
    param(
      [string]$username,
      [string]$FolderPath
    )
    #Cleanse the username
    if ($username -ilike "*$((Get-ADDomain).NETBIOSNAME)*"){
        #Process username string removing domain if present.
        $username =  "$(($username.split("\",2)[1]))"
    }
    #Create Array for output
    $evaluatedpermissions = @()

    #Get Permissions where user is explicitly defined.
    $explicitpermissions = (get-childitem "$($FolderPath)" |? {$_.PSiscontainer} | % {Get-Acl $_.FullName -filter {Access -contains $($username) }}) | ? {$_.Access.IdentityReference -like "*$($username)"}
      $explicitpermissions  | foreach-object {
      if ($_ -ne $null) {
        $evaluatedpermissions +=  New-object psobject -property @{
          "Path" = "$($_.Path -replace('Microsoft.PowerShell.Core\\FileSystem::',''))";
          "Identity" = "$(($_.Access).IdentityReference | ? {$_ -ilike "*$username"})";
          "Access" = "$(($_.Access).FilesystemRights[0])";
            }
        }
      }


    #Get-Permissions from where user is a member of the group.
    $Usersgroups = Get-UsersGroups $username -recurse
    $usersgroups += New-object psobject -property @{"GroupName" = "Everyone"}
    $usersgroups += New-object psobject -property @{"GroupName" = "Authenticated Users"}
    $usersgroups += New-object psobject -property @{"GroupName" = "Domain Computers"}
    Foreach ($item in $Usersgroups) {
    $GroupPermissions = (get-childitem "$($FolderPath)" |? {$_.PSiscontainer} | % {Get-Acl $_.FullName -filter {Access -contains $($item.GroupName) }}) | ? {$_.Access.IdentityReference -like "*$($item.GroupName)*"}
    $GroupPermissions | foreach-object {if ($_ -ne $null) {
        $evaluatedpermissions +=  New-object psobject -property @{
          "Path" = "$($_.Path -replace('Microsoft.PowerShell.Core\\FileSystem::',''))";
          "Identity" = "$(($_.Access).IdentityReference | ? {$_ -ilike "*$($item.GroupName)"})";
          "Access" = "$((($_.Access) | ?{$_.IdentityReference -ilike "*$($item.GroupName)"}).FilesystemRights[0])";
            }
      }
    }
    }
    #Return full array of permissions.
    return $evaluatedpermissions
}
