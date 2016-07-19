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
    $groups = @()
    ((((get-aduser $username -properties memberof).memberof) | `
        % {$_ -split(",",2)} | `
         select-string -Pattern "CN\=.+" -AllMatches).Matches).Value | `
          ? {$_ -notlike "*,*"} | `
           % {$_ -replace ("CN=","")} | % {
           $groups += New-object psobject -Property @{
            "GroupName" = "$_"
            }

        }
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
  return $groups
}

Function Get-NTFSPermissions {

}

Function Get-FilePermissions{
    param(
      [string]$username,
      [string]$FolderPath,
      [int]$depth
    )
    #Process username string, converting domain name to Uppercase and username to lowercase string.
    $username =  "$(($username.split("\",2)[0]).ToUpper()\)$($username.split("\",2)[1]).ToLower()"

    $ADGroups = Get-UsersGroups -username $username
    #Create Array for output
    $evaluatedpermissions = @()

    #Get Permissions where user is explicitly defined.
    $explicitpermissions = (get-childitem "$($FolderPath)"  -Exclude "*.*" -Depth "$($depth)"  |`
    % {Get-Acl $_.FullName -filter {Access -contains $($username) }}) | `
      ` ? {$_.Access.IdentityReference -like "*$($username)*"}
      $evaluatedpermissions +=  New-object psobject -property @{
        "Path" = "$($explicitpermissions.FullName)";
        "Owner" = "$($explicitpermissions.Owner)";
        "Access" = "$($explicitpermissions.Access)";
      }

    #Get-Permissions from where user is a member of the group.
    $Usersgroups = Get-UsersGroups $username -recurse
    Foreach ($item in $Usersgroups) {
    $GroupPermissions = (get-childitem "$($FolderPath)"  -Exclude "*.*" -Depth "$($depth)"  |`
    % {Get-Acl $_.FullName -filter {Access -contains $($username) }}) | `
      ` ? {$_.Access.IdentityReference -like "*$($username)*"}
    if ($GroupPermissions -ne $null) {
        $evaluatedpermissions +=  New-object psobject -property @{
          "Path" = "$($GroupPermissions.FullName)";
          "Owner" = "$($GroupPermissions.Owner)";
          "Access" = "$($GroupPermissions.Access)";
        }
      }
    }
return $evaluatedpermissions
}
