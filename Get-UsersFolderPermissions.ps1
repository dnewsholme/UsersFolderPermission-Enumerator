<#
.Synopsis
Gets all permissions either explicit or by group membership for a given user on the sub-folders for path specified even if it's a nested group which grants access.

.DESCRIPTION
Gets all permissions either explicit or by group membership for a given user on the sub-folders for path specified even if it's a nested group which grants access.

Features:

+ Searches ACLS Matching username.
+ Searches ACLS Matching group membership including recursive/sub groups.

`Note: you need to run the PowerShell window as privileged user such as a domain admin.`

.PARAMETER username
The username you wish to see the effective permissions for, either Domain\username format or just username.

.PARAMETER FolderPath
The folder you wish to get permissions from. Note it Searches the children of this item.

.PARAMETER recurse
Adding this switch will search the child directories as well.

.PARAMETER NoDefaultGroups
Using this switch will remove the groups users are a memberof by default eg. Everyone,Domain Computers,Authenticated Users and BUILTIN\Users

.PARAMETER depth
This parameter only works with recurse if not specified with recurse it will default to 0. Otherwise Will search the amount of sub-directories you specify.

.EXAMPLE
Get-UsersFolderPermissions -username bgates -path "E:\Microsoft" -recurse -depth 5

.EXAMPLE
Get-UsersFolderPermissions -username bgates -path "E:\Microsoft"

.EXAMPLE
Get-UsersFolderPermissions -username bgates -path "\\fileserver01\Microsoft" -NoDefaultGroups

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
      [string]$FolderPath,
      [switch]$recurse,
      [switch]$NoDefaultGroups,
      [int32]$depth
    )
    #test module import
    try {Import-Module activedirectory}
    catch [System.IO.FileNotFoundException] {
        $Error[0].Exception
        Write-Error "This module requires the ActiveDirectory Module for group membership lookup."
        exit
    }
    if ($depth -and $recurse -like $null){
      Write-Error "To use depth parameter the recurse switch must also be specified."
    }
    elseif ($depth -and $recurse -eq $true -and (((get-host).version).Major) -lt 5 ) {
      #powershell version isn't 5 so some jiggerypokery needed to set recurse depth.
        Write-Verbose "Powershell Version doesn't support depth parameter, using \* method"
        While ($depth -gt 0){
          #Check for trailing slash and remove if exists on path.
          if ($folderpath[-1] -eq "\"){$folderpath.replace($folderpath[-1],"")}
          #Add backslash and asterix for as many directories the recurse is required for.
          $folderpath += "\*"
          $depth = ($depth - 1)
        }
      $gcitemparams = @{
        "path" = "$($FolderPath)"
      }
    }
    Else {
      $gcitemparams = @{
        "path" = "$($FolderPath)"
        "recurse" = $(if($recurse){$true}Else{$false})
        "depth" = $(if ($depth){$depth}else{0})
      }
    }
    #Cleanse the username
    if ($username -ilike "*$((Get-ADDomain).NETBIOSNAME)*"){
        #Process username string removing domain if present.
        $username =  "$(($username.split("\",2)[1]))"
    }
    #Set Parameters for getting folders based on Parameters specified.
    Write-Verbose "Getting Folder ACLS"
    #If not set to recurse just get the single folder ACLS
    if ($recurse -eq $false){
      $foldersacls = (get-item $folderpath).where({$_.PSiscontainer -eq $true}) | Get-Acl
    }
    #Otherwise get for children at
    Else {
      $foldersacls = (get-childitem @gcitemparams).where({$_.PSiscontainer -eq $true}) | Get-Acl
    }
    #Create Array for output
    $evaluatedpermissions = @()

    #Filter Permissions where user is explicitly defined.
    $explicitpermissions = $foldersacls.where{$_.Access.IdentityReference -like "*$($username)"}
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
    if ($NoDefaultGroups){
        Write-Verbose "Skipping adding default groups due to paramaters specified"
    }
    Else{
        #Set standard groups which aren't reported by AD memberof search.
        $usersgroups += New-object psobject -property @{"GroupName" = "Everyone"}
        $usersgroups += New-object psobject -property @{"GroupName" = "Authenticated Users"}
        $usersgroups += New-object psobject -property @{"GroupName" = "Domain Computers"}
        $usersgroups += New-object psobject -property @{"GroupName" = "BUILTIN\Users"}
    }
    #Begin filtering for directories affected by group membership.
    Foreach ($item in $Usersgroups) {
    $GroupPermissions = $foldersacls.where{$_.Access.IdentityReference -like "*$($item.GroupName)*"}
    $GroupPermissions | foreach-object {if ($_ -ne $null) {
        $evaluatedpermissions +=  New-object psobject -property @{
          "Path" = "$($_.Path -replace('Microsoft.PowerShell.Core\\FileSystem::',''))";
          "Identity" = "$((($_.Access).IdentityReference | ? {$_ -ilike "*$($item.GroupName)"})[0])";
          "Access" = "$((($_.Access) | ?{$_.IdentityReference -ilike "*$($item.GroupName)"}).FilesystemRights[0])";
            }
      }
    }
    }
    #Return full array of permissions.
    return $evaluatedpermissions
}
