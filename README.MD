# Folder Permission Enumerator
Gets all permissions either explicit or by group membership for a given user on the sub-folders for path specified even if it's a nested group which grants access.

Features:

+ Searches ACLS Matching username.
+ Searches ACLS Matching group membership including recursive/sub groups.

`Note: you need to run the PowerShell window as privileged user such as a domain admin.`

## How to use:

```PowerShell
Get-UserFolderPermissions -username bgates -FolderPath "E:\" -recurse -depth 1
```
### Parameters
`username`
    The username you wish to see the effective permissions for, either Domain\username format or just username.

`FolderPath`
    The folder you wish to get permissions from. Note it Searches the children of this item.

`recurse`
    Adding this switch will search the child directories as well.

`NoDefaultGroups`
    Using this switch will remove the groups users are a memberof by default eg. Everyone,Domain Computers,Authenticated Users and BUILTIN\Users

`depth`
    This parameter only works with recurse if not specified with recurse it will default to 0. Otherwise Will search the amount of sub-directories you specify.

The Results are returned in the following format:
```
      Path                                    Access                                  Identity
      ----                                    ------                                  --------
      E:\DCA Governance                       FullControl                             DOMAIN\bgates
      E:\IT                                   FullControl                             DOMAIN\Technology Management
      E:\Technology Management                Modify, Synchronize                     DOMAIN\Technology Management
      E:\Development                          ReadAndExecute, Synchronize             DOMAIN\IT Support
      E:\IT                                   FullControl                             DOMAIN\IT Support
```

This can then easily be exported to CSV via the export-csv cmdlet.

## Installation:
Download ZIP and extract contents to:
     %programfiles%\WindowsPowershell\modules\File-Permissions

Make the folder-file permissions if it doesn't already exist.
Finally import the module.

```PowerShell
    import-module File-Permissions
```

NOTE: This function is `only` designed to enumerate folder permissions and not files.
