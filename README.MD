# Folder Permission Enumerator
Gets all permissions either explicit or by group membership for a given user on the sub-folders for path specified even if it's a nested group which grants access.

Features:

+ Searches ACLS Matching username.
+ Searches ACLS Matching group membership including recursive/sub groups.

How to use:

```PowerShell
Get-FilePermissions -username dbizsley -FolderPath "E:\
```
The Results are returned in the following format:
    Path                                    Access                                  Identity
    ----                                    ------                                  --------
    E:\DCA Governance                       FullControl                             LOWELL2\dbizsley_p
    E:\IT                                   FullControl                             LOWELL2\Technology Management
    E:\Technolgy Management                 Modify, Synchronize                     LOWELL2\Technology Management
    E:\Development                          ReadAndExecute, Synchronize             LOWELL2\IT Support
    E:\IT                                   FullControl                             LOWELL2\IT Support


This can then easily be exported to CSV via the export-csv cmdlet.

NOTE: This function is only designed to enumerate folder permissions and not files.
