function Get-PALPathStatus
{
<#
.SYNOPSIS

Checks given path/file if it is allowed or denied by the AppLocker rules.
When a folder path is checked it will return allow if the folder path is allowed in either EXE,DLL,MSI,SCRIPT,APPX.
When a file path is checked it will only check the correct section. EX: file.exe is only checked against EXE path rules and will only return deny or allow.
The function does not handle exceptions yet.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-PALRules,Get-PALRulesNative
Optional Dependencies: None

.DESCRIPTION

Gets all the AppLocker path rules and enumerates if the supplied path or file is allowed or denied. 
Returns Allow or Deny.

.PARAMETER Path

The Path you want to verify. Can either be a path to a folder or file. 
Parameter is mandatory.
	
.PARAMETER SID

The SID you want to get the rules for. 
Default is S-1-1-0. (Admin rules will not show up default as a consequence of that.)
If you want all you can supply *
List of well-known SIDs can be found here: https://support.microsoft.com/en-au/help/243330/well-known-security-identifiers-in-windows-operating-systems 

.PARAMETER OfflineXML

Path to OfflineXML that you have exported. 
This makes the function parse that file instead of the current AppLocker policy on the machine this script is running on.

.EXAMPLE
Tests status of cmd.exe. This is allowed in this example.

PS C:\> Get-PALPathStatus -Path "C:\windows\system32\cmd.exe"

Allow

.EXAMPLE
Tests if c:\blockedpath is blocked or not by the rules. The path is a blocked path in this example.

PS C:\> Get-PALPathStatus -Path c:\windows\tracing\

Name   Action
----   ------
Exe    Deny  
Msi    Deny  
Script Allow

.EXAMPLE
Test if c:\temp2\evil.exe is allowed or not, tested against an offline XML file.

PS C:\> Get-PALPathStatus -Path "c:\temp2\evil.exe" -OfflineXML "C:\folder\Export.xml"

Allow

.EXAMPLE
Test if c:\block is allowed for administrators.

PS C:\> Get-PALPathStatus -Path "C:\block" -SID "S-1-5-32-544"

Deny

#>    

# Function Version: 0.95

    [CmdletBinding()] Param (
        [Parameter(Mandatory=$true)]
        [String]
        $Path,

        [String]
        #S-1-1-0 = Everyone
        $SID = "S-1-1-0",

        [String]
        $OfflineXML
    )
    Process
    {
        Try
        {
            #Check if path or file
            #Uses simple check if supplied string ends with ".{2-4chars}"
            if($path -match "\.\w{2,4}$" -and $path -notmatch "\.\d{2,4}$")
            {
                Write-Verbose "Specified file"
                $Type = "File"
                
                #Find type of file relevant to AppLocker
                $Executable = @(".exe",".com")
                $WinInstaller = @(".msi",".mst",".msp")
                $Script = @(".ps1",".bat",".cmd",".vbs",".js") #More types?
                $DLL = @(".dll",".ocx")
                $Package = @(".appx")
                
                $FileExtension = ".$($path.Split(".")[1])"

                if($Executable -contains $FileExtension.ToLower())
                {
                    $FileType = "Exe"
                }
                elseif($WinInstaller -contains $FileExtension.ToLower())
                {
                    $FileType = "Msi"
                }
                elseif($Script -contains $FileExtension.ToLower())
                {
                    $FileType = "Script"
                }
                elseif($Dll -contains $FileExtension.ToLower())
                {
                    $FileType = "Dll"
                }
                elseif($Package -contains $FileExtension.ToLower())
                {
                    $FileType = "Appx"
                }
                else
                {
                    Write-error "Unknown file format specified - quitting"
                    break
                }
            }
            else
            {
                Write-Verbose "Specified folder"
                $Type = "Folder"
                if(!($path.Substring(($path.Length-1)) -eq "\"))
                {
                    $path = Join-Path $Path -ChildPath ""
                }
            }

            if($OfflineXML)
            {
                Write-Verbose "Parsing rules from XML"
                $PathRules = Get-PALRulesNative -OutputRules Path -RuleActions All -OfflineXML $OfflineXML -SID $sid
            }
            else
            {
                $DenyRules = Get-PALRules -OutputRules Path -RuleActions Deny -SID $SID -ExceptionsAsDeny
            }

            ## File check
            if($Type -eq "File")
            {
                #First check if path is allowed, then check if it is denied
                $AllowRules = Get-PALRules -OutputRules Path -RuleActions Allow -RuleSection $FileType -SID $SID
                #$Allowed = $null
                foreach($AllowRule in $AllowRules.RulesList)
                {
                    if($path -like "*$($AllowRule.Path)*")
                    {
                        $Allowed = $true
                        break
                    }
                }

                # Path is allowed, now check all deny rules and exceptions if it is denied
                if($Allowed)
                {
                    foreach($DenyRule in $($DenyRules | where-object{$_.name -eq $FileType}).RulesList)
                    {
                        if($path -like "*$($DenyRule.path)*")
                        {
                            return "Deny"
                            break
                        }
                    }
                    # Not explicit denied - Returing allowed
                    return "Allow"
                }
                else
                {
                    return "Deny"
                }
            }

            ## Folder check
            if($Type -eq "Folder")
            {
                $PathRuleReturnStatus = @()
                $AllowRules = Get-PALRules -OutputRules Path -RuleActions Allow -RuleSection All -SID $SID
                foreach($Section in $AllowRules)
                {
                    $Denied = $false
                    $Allowed = $false

                    foreach($AllowRule in $Section.RulesList)
                    {

                        # Dont process file paths
                        if(!($($AllowRule.path) -match "\.\w{2,4}$"))
                        {
                            if($Path -like "*$($AllowRule.Path)*")
                            {
                                $Allowed = $true
                            }
                        }
                    }
                
                    if($Allowed)
                    {
                        foreach($DenyRule in $($DenyRules | where-object{$_.name -eq $($Section.Name)}).RulesList)
                        {
                            if($path -like "*$($DenyRule.path)*")
                            {
                                $PathRuleReturnStatus += $path | select-object @{Name = 'Name'; Expression = {$AllowRule.ParentName}}, @{Name = 'Action'; Expression = {"Deny"}}
                                $Denied = $true
                                break
                            }
                        }
                        # Not explicit denied - Returning allowed
                        if(!($Denied))
                        {
                            $PathRuleReturnStatus += $path | select-object @{Name = 'Name'; Expression = {$AllowRule.ParentName}}, @{Name = 'Action'; Expression = {"Allow"}}
                        }
                    }
                    else
                    {
                        $PathRuleReturnStatus += $path | select-object @{Name = 'Name'; Expression = {$AllowRule.ParentName}}, @{Name = 'Action'; Expression = {"Deny"}}
                        $Denied = $true
                    }
                }
                return $PathRuleReturnStatus
            }
        }
        Catch
        {
            Write-error $_
        }
        Finally{}
    }
}