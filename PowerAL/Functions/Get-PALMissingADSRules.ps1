function Get-PALMissingADSRules
{
<#
.SYNOPSIS
Lists out missing ADS blocking rules for userwriteable allowed paths

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-PALRules, Get-PALWriteablePaths
Optional Dependencies: None

.DESCRIPTION

Lists out missing ADS blocking rules for userwriteable allowed paths

.PARAMETER RuleSection

What sort of section you want the rules for. Default is "All
Can be "All","Dll","Exe","Script","Appx","Msi". This Parameter is passed to the Get-PALRules.

.PARAMETER SID

The SID you want to get the rules for. 
Default is S-1-1-0. (Admin rules will not show up default as a consequence of that.)
If you want all you can supply *
List of well-known SIDs can be found here: https://support.microsoft.com/en-au/help/243330/well-known-security-identifiers-in-windows-operating-systems 

.EXAMPLE

#>

# Function Version: 0.95

    [CmdletBinding()] Param (
        [ValidateSet("All","Appx","Dll","Exe","Msi","Script")]
        [String]
        $RuleSection = "All",
                
        [String]
        #S-1-1-0 = Everyone
        $SID = "S-1-1-0"
        
    )
    Process
    {
        Try
        {

            $AllPaths = "C:\"
            if(!($WriteablePaths))
            {
                    Get-PALWriteablepaths -Path $AllPaths -ErrorAction SilentlyContinue
            }
            
            $DenyPathRules = Get-PALRules -OutputRules Path -RuleActions Allow -RuleSection $RuleSection -SID $SID -ExceptionsAsDeny

            
            $ADSCompareArray1 = @()
            $ADSCompareArray2 = @()
            
            $PathRuleReturnStatus += $path | select-object @{Name = 'Name'; Expression = {$AllowRule.ParentName}}, @{Name = 'Action'; Expression = {"Deny"}}
            
            foreach($Section in $DenyPathRules)
            {
                foreach($CompRule in $Section.RulesList)
                {
                    if($CompRule.RulePath -match "\\\*$" -and $CompRule.RulePath -notmatch "^\\\\")
                    {
                        if($($CompRule.path).count -gt 1)
                        {
                            foreach($Path in $CompRule.path)
                            {
                                $ADSCompareArray1 += $Path | Select-Object @{Name = 'Name'; Expression = {$CompRule.ParentName}}, @{Name = 'Path'; Expression = {$Path -Replace "\\$",":*"}}, @{Name = 'RealPath'; Expression = {$Path -replace "\\$",""}}
                            }
                        }
                        else
                        {
                            $ADSCompareArray1 += $CompRule | Select-Object @{Name = 'Name'; Expression = {$CompRule.ParentName}}, @{Name = 'Path'; Expression = {$CompRule.path -Replace "\\$",":*"}}, @{Name = 'RealPath'; Expression = {$CompRule.Path -replace "\\$",""}}
                        }
                    }

                    if($CompRule.RulePath -match ":\*$")
                    {
                        if($($CompRule.path).count -gt 1)
                        {
                            foreach($Path in $CompRule.path)
                            {
                                $ADSCompareArray2 += $Path | Select-Object @{Name = 'Name'; Expression = {$CompRule.ParentName}}, @{Name = 'Path'; Expression = {$Path -Replace "\\$",":*"}}
                            }
                        }
                        else
                        {
                            $ADSCompareArray2 += $CompRule | Select-Object @{Name = 'Name'; Expression = {$CompRule.ParentName}}, @{Name = 'Path'; Expression = {$CompRule.path}}
                        }
                    }
                }
            }

            $TempArray = $ADSCompareArray1 | Where-Object {$_.path -notin $ADSCompareArray2.path}
                       
            $Out = $TempArray | Where-Object {$_.RealPath -in $writeablepaths}
            return $Out | Sort-Object -Property path,name -Unique | Sort-Object -Property name | select Name,Path
        }
        Catch
        {
            write-error $_
        }
        Finally{}
    }
}