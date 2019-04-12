function Get-PALRuleSectionStatus
{
<#
.SYNOPSIS

Returns current status on the local machine of the AppLocker rule sections.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Will check against local registry to figure out what status the different AppLocker rule sections is at for the applied AppLocker policy.
Status can be either "Not Configured", "Enforced" or "Auditing"

.EXAMPLE

PS C:\> Get-PALRuleSectionStatus

Name   Status  
----   ------  
Appx   Enforced
Dll    Enforced
Exe    Enforced
Msi    Auditing
Script Not configured
#>

# Function Version: 1.0

    [CmdletBinding()] Param ()
    Process
    {
        Try
        {
            $OutArray = @()

		    $RuleTypes = @("Appx","Dll","Exe","Msi","Script")
		    foreach($RuleType in $RuleTypes)
            {
                $Out = New-Object PSObject
                $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$RuleType"

		    	# EnforcementMode missing = Not configured
		    	# EnforcementMode 0 = Audit mode
		    	# EnforcementMode 1 = Enforced
                $RuleStatus = Get-ItemProperty -Path $RegPath -Name "EnforcementMode" -ErrorAction SilentlyContinue
                If (($RuleStatus -ne $null) -and ($RuleStatus.Length -ne 0)) {
                    $EnforcementMode = (Get-ItemProperty -path $RegPath -Name "EnforcementMode").EnforcementMode
                        
                    If($EnforcementMode -eq "1")
                    {
                        $Result = "Enforced"
                    }
                    elseif($EnforcementMode -eq "0")
                    {
                        $Result = "Audit"
                    }    
                }
                else
                {
                    $Result = "NotConfigured"
                }

		    	$Out | Add-Member Noteproperty -name "Name" $RuleType
		    	$Out | Add-Member Noteproperty -name "Status" $Result
                $OutArray += $Out
		    }
		    return $OutArray
        }
        Catch
        {
            write-error $_
        }
        Finally{}
    }
}