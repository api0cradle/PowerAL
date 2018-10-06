function Get-PALRulesStatus
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

PS C:\> Get-PALRulesStatus

Name   Status  
----   ------  
Appx   Enforced
Dll    Enforced
Exe    Enforced
Msi    Auditing
Script Not configured
#>
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
		    	$RuleStatus = Get-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$RuleType"

		    	# EnforcementMode missing = Not configured
		    	# EnforcementMode 0 = Audit mode
		    	# EnforcementMode 1 = Enforced
		    	If($RuleStatus -eq $null)
                {
		    	    $Result = "Not configured"
		    	}

		    	If($RuleStatus.EnforcementMode -eq 1)
                {
		    		$Result = "Enforced"
		    	}

		    	If($RuleStatus.EnforcementMode -eq 0)
                {
		    		$Result = "Auditing"
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