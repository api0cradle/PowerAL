function Get-PALServiceStatus
{
<#
.SYNOPSIS

Returns the status on the Application Identity (AppIDSVC) service from the local machine.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-Process
Optional Dependencies: None

.DESCRIPTION

Checks the Application Identity service status using the get-service cmdlet.
Outputs: Name,Status,StartType

.EXAMPLE

PS C:\> Get-PALServiceStatus

Name      Status StartType
----      ------ ---------
AppIDSvc Stopped    Manual
#>    

# Function Version: 0.90

	[CmdletBinding()] Param ()
    Process
    {
        Try
        {
		    $Out = Get-Service -Name AppIDSvc
            return $Out | Select-Object Name,Status,StartType
        }
        Catch
        {
            Write-Error $_
        }
        Finally{}
    }
}