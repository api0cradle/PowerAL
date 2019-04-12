function Get-PALPoshV2Installed
{
<#
.SYNOPSIS

Checks if PowerShell version 2 and .NET Framework 2 is installed or not. Use verbose for details.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Checks registry for key that indicates that PowerShell version 2 is still installed on system. 
If it is present, Powershell can be started with -version 2 to bypass constrained language.

.EXAMPLE

PS C:\> Get-PALPoshV2Installed

True

#>  

# Function Version: 1.00

    [CmdletBinding()] Param ()
    Process
    {
        try
        {
            if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727" -ErrorAction SilentlyContinue).install)
            {
                Write-Verbose ".NET Framework 2 present"
                if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1" -ErrorAction SilentlyContinue).install -eq 1)
                {
                    Write-Verbose "Posh v2 present"
                    return $true
                }
                else
                {
                    Write-Verbose "Posh v2 missing"
                    return $false
                }    
            }
            else
            {
                Write-Verbose ".NET Framework 2 missing"
                return $false
            }   
        }
        catch
        {
            write-error $_
        }
        finally{}
    }
}