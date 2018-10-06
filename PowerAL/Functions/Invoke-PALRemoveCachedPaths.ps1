Function Invoke-PALRemoveCachedPaths
{
<#
.SYNOPSIS

Function used to remove log files that are saved under %TEMP%. These files are generated with Get-PALwriteablepaths to prevent rescanning of ACL on every run.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION
Removes all PAL.*.log files under %TEMP%. These files contains the writeable paths for the user that was used to run the get-PALwriteablepaths

.EXAMPLE

PS C:\> Invoke-PALRemoveCachedPaths -Verbose

VERBOSE: Deleting file: C:\Users\NORMAL~1\AppData\Local\Temp\PAL-C-Program Files (x86).log
VERBOSE: Deleting file: C:\Users\NORMAL~1\AppData\Local\Temp\PAL-C-Program Files.log
VERBOSE: Deleting file: C:\Users\NORMAL~1\AppData\Local\Temp\PAL-C-windows-system32.log
VERBOSE: Cached is cleaned
True

#>  
    [CmdletBinding()] Param ()
    Process
    {
        try
        {
            $FilesToDelete = get-item -path ("$env:temp\PAL-*.log")
            foreach($File in $FilesToDelete)
            {
                write-verbose "Deleting file: $File"
                Remove-Item $File
            }
            Write-Verbose "Cached is cleaned"
            return $true
        }
        catch
        {
            $ErrorMessage = $_
            Write-Error $ErrorMessage
        }
        finally{}
    }
}