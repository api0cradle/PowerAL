Function Expand-PALPath
{
<#
.SYNOPSIS

Converts path that contains AppLocker specific variables into to normal paths.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION
Takes path as input and normalizes it by changing AppLocker specific parameters into paths.
If variable that is sent into the function resolves to two paths (ex: System32/SysWOW64) the function will return both.
It also resolves paths containing ADS rules such as "%windir%\folder:*".

.EXAMPLE

PS C:\> Expand-PALPath -Path "%windir%\temp"

C:\Windows\temp

.EXAMPLE

PS C:\> Expand-PALPath -Path "%programfiles%"

C:\Program Files
C:\Program Files (x86)

.EXAMPLE

PS C:\> Expand-PALPath -Path "*"

C:

.EXAMPLE

PS C:\> Expand-PALPath -Path "%windir%\tasks:*"

C:\Windows\tasks:*
#>

# Function Version: 1.00

[CmdletBinding()] Param (
        [Parameter(ValueFromPipeline)]
		[string[]]
        $Path

    )
    Process
    {
        Try
        {
            $ReturnPaths = @()

            foreach($P in $Path)
            {
                $Temp = $null
                $TempX64 = $null

                if($P -eq "*")
                {
                    $Temp = $P -replace "\*",$env:SystemDrive
                }
                elseif($P -match "%PROGRAMFILES%")
                {
                        $Temp = $P -replace "%PROGRAMFILES%",$env:ProgramFiles
                        $TempX64 = $P -replace "%PROGRAMFILES%",${env:ProgramFiles(x86)}
                    }
                elseif($P -match "%windir%")
                {
                    $Temp = $P -replace "%windir%",$env:windir
                }
                elseif($P -match "%system32%")
                {
                    $Temp = $P -replace "%SYSTEM32%","c:\windows\system32"    
                    $TempX64 = $P -replace "%SYSTEM32%","c:\windows\syswow64"    
                }
                elseif($P -match "%OSDRIVE%")
                {
                    $Temp = $P -replace "%OSDRIVE%",$env:SystemDrive
                }
                else
                {
                    $Temp = ($P)
                }
                
                if($Temp -match ":\*")
                {
                }
                else
                {
                    $Temp = $Temp.TrimEnd("*")
                }
                
                $ReturnPaths += $Temp
                if($TempX64)
                {
                    if($TempX64 -match ":\*")
                    {
                    }
                    else
                    {
                        $TempX64 = $TempX64.TrimEnd("*")
                    }
                    $ReturnPaths += $TempX64
                }
                
                
            }
            return $ReturnPaths
        }
        Catch
        {
            write-error $_
        }
        Finally{}
    }
}