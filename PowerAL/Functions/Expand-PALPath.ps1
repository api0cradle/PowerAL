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

#>
[CmdletBinding()] Param (
        [String]
        $Path

    )
    Process
    {
        Try
        {
            $ReturnPaths = @()
            $Temp = $null
            $TempX64 = $null

            if($Path -eq "*")
            {
                $Temp = $Path -replace "\*",$env:SystemDrive
            }
            elseif($Path -match "%PROGRAMFILES%")
            {
                    $Temp = $Path -replace "%PROGRAMFILES%",$env:ProgramFiles
                    $TempX64 = $Path -replace "%PROGRAMFILES%",${env:ProgramFiles(x86)}
                }
            elseif($Path -match "%windir%")
            {
                $Temp = $Path -replace "%windir%",$env:windir
            }
            elseif($Path -match "%system32%")
            {
                $Temp = $Path -replace "%SYSTEM32%","c:\windows\system32"    
                $TempX64 = $Path -replace "%SYSTEM32%","c:\windows\syswow64"    
            }
            elseif($Path -match "%OSDRIVE%")
            {
                $Temp = $Path -replace "%OSDRIVE%",$env:SystemDrive
            }
            else
            {
                $Temp = ($Path)
            }
            
            $Temp = $Temp.TrimEnd("*")
            
            $ReturnPaths += $Temp
            if($TempX64)
            {
                $TempX64 = $TempX64.TrimEnd("*")
                $ReturnPaths += $TempX64
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