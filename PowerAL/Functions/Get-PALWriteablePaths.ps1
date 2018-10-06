function Get-PALWriteablepaths
{
<#
.SYNOPSIS

Lists paths that are writeable for the current user.
This function can be noisy since it creates a temporary file in every directory to verify write access.
It will only test for folders and will not list files with modify rights that are present on the system.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: ICACLS.exe

.DESCRIPTION

Checks the path and all subdirs for writeable access by creating a temporary file to the dir and deleting it.
Outputs: Path

.EXAMPLE

PS C:\> Get-PALWriteablepaths -Path "C:\windows"

C:\windows\Tasks
C:\windows\Temp
C:\windows\tracing
C:\windows\Registration\CRMLog
C:\windows\System32\FxsTmp
C:\windows\System32\Tasks
C:\windows\System32\com\dmp
C:\windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\windows\System32\spool\PRINTERS
C:\windows\System32\spool\SERVERS
C:\windows\System32\spool\drivers\color
C:\windows\SysWOW64\FxsTmp
C:\windows\SysWOW64\Tasks
C:\windows\SysWOW64\com\dmp
#>  
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [String]
        $Path,

        [Switch]
        $Rerun
    )
    begin
    {
        #Check if path is checked before. stored in local folder where script is executed
        #turn path to filename
        $filename = $Path.Replace(":\","-")
        $filename = $filename.Replace("\","-")
        $filename = $filename.TrimEnd("-")
        $filename = "$env:temp\PAL-$filename.log"
        if(Test-Path -Path $filename)
        {
            if($Rerun)
            {
                Remove-Item -Path $filename
                [bool]$UseFile = $false
            }
            else
            {
                [bool]$UseFile = $true
                Write-Verbose "Path checked before, read result from file instead of rerun"
            }
        }
    }

    Process
    {
        if($UseFile)
        {
            $writeablepaths = Get-Content $filename
        }
        else
        {
            [string]$tempname = "$(Get-Random).txt"
            write-debug $tempname
            $writeablepaths = @()

            $AllPaths = (Get-ChildItem $($path) -directory -Recurse -ErrorAction SilentlyContinue).FullName

            $ProgressTotal = $AllPaths.count
            $i = 0
            [int]$interval = $ProgressTotal * 0.1
            foreach($pth in $AllPaths){
                #write-verbose "-- $pth\$tempname --"
                try{
                    # Update progress less often
                    if ($i % $interval -eq 0) 
                    {
                      Write-Progress -Activity 'Checking for writeable folders' -Status "Checking subfolders for $path - $i of $ProgressTotal" -PercentComplete (($i/$ProgressTotal)*100)
                    }
                    $i++

                    New-Item -Path $pth -Name $tempname -ItemType File -ErrorAction Stop | Out-Null
                    #New-Item -Path $pth -Name $tempname -ItemType Directory -ErrorAction Stop | Out-Null
                    Write-verbose "Created file: $pth\$tempname"
                    $writeablepaths += $pth
                    
                }
                catch{
                    #Write-verbose "Not able to create file: $pth\$tempname"
                    $ErrorMessage = $_
                    Write-Debug $ErrorMessage
                }
                Finally{

                }

                #Cleanup - delete the temporary file
                Remove-Item -Path $pth"\"$tempname -ErrorAction SilentlyContinue | Out-Null
                if(test-path $pth"\"$tempname){
                    Write-Verbose "File not deleted: $pth\$tempname"
                    Write-verbose "Adjusting ACLs on $pth\$tempname"
                    icacls $pth"\"$tempname /grant "BUILTIN\Users:(F)" | Out-Null
                    Write-Verbose "Trying to delete again: $path\$tempname"
                    Remove-Item -Path $pth"\"$tempname -ErrorAction SilentlyContinue | Out-Null
                    if(test-path $pth"\"$tempname)
                    {
                        Write-Error "File not deleted: $pth\$tempname"
                    }
                    else
                    {
                        Write-Verbose "Successfully deleted: $pth\$tempname"
                    }
                }
                else
                {
                }
            }
        }
        if(!($UseFile))
        {
            $writeablepaths | Out-File $filename
        }
        
        return $writeablepaths
    }
}
