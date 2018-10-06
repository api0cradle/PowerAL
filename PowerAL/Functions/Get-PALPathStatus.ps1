function Get-PALPathStatus
{
<#
.SYNOPSIS

Checks given path/file if it is allowed or denied by the AppLocker rules.
When a folder path is checked it will return allow if the folder path is allowed in either EXE,DLL,MSI,SCRIPT,APPX.
When a file path is checked it will only check the correct section. EX: file.exe is only checked against EXE path rules.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-PALRules
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
Tests status of NETFXSBS10.exe. This is blocked in this example.

PS C:\> Get-PALPathStatus -Path "C:\windows\system32\cmd.exe"

Allow

.EXAMPLE
Tests if c:\temp is blocked or not by the rules. c:\temp is not a blocked path in this example.

PS C:\> Get-PALPathStatus -Path "C:\blockedpath"

Deny

.EXAMPLE
Test if c:\temp2\evil.exe is allowed or not, tested against an offline XML file.

PS C:\> Get-PALPathStatus -Path "c:\temp2\evil.exe" -OfflineXML "C:\folder\Export.xml"

Allow

.EXAMPLE
Test if c:\block is allowed for administrators.

PS C:\> Get-PALPathStatus -Path "C:\block" -SID "S-1-5-32-544"

Deny

#>    
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
            if($path -match "\.\w{2,4}$")
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
                $PathRules = Get-PALRules -OutputRules Path -RuleActions All -OfflineXML $OfflineXML -SID $sid
            }
            else
            {
                $PathRules = Get-PALRules -OutputRules Path -RuleActions All -SID $SID
            }

		    $Status = ""

            if($PathRules)
            {
                $Paths = @()
                $Exceptions = @()
                
                foreach($Pr in $PathRules)
                {
                    $Parent = $Pr.Name
                    
                    foreach($P in $Pr.RulesList)
                    {
                        #Exceptions
                        if($P.PathExceptions)
                        {
                            write-verbose "Exceptions present"
                            foreach($ex in $P.PathExceptions)
                            {
                                if($SID -eq $P.sid -or $SID -eq "*")
                                {
                                    #SID match - Create object
                                    #$InjectiblePaths += Get-PALWriteablepaths -Path $pa
                                    $TmpExceptionObject = New-Object psobject

                                    #The path is file
                                    if($ex -match "\.\w{2,4}$" -or $ExTemp -eq "*.*")
                                    {
                                        $TmpExceptionObject | Add-Member NoteProperty Path $ex
                                        $TmpExceptionObject | Add-Member NoteProperty Type "File"
                                    }
                                    else
                                    {
                                        #Folder
                                        $TmpExceptionObject | Add-Member NoteProperty Path (join-path (split-path $ex) -ChildPath "")
                                        $TmpExceptionObject | Add-Member NoteProperty Type "Folder"
                                    }
                                    $TmpExceptionObject | Add-Member NoteProperty Action "Deny"
                                    $TmpExceptionObject | Add-Member NoteProperty Name $Parent
                                    $TmpExceptionObject | Add-Member NoteProperty SID $p.sid

                                    #Add exception object to exception array
                                    $Exceptions += $TmpExceptionObject
                                }
                            }
                        }

                        # Rules
                        if($SID -eq $P.sid -or $SID -eq "*")
                        {
                            $TmpPathObject = New-Object psobject

                            #File
                            if($P -match "\.\w{2,4}$" -or $Temp -eq "*.*")
                            {
                                $TmpPathObject | Add-Member NoteProperty Path $P.Path
                                $TmpPathObject | Add-Member NoteProperty Type "File"
                            }
                            else
                            {
                                #Folder
                                #$TmpPathObject | Add-Member NoteProperty Path (join-path (split-path $pa) -ChildPath "")
                                $TmpPathObject | Add-Member NoteProperty Path $P.Path
                                $TmpPathObject | Add-Member NoteProperty Type "Folder"
                            }
                        
                            $TmpPathObject | Add-Member NoteProperty Action $P.Action
                            $TmpPathObject | Add-Member NoteProperty Name $Parent
                            $TmpPathObject | Add-Member NoteProperty SID $P.sid
                            
                            # Add path object to path array
                            $Paths += $TmpPathObject
                        }
                    }
                }            

                $ReturnArray = @()

                #Exceptions / Deny
                foreach($Except in $Exceptions)
                {
                    if($Except.Type -eq "File")
                    {
                        if($Except.Name -eq $FileType)
                        {
                            if($Path.ToLower().Contains($Except.path.ToLower()))
                            {
                                $Status = "Deny"
                                Write-Verbose "Denied by Exception in rule: $Except"
                                return $Status
                            }
                        }
                    }
                    
                    if($Except.Type -eq "Folder")
                    {
                        if($Type -eq "File")
                        {
                            if($Except.name -eq $FileType)
                            {
                                if($Path.ToLower().Contains($Except.path.ToLower()))
                                {
                                    $Status = "Deny"
                                    Write-Verbose "Denied by Exception in rule: $Except"
                                    return $Status
                                }
                            }
                        }
                        else
                        {
                            if($Path.ToLower().Contains($Except.path.ToLower()))
                            {
                                # MATCH PATH
                                $Status = "Deny"
                                Write-Verbose "Denied by Exception in rule: $Except"
                                return $Status
                            }
                        }
                    }
                }
                
                foreach($Pth in $Paths)
                {
                    if($Pth.Type -eq "File")
                    {
                        if($Pth.Name -eq $FileType)
                        {
                            if($Path.ToLower().Contains($Pth.path.ToLower()))
                            {
                                $Status = $Pth.Action
                                if($Pth.Action -eq "Deny")
                                {
                                    Write-Verbose "Explicit denied by Path rule: $Pth"
                                    return $Status
                                }
                            }
                        }
                    }
                    
                    if($Pth.Type -eq "Folder")
                    {
                        if($Type -eq "File")
                        {
                            if($pth.name -eq $FileType)
                            {
                                if($Path.ToLower().Contains($Pth.path.ToLower()))
                                {
                                    $ReturnArray += $pth
                                    Write-Verbose "Allowed in $($pth.name)"
                                    $Status = $Pth.Action
                                    if($Pth.Action -eq "Deny")
                                    {
                                        Write-Verbose "Explicit denied by Path rule: $Pth"
                                        return $Status
                                    }
                                }
                            }
                        }
                        else
                        {
                            if($Path.ToLower().Contains($Pth.path.ToLower()))
                            {
                                # MATCH PATH
                                $ReturnArray += $pth
                                Write-Verbose "Allowed in $($pth.name)"
                                $Status = $Pth.Action
                                if($Pth.Action -eq "Deny")
                                {
                                    Write-Verbose "Explicit denied by Path rule: $Pth"
                                    return $Status
                                }
                            }
                        }
                    }
                }
                if($Status)
                {
                    return $ReturnArray
                }
                else
                {
                    return "Deny"
                }
            }
            else
            {
                Write-Error "No rules present"
                break
            }
            return $ReturnArray
        }
        Catch
        {
            Write-error $_
        }
        Finally{}
    }
}