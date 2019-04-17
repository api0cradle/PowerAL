function Get-PALMissingAllowedPaths
{
<#
.SYNOPSIS

Lists paths that are missing on the filesystem that is allowed for execution. 

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-PALWriteablePaths, Get-PALRules
Optional Dependencies: None

.DESCRIPTION

Retrieves the path from all the allowed AppLocker path rules and checks if the path is missing or not.  
It will list out the paths it cannot find and these paths can likely be exploited if the user can create the folders. 
Currently it does not resolve * in paths so it may contain false positives. 
Outputs: Name,Path

.PARAMETER RuleSection
What sort of section you want the rules for. Default is "All
Can be "All","Dll","Exe","Script","Appx","Msi". This Parameter is passed to the Get-PALRules.


.EXAMPLE

PS C:\> Get-PALMissingAllowedPaths

Name   Path                                                                                                                      
----   ----                                                                                                                      
Exe    C:\WINPROG\FARMS\FARM.EXE                                                                                                   
Exe    C:\USERS\*\APPDATA\LOCAL\CITRIX\SELFSERVICE\PROGRAM FILES\SELFSERVICEPLUGIN.EXE                                           
Exe    C:\HOMEMADE\CORE.EXE                                                                                                         
Script C:\HOMEMADE\START.BAT

#>

# Function Version: 0.80

    [CmdletBinding()] Param (
        [ValidateSet("All","Appx","Dll","Exe","Msi","Script")]
        [String]
        $RuleSection = "All"
        
    )
    Process
    {
        Try
        {
            $PathArray = @()
            $FinaleArray = @()
            
            $AllAppLockerRules = Get-PALRules -OutputRules Path -RuleActions Allow -RuleSection $RuleSection
            
            #Loop through each section DLL,EXE++
            foreach($SectionRules in $AllAppLockerRules)
            {
                # Fresh empty array for each section
                $MissingPathsArray = @()
                
                #Loop through each rule in the section
                foreach($Rule in $SectionRules.RulesList)
                {
                    # Expand the AppLocker path variables into real paths
                    $Paths = Expand-PALPath -Path $Rule.RulePath
                    foreach($Path in $Paths)
                    {
                        
                        if($Path -match "\.\w{2,4}$")
                        #File
                        {
                            if($path -match "^C:\\") #Only check local paths
                            {
                                if(Test-Path -path (Join-Path -Path (($path -split "\\")[0]) -ChildPath (($path -split "\\")[1])))
                                {
                                    
                                    if(test-path -Path $path -ErrorAction SilentlyContinue)
                                    {
                                        #all good, nothing todo here
                                    }
                                    else
                                    {
                                        #File not found, exploitable
                                        Write-Verbose "File not found, can be exploited"
                                        $MissingPathsArray += $path
                                    }

                                }
                                else
                                {
                                    write-verbose "Missing parent folder to $path - Exploit it"
                                    $MissingPathsArray += $path
                                }
                            }
                        }
                        else
                        #Folder
                        {
                            #Check if folder exists...assume it can be created if it does not exist under C:\
                            if($path -match "^C:\\") #Only check local paths
                            {
                                if(!(Test-Path -path (Join-Path -Path (($path -split "\\")[0]) -ChildPath (($path -split "\\")[1]))))
                                {
                                    write-verbose "Allow path rule is pointing to a missing parent folder: $path"
                                    $MissingPathsArray += $Path 
                                }
                            }
                        }
                    }
                }                

                foreach($MissingPath in $MissingPathsArray)
                {
                        $RuObject = New-Object PSObject
                        $RuObject | Add-Member NoteProperty Name $SectionRules.Name
                        $RuObject | Add-Member NoteProperty Path $MissingPath
                        $PathArray += $RuObject
                }
            
            }

            # Remove deny rules from the PathArray array
            $DenyRules = Get-PALRules -OutputRules Path -RuleActions Deny -RuleSection $RuleSection
            
            # Check if Deny rules are present
            if($DenyRules)
            {
                foreach($PathObj in $PathArray)
                {
                    $Add = $true
                    # See if Path we are checking has the correct section (DLL,Script). -1 eq not.
                    if(!($DenyRules.Name.IndexOf($($PathObj.Name))) -eq "-1")
                    {
                        foreach($DRP in $DenyRules[($DenyRules.Name.IndexOf($($PathObj.Name)))].ruleslist.path)
                        {
                            $diff = $($PathObj.path)
                            if($(Join-Path -Path $($DRP.ToLower()) -ChildPath $null) -like "$(Join-Path -Path $($diff.ToLower()) -childpath $null)*")
                            {
                                #Dont add, because it is a deny rule
                                $Add = $false
                            }
                        }
                    }
                    
                    if($Add)
                    {
                        $FinaleArray += $PathObj
                    }
                }
                return $FinaleArray
            }
            else
            {
                #No deny rules - return patharray instead
                if($PathArray)
                {
                    return $PathArray
                }
                else
                {
                    Write-Verbose "No paths found - returning null"
                    return $null
                }
            }
        }
        Catch
        {
            write-error $_
        }
        Finally{}
    }
}