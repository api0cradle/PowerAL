function Get-PALWriteableAllowedPaths
{
<#
.SYNOPSIS

Lists paths that are allowed for execution that the current user can write to or create. Currently does not handle Exceptions that are defined in rules, only explicit deny rules.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-PALWriteablePaths, Get-PALRules
Optional Dependencies: None

.DESCRIPTION

Retrieves the path from all the allowed AppLocker path rules and checks the paths against Get-PALWriteablePaths. 
It will also remove paths that are explicit denied.
Outputs: Name,Path

.PARAMETER Rerun
When this switch is used it will rerun the Get-PALWriteablePaths and give fresh results stored 
in the Global variable WriteablePaths

.PARAMETER RuleSection
What sort of section you want the rules for. Default is "All
Can be "All","Dll","Exe","Script","Appx","Msi". This Parameter is passed to the Get-PALRules.


.EXAMPLE

PS C:\> Get-PALWriteableAllowedPaths

		Name   Path                                                
----   ----                                                
Exe    C:\Windows\Tasks                                    
Exe    C:\Windows\Temp                                     
Exe    C:\Windows\tracing                                  
Exe    C:\Windows\Registration\CRMLog                      
Exe    C:\Windows\System32\FxsTmp                          
Exe    C:\Windows\System32\Tasks                           
Exe    C:\Windows\System32\com\dmp                         
Exe    C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
Exe    C:\Windows\System32\spool\PRINTERS                  
Exe    C:\Windows\System32\spool\SERVERS                   
Exe    C:\Windows\System32\spool\drivers\color             
Exe    C:\Windows\SysWOW64\FxsTmp                          
Exe    C:\Windows\SysWOW64\Tasks                           
Exe    C:\Windows\SysWOW64\com\dmp                         
Msi    C:\Windows\Tasks                                    
Msi    C:\Windows\Temp                                     
Msi    C:\Windows\tracing                                  
Msi    C:\Windows\Registration\CRMLog                      
Msi    C:\Windows\System32\FxsTmp                          
Msi    C:\Windows\System32\Tasks                           
Msi    C:\Windows\System32\com\dmp                         
Msi    C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
Msi    C:\Windows\System32\spool\PRINTERS                  
Msi    C:\Windows\System32\spool\SERVERS                   
Msi    C:\Windows\System32\spool\drivers\color             
Msi    C:\Windows\SysWOW64\FxsTmp                          
Msi    C:\Windows\SysWOW64\Tasks                           
Msi    C:\Windows\SysWOW64\com\dmp                         
Script C:\Windows\Tasks                                    
Script C:\Windows\Temp                                     
Script C:\Windows\tracing                                  
Script C:\Windows\Registration\CRMLog                      
Script C:\Windows\System32\FxsTmp                          
Script C:\Windows\System32\Tasks                           
Script C:\Windows\System32\com\dmp                         
Script C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
Script C:\Windows\System32\spool\PRINTERS                  
Script C:\Windows\System32\spool\SERVERS                   
Script C:\Windows\System32\spool\drivers\color             
Script C:\Windows\SysWOW64\FxsTmp                          
Script C:\Windows\SysWOW64\Tasks                           
Script C:\Windows\SysWOW64\com\dmp  
#>

# Function Version: 0.90

    [CmdletBinding()] Param (
        [Switch]
        $Rerun,

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
            
            $AllPaths = "C:\"
            # Check if global variable exist. If it does, WriteablePaths has been runned.
            if(!($WriteablePaths))
            {
                Get-PALWriteablepaths -Path $AllPaths -ErrorAction SilentlyContinue
            }

            if($Rerun)
            {
                Get-PALWriteablepaths -Path $AllPaths -Rerun -ErrorAction SilentlyContinue
            }

            

            #Loop through each section DLL,EXE++
            foreach($SectionRules in $AllAppLockerRules)
            {
                # Fresh empty array for each section
                $AllowedPathsArray = @()
                
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
                        }
                        else
                        #Folder
                        {
                            #Loop through all writeable paths to see if there is a match. Add to list if there is.
                            #Compare using tolower and normalized paths
                            foreach($Wpath in $WriteablePaths)
                            {
                                if($(Join-Path -Path $($Wpath.ToLower()) -ChildPath $null) -like "$(Join-Path -Path $($Path.ToLower()) -ChildPath $null)*")
                                {
                                    # Only add if it is not in the array already
                                    if($AllowedPathsArray -notcontains $Wpath)
                                    {
                                        $AllowedPathsArray += $Wpath
                                    }
                                }
                            }        
                        }
                    }
                }                

                foreach($AllowedPath in $AllowedPathsArray)
                {
                        $RuObject = New-Object PSObject
                        $RuObject | Add-Member NoteProperty Name $SectionRules.Name
                        $RuObject | Add-Member NoteProperty Path $AllowedPath
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
                    Write-Verbose "No possible paths found - returning null"
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