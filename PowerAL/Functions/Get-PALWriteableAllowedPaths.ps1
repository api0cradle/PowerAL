function Get-PALWriteableAllowedPaths
{
<#
.SYNOPSIS

Lists paths that are allowed for execution that the current user can write to. 

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-PALWriteablePaths, Get-PALRules
Optional Dependencies: None

.DESCRIPTION

Retrieves the path from all the allowed AppLocker path rules and checks the paths against Get-PALWriteablePaths. 
It will also remove paths that are explicit denied.
Outputs: Name,Path

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
    [CmdletBinding()] Param ()
    Process
    {
        Try
        {
            #Array with paths
            $PathArray = @()

            $Rules = Get-PALRules -OutputRules Path -RuleActions Allow
            
            foreach($Ru in $Rules)
            {
                $InjectiblePaths = @()
                if($Ru.RulesList.path -eq "*")
                {
                    #Wildcard - Search everything!
                    $AllPaths = (Get-ChildItem C:\ -Directory -Recurse).FullName
                    $InjectiblePaths = Get-PALWriteablepaths -Path $AllPaths -ErrorAction SilentlyContinue
                }
                else
                {
                    foreach($R in $Ru.RulesList)
                    {
                        $Paths = Expand-PALPath -Path $R.path
                        foreach($pa in $Paths)
                        {
                            $InjectiblePaths += Get-PALWriteablepaths -Path $pa
                        }
                    }                
                }
            
                foreach($InjPath in $InjectiblePaths)
                {
                        $RuObject = New-Object PSObject
                        $RuObject | Add-Member NoteProperty Name $Ru.Name
                        $RuObject | Add-Member NoteProperty Path $InjPath
                        $PathArray += $RuObject
                }
            }

            #remove deny rules from the return array
            $denyrules = Get-PALRules -OutputRules Path -RuleActions Deny
            $FinaleArray = @()
            if($denyrules)
            {
                foreach($pat in $PathArray)
                {
                    # Deny rules present for section?
                    if($denyrules[($denyrules.Name.IndexOf($pat.Name))])
                    {
                        foreach($denr in $denyrules[($denyrules.Name.IndexOf($pat.Name))])
                        { #DLL, EXE, MSI...
                            
                            foreach($pa in $denr.ruleslist.path)
                            {
                                $diffe = $($pat.path)
                                if($pa -like "*$diffe*")
                                {
                                }
                                else
                                {
                                    #Not
                                    $DuObject = New-Object PSObject
                                    $DuObject | Add-Member NoteProperty Name $Denr.Name
                                    $DuObject | Add-Member NoteProperty Path $pat.path
                                    $FinaleArray += $DuObject
                                }
                            }
                        }
                    }
                    else
                    {
                        $FinaleArray += $pat
                    }
                }
                return $FinaleArray
            }
            else
            {
                #No deny rules - return patharray instead
                return $PathArray
            }
        }
        Catch
        {
            write-error $_
        }
        Finally{}
    }
}