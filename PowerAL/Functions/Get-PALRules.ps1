function Get-PALRules
{
<#
.SYNOPSIS

The function Get-PALRules returns the AppLocker rules as an object that is current on the local machine from the registry.
AppLocker rules are written to registry.
 

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Expand-PALPaths
Optional Dependencies: None

.DESCRIPTION

Will check against local registry under HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\ to find the AppLocker rules. 
Rules are stored as XML in the registry, the function converts it to an object before it returns it. The function also supports to export the rules to an xml 
that can be extracted and viewed offline

.PARAMETER OutputRules

The type of rules you want to get. Default is "All".
Can be "All","Path","Publisher","Hash"

.PARAMETER RuleActions

What sort of rules you want. Default is "All"
Can be "All","Allow","Deny"

.PARAMETER RuleSection

What sort of section you want the rules for. Default is "All
Can be "All","Dll","Exe","Script","Appx","Msi"

.PARAMETER SID

The SID you want to get the rules for. 
Default is S-1-1-0. (Admin rules will not show up default as a consequence of that.)
If you want all you can supply *
List of well-known SIDs can be found here: https://support.microsoft.com/en-au/help/243330/well-known-security-identifiers-in-windows-operating-systems 

.PARAMETER XML

Switch. Returns output in XML format instead of Powershell objects. This makes it possible to export the data.
Note that it is not supported to specify Outputrules, RuleActions, RuleSection or SID when using this option.
The function exports all rules from the registry.

.PARAMETER OfflineXML

Path to OfflineXML that you have exported. 
This makes the function parse that file instead of the current AppLocker policy on the machine this script is running on. 
This function is currently now developed so it is adviced to use the Get-PALRulesNative instead for now.

.EXAMPLE
Gets all the AppLocker rules

PS C:\> Get-PALRulesStatus

Name RulesList                                                                                                                       
---- ---------                                                                                                                       
Appx {@{Ruletype=FilePublisherRule; Action=Allow; SID=S-1-1-0; Description=Allows members of the Everyone group to run packaged ap...
Exe  {@{Ruletype=FilePathRule; Action=Deny; SID=S-1-1-0; Description=; Name=%OSDRIVE%\inetpub; Id=16d974b5-279a-49a3-92c3-42b91050...
Msi  {@{Ruletype=FilePathRule; Action=Allow; SID=S-1-1-0; Description=Allows members of the Everyone group to run all Windows Inst...

.EXAMPLE
	
Gets all path rules that are defined with the deny Action

PS C:\> Get-PALRules -OutputRules Path -RuleActions Deny

Name RulesList                                                                                                                       
---- ---------                                                                                                                       
Exe  {@{Ruletype=FilePathRule; Action=Deny; SID=S-1-1-0; Description=; Name=%OSDRIVE%\inetpub; Id=16d974b5-279a-49a3-92c3-42b91050...

.EXAMPLE

Gets all the denied path rules and shows only the paths

PS C:\> (Get-PALRules -OutputRules Path -RuleActions Deny).RulesList.Path
%OSDRIVE%\inetpub\*
%WINDIR%\Microsoft.NET\*

.EXAMPLE

Gets all the publisher rules

PS C:\> Get-PALRules -OutputRules Publisher

Name RulesList                                                                                                                       
---- ---------                                                                                                                       
Appx {@{Ruletype=FilePublisherRule; Action=Allow; SID=S-1-1-0; Description=Allows members of the Everyone group to run packaged ap...
Exe  {@{Ruletype=FilePublisherRule; Action=Deny; SID=S-1-1-0; Description=; Name=CIPHER.EXE, in MICROSOFT® WINDOWS® OPERATING SYST...
Msi  {@{Ruletype=FilePublisherRule; Action=Allow; SID=S-1-1-0; Description=Allows members of the Everyone group to run digitally s...

.EXAMPLE

Exports the rules to an XML file

PS C:\> (Get-PALRules -XML).Save("c:\folder\Export.xml")

.EXAMPLE

Gets only allowed script rules.

PS C:\> Get-PALRules -OutputRules All -RuleActions Deny -RuleSection Script

Name   RulesList                                                                                                                                                                                                      
----   ---------                                                                                                                                                                                                      
Script {@{ParentName=Script; Ruletype=FilePathRule; Action=Deny; SID=S-1-1-0; Description=; Name=%WINDIR%\SysWOW64\Tasks\evil.exe; Id=88548f1b-4850-45d5-a551-2ab549fb0372; Path=C:\Windows\SysWOW64\Tasks\evil.exe...

#>

# Function Version: 0.95

    [CmdletBinding()] Param (
        [ValidateSet("All","Path","Publisher","Hash")]
        [String]
        $OutputRules = "All",
        
        [ValidateSet("All","Allow","Deny")]
        [String]
        $RuleActions = "All",

        [ValidateSet("All","Appx","Dll","Exe","Msi","Script")]
        [String]
        $RuleSection = "All",

        [String]
        #S-1-1-0 = Everyone - Default
        #* = ALL Sids
        $SID = "S-1-1-0",

        [Switch]
        $ExceptionsAsDeny,

        [Switch]
        $XML,

        [String]
        $OfflineXML
    )
    Process
    {
        Try
        {
            $RuleTypes = @("Appx","Dll","Exe","Msi","Script")

            If($OfflineXML)
            {
                write-error "OfflineXML not implemented yet. Still possible with Get-PALRulesNative -OfflineXML"
                break
            }

            If($XML) #Method to export rules from registry to a valid XML file
            {
                $TempXML = "<AppLockerPolicy Version=`"1`"`>"
                foreach($RuleType in $RuleTypes)
                {
                    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$RuleType"
                    $AppLockerRulesRegistry = Get-childItem -path $RegPath
                    
                    $HeadersAllowWindows = (Get-ItemProperty -path $RegPath -Name "AllowWindows").AllowWindows
                    
                    $ValueExists = Get-ItemProperty -Path $RegPath -Name "EnforcementMode" -ErrorAction SilentlyContinue
                    If (($ValueExists -ne $null) -and ($ValueExists.Length -ne 0)) {
                        $EnforcementMode = (Get-ItemProperty -path $RegPath -Name "EnforcementMode").EnforcementMode
                        
                        If($EnforcementMode -eq "1")
                        {
                            $HeadersEnforcementMode = "Enabled"
                        }
                        elseif($EnforcementMode -eq "0")
                        {
                            $HeadersEnforcementMode = "Audit"
                        }    
                    }
                    else
                    {
                        $HeadersEnforcementMode = "NotConfigured"
                    }
  
                    $TempXML += "<RuleCollection Type=`"$RuleType`" EnforcementMode=`"$HeadersEnforcementMode`"`>"
	                foreach($rule in $AppLockerRulesRegistry)
                    {
	                	[XML]$RuleXML = (Get-ItemProperty -Path $rule.PSPath).value
	                	$TempXML += $RuleXML.InnerXML
                    }
                    #End the ruletype currently proccessing
	                $TempXML += "</RuleCollection`>"
                }
                $TempXML += "</AppLockerPolicy`>"
                return ([xml]$TempXML)
            }
            else
            {
                $AllRulesArray = @()
                if($RuleSection -ne "All")
                {
                    $RuleTypes = @($RuleSection)
                }
		    	foreach($RuleType in $RuleTypes)
                {
		    	    
                    Write-Verbose "Processing $RuleType"
		        	$SectionRules = Get-childItem -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$RuleType"
                
		        	$ParentRulesObject = New-Object PSObject
		        	$ParentRulesObject | Add-Member NoteProperty 'Name' $RuleType
                
		        	#Array to store objects in
		        	$RulesArray = @()
                
		        	foreach($rule in $SectionRules) {
		        		[XML]$XML = (Get-ItemProperty -Path $rule.PSPath).value
                                    
		        		##Publisher rule
		        		if(($xml.FirstChild.LocalName) -eq "FilePublisherRule")
                        {
		        			if($OutputRules -eq "Publisher" -or $OutputRules -eq "All")
                            {
		        				if($xml.FirstChild.Action -eq $RuleActions -or $RuleActions -eq "All")
                                {
                                    if($xml.FirstChild.UserOrGroupSid -eq $SID -or $SID -eq "*")
                                    {   

		        					    write-verbose "Publisher rule"
		        					    $RulesObject = New-Object PSObject
                                
		        					    #Common structure for all rule types
		        					    $RulesObject | Add-Member NoteProperty 'ParentName' $RuleType
                                        $RulesObject | Add-Member NoteProperty 'Ruletype' $xml.FirstChild.LocalName
		        					    $RulesObject | Add-Member NoteProperty 'Action' $xml.FirstChild.Action
		        					    $RulesObject | Add-Member NoteProperty 'SID' $xml.FirstChild.UserOrGroupSid
		        					    $RulesObject | Add-Member NoteProperty 'Description' $xml.FirstChild.Description
		        					    $RulesObject | Add-Member NoteProperty 'Name' $xml.FirstChild.Name
		        					    $RulesObject | Add-Member NoteProperty 'Id' $xml.FirstChild.Id
                                
		        					    #Special Publisher attributes
		        					    $RulesObject | Add-Member NoteProperty 'PublisherName' $xml.FilePublisherRule.Conditions.FilePublisherCondition.PublisherName
		        					    $RulesObject | Add-Member NoteProperty 'Productname' $xml.FilePublisherRule.Conditions.FilePublisherCondition.ProductName
		        					    $RulesObject | Add-Member NoteProperty 'BinaryName' $xml.FilePublisherRule.Conditions.FilePublisherCondition.BinaryName
		        					    $RulesObject | Add-Member NoteProperty 'LowSection' $xml.FilePublisherRule.Conditions.FilePublisherCondition.BinaryVersionRange.LowSection
		        					    $RulesObject | Add-Member NoteProperty 'HighSection' $xml.FilePublisherRule.Conditions.FilePublisherCondition.BinaryVersionRange.HighSection

                                        #Exceptions
                                        if($xml.FirstChild.Exceptions.FilePathCondition)
                                        {
                                            $RealExceptionsPath = Expand-PALPath -Path $($xml.FirstChild.Exceptions.FilePathCondition.Path)
                                            $RulesObject | Add-Member NoteProperty 'PathExceptions' $RealExceptionsPath
                                            $RulesObject | Add-Member NoteProperty 'RulePathExceptions' $xml.FirstChild.Exceptions.FilePathCondition.Path
                                        }
                                        if($xml.FirstChild.Exceptions.FileHashCondition)
                                        {
                                            $RulesObject | Add-Member NoteProperty 'HashExceptions' $xml.FirstChild.Exceptions.FileHashCondition
                                        }
                                        if($xml.FirstChild.Exceptions.FilePublisherCondition)
                                        {
                                            $RulesObject | Add-Member NoteProperty 'PublisherExceptions' $xml.FirstChild.Exceptions.FilePublisherCondition
                                        }

                                        $RulesArray += $RulesObject 
                                    }
		        				}
		        			}
		        		}
                    
		        		##File hash rule
		        		if(($xml.FirstChild.LocalName) -eq "FileHashRule")
                        {
		        			if($OutputRules -eq "Hash" -or $OutputRules -eq "All")
                            {
		        				if($xml.FirstChild.Action -eq $RuleActions -or $RuleActions -eq "All")
                                {
                                    if($xml.FirstChild.UserOrGroupSid -eq $SID -or $SID -eq "*")
                                    {
                                        write-verbose "Hash rule"
		        					    $RulesObject = New-Object PSObject

		        					    #Common structure for all rule types
                                        $RulesObject | Add-Member NoteProperty 'ParentName' $RuleType
		        					    $RulesObject | Add-Member NoteProperty 'Ruletype' $xml.FirstChild.LocalName
		        					    $RulesObject | Add-Member NoteProperty 'Action' $xml.FirstChild.Action
		        					    $RulesObject | Add-Member NoteProperty 'SID' $xml.FirstChild.UserOrGroupSid
		        					    $RulesObject | Add-Member NoteProperty 'Description' $xml.FirstChild.Description
		        					    $RulesObject | Add-Member NoteProperty 'Name' $xml.FirstChild.Name
		        					    $RulesObject | Add-Member NoteProperty 'Id' $xml.FirstChild.Id

		        					    #Special Hash attributes
		        					    $RulesObject | Add-Member NoteProperty 'HashType' $xml.FileHashRule.Conditions.FileHashCondition.FileHash.Type
		        					    $RulesObject | Add-Member NoteProperty 'Hash' $xml.FileHashRule.Conditions.FileHashCondition.FileHash.Hash
		        					    $RulesObject | Add-Member NoteProperty 'Filename' $xml.FileHashRule.Conditions.FileHashCondition.FileHash.SourceFileName
		        					    $RulesObject | Add-Member NoteProperty 'Sourcefile Length' $xml.FileHashRule.Conditions.FileHashCondition.FileHash.SourceFileLength

                                        #Exceptions
                                        if($xml.FirstChild.Exceptions.FilePathCondition)
                                        {
                                            $RealExceptionsPath = Expand-PALPath -Path $($xml.FirstChild.Exceptions.FilePathCondition.Path)
                                            $RulesObject | Add-Member NoteProperty 'PathExceptions' $RealExceptionsPath
                                            $RulesObject | Add-Member NoteProperty 'RulePathExceptions' $xml.FirstChild.Exceptions.FilePathCondition.Path
                                        }
                                        if($xml.FirstChild.Exceptions.FileHashCondition)
                                        {
                                            $RulesObject | Add-Member NoteProperty 'HashExceptions' $xml.FirstChild.Exceptions.FileHashCondition
                                        }
                                        if($xml.FirstChild.Exceptions.FilePublisherCondition)
                                        {
                                            $RulesObject | Add-Member NoteProperty 'PublisherExceptions' $xml.FirstChild.Exceptions.FilePublisherCondition
                                        }

                                        $RulesArray += $RulesObject 
                                    }
		        				}
		        			}
		        		}
                    
		        		##Path rule
		        		if(($xml.FirstChild.LocalName) -eq "FilePathRule")
                        {
		        			if($OutputRules -eq "Path" -or $OutputRules -eq "All")
                            {
                                ## TEST CODE
                                if($ExceptionsAsDeny)
                                {
                                    if($xml.FirstChild.UserOrGroupSid -eq $SID -or $SID -eq "*")
                                    {
                                        #Exceptions
                                        if($xml.FirstChild.Exceptions.FilePathCondition)
                                        {
                                            foreach($Exception in $xml.FirstChild.Exceptions.FilePathCondition)
                                            {
                                                $ExceptionPath = Expand-PALPath -Path $($Exception.Path)
                                                $RulesObject = New-Object PSObject
                            
                                                #Common structure for all rule types
                                                $RulesObject | Add-Member NoteProperty 'ParentName' $RuleType
                                                $RulesObject | Add-Member NoteProperty 'Ruletype' $xml.FirstChild.LocalName
                                                $RulesObject | Add-Member NoteProperty 'Action' 'Deny'
                                                $RulesObject | Add-Member NoteProperty 'SID' $xml.FirstChild.UserOrGroupSid
                                                $RulesObject | Add-Member NoteProperty 'Description' $xml.FirstChild.Description
                                                $RulesObject | Add-Member NoteProperty 'Name' $xml.FirstChild.Name
                                                $RulesObject | Add-Member NoteProperty 'Id' $xml.FirstChild.Id

                                                #Special Path attributes
                                                $RulesObject | Add-Member NoteProperty 'Path' $ExceptionPath
                                                $RulesObject | Add-Member NoteProperty 'RulePath' $Exception.Path

                                                $RulesArray += $RulesObject
                                            }
                                        }
                                    }
                                }

		        				if($xml.FirstChild.Action -eq $RuleActions -or $RuleActions -eq "All")
                                {
                                    $RealPath = Expand-PALPath -Path $($xml.FirstChild.Conditions.FilePathCondition.Path)
                                    if($xml.FirstChild.UserOrGroupSid -eq $SID -or $SID -eq "*")
                                    {
		        					    write-verbose "Path rule"
                                        foreach($Path in $RealPath)
                                        {
		        					        $RulesObject = New-Object PSObject
                        
		        					        #Common structure for all rule types
                                            $RulesObject | Add-Member NoteProperty 'ParentName' $RuleType
		        					        $RulesObject | Add-Member NoteProperty 'Ruletype' $xml.FirstChild.LocalName
		        					        $RulesObject | Add-Member NoteProperty 'Action' $xml.FirstChild.Action
		        					        $RulesObject | Add-Member NoteProperty 'SID' $xml.FirstChild.UserOrGroupSid
		        					        $RulesObject | Add-Member NoteProperty 'Description' $xml.FirstChild.Description
		        					        $RulesObject | Add-Member NoteProperty 'Name' $xml.FirstChild.Name
		        					        $RulesObject | Add-Member NoteProperty 'Id' $xml.FirstChild.Id

		        					        #Special Path attributes
		        					        $RulesObject | Add-Member NoteProperty 'Path' $Path
                                            $RulesObject | Add-Member NoteProperty 'RulePath' $xml.FilePathRule.Conditions.FilePathCondition.Path

                                            #Exceptions
                                            if(!($ExceptionsAsDeny))
                                            {
                                                if($xml.FirstChild.Exceptions.FilePathCondition)
                                                {
                                                    $RealExceptionsPath = Expand-PALPath -Path $($xml.FirstChild.Exceptions.FilePathCondition.Path)
                                                    $RulesObject | Add-Member NoteProperty 'PathExceptions' $RealExceptionsPath
                                                    $RulesObject | Add-Member NoteProperty 'RulePathExceptions' $xml.FirstChild.Exceptions.FilePathCondition.Path
                                                }
                                                if($xml.FirstChild.Exceptions.FileHashCondition)
                                                {
                                                    $RulesObject | Add-Member NoteProperty 'HashExceptions' $xml.FirstChild.Exceptions.FileHashCondition
                                                }
                                                if($xml.FirstChild.Exceptions.FilePublisherCondition)
                                                {
                                                    $RulesObject | Add-Member NoteProperty 'PublisherExceptions' $xml.FirstChild.Exceptions.FilePublisherCondition
                                                }
                                            }
                                            
                                            $RulesArray += $RulesObject 
                                        }
		        				    }
                                }
		        			}
		        		}
		        	}
                                    
		        	# Only add to object if rules are found
		        	if($RulesArray) {
                        $ParentRulesObject | Add-Member NoteProperty -Name RulesList -Value $RulesArray
		        		$AllRulesarray += $ParentRulesObject
		        	}
		        }

		        if($AllRulesArray)
                {
                    return $AllRulesArray
		        }
            }

        }
        Catch
        {
            Write-Error $_
        }
        Finally{}
    }
}