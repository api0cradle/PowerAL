function Get-PALRules
{
#Requires -Modules AppLocker
<#
.SYNOPSIS

The function Get-PALRules returns the AppLocker rules as an object that is current on the local machine.
 

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-AppLockerPolicy (Native windows), Expand-PALPaths
Optional Dependencies: None

.DESCRIPTION

Will check against local registry under HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\ to find the AppLocker rules. 
Rules are stored as XML in the registry, the function converts it to an object before it returns it.

.PARAMETER OutputRules

The type of rules you want to get. Default is "All".
Can be "All","Path","Publisher","Hash"

.PARAMETER RuleActions

What sort of rules you want. Default is "All"
Can be "All","Allow","Deny"

.PARAMETER SID

The SID you want to get the rules for. 
Default is S-1-1-0. (Admin rules will not show up default as a consequence of that.)
If you want all you can supply *
List of well-known SIDs can be found here: https://support.microsoft.com/en-au/help/243330/well-known-security-identifiers-in-windows-operating-systems 

.PARAMETER XML

Switch. Returns output in XML format instead of Powershell objects. 

.PARAMETER OfflineXML

Path to OfflineXML that you have exported. 
This makes the function parse that file instead of the current AppLocker policy on the machine this script is running on.

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
    
Gets AppLocker rules from the specified XML file

PS C:\> Get-PALRules -OfflineXML C:\folder\Export.xml


Name   RulesList                                                                                                                                                                                     
----   ---------                                                                                                                                                                                     
Appx   {@{Ruletype=FilePublisherRule; Action=Allow; SID=S-1-1-0; Description=Allows members of the Everyone group to run packaged apps that are signed.; Name=(Default Rule) All signed packaged a...
Exe    {@{Ruletype=FilePathRule; Action=Allow; SID=S-1-1-0; Description=Allows members of the Everyone group to run applications that are located in the Program Files folder.; Name=(Default Rule...
Msi    {@{Ruletype=FilePublisherRule; Action=Allow; SID=S-1-1-0; Description=Allows members of the Everyone group to run digitally signed Windows Installer files.; Name=(Default Rule) All digita...
Script {@{Ruletype=FilePathRule; Action=Allow; SID=S-1-1-0; Description=Allows members of the Everyone group to run scripts that are located in the Program Files folder.; Name=(Default Rule) All...
#>
    [CmdletBinding()] Param (
        [ValidateSet("All","Path","Publisher","Hash")]
        [String]
        $OutputRules = "All",
        
        [ValidateSet("All","Allow","Deny")]
        [String]
        $RuleActions = "All",

        [String]
        #S-1-1-0 = Everyone - Default
        #* = ALL Sids
        $SID = "S-1-1-0",

        [Switch]
        $XML,

        [String]
        $OfflineXML
    )
    Process
    {
        Try
        {
            If($OfflineXML)
            {
                [XML]$Rules = Get-content -Path $OfflineXML
            }
            else
            {
                [XML]$Rules = Get-AppLockerPolicy -Effective -xml		
            }

            # All rules to XML as output if XML switch is on
            if($XML)
            {
                if($OutputRules -eq "All" -and $RuleActions -eq "All")
                {
                    return $Rules
                }
                else
                {
                    # Need a method to get selection rules to XML!
                    # Maybe V.next
                    "I do not support XML export of subset of rules and actions. Maybe next version - Sorry...."
                    return $null
                }
            }

            $AllRulesArray = @()

            foreach($col in $Rules.AppLockerPolicy.RuleCollection)
            {

                $ParentRulesObject = New-Object PSObject
		        $ParentRulesObject | Add-Member NoteProperty 'Name' $col.Type
                
		    	#Array to store objects in
		        $RulesArray = @()
            
                if($col.FilePublisherRule)
                {
                    if($OutputRules -eq "Publisher" -or $OutputRules -eq "All")
                    {
                        foreach($co in $col.FilePublisherRule)
                        {
                            if($co.action -eq $RuleActions -or $RuleActions -eq "All")
                            {
                                if($co.UserOrGroupSid -eq $SID -or $SID -eq "*")
                                {
                                    $RulesObject = New-Object PSObject
                                                
            			            #Common structure for all rule types
            			            $RulesObject | Add-Member NoteProperty 'Ruletype' "FilePublisherRule"
            			            $RulesObject | Add-Member NoteProperty 'Action' $co.Action
            			            $RulesObject | Add-Member NoteProperty 'SID' $co.UserOrGroupSid
            			            $RulesObject | Add-Member NoteProperty 'Description' $co.Description
            			            $RulesObject | Add-Member NoteProperty 'Name' $co.Name
            			            $RulesObject | Add-Member NoteProperty 'Id' $co.Id
                                    
            			            #Special Publisher attributes
            			            $RulesObject | Add-Member NoteProperty 'PublisherName' $co.Conditions.FilePublisherCondition.PublisherName
            			            $RulesObject | Add-Member NoteProperty 'Productname' $co.Conditions.FilePublisherCondition.ProductName
            			            $RulesObject | Add-Member NoteProperty 'BinaryName' $co.Conditions.FilePublisherCondition.BinaryName
            			            $RulesObject | Add-Member NoteProperty 'LowSection' $co.Conditions.FilePublisherCondition.BinaryVersionRange.LowSection
            			            $RulesObject | Add-Member NoteProperty 'HighSection' $co.Conditions.FilePublisherCondition.BinaryVersionRange.HighSection
                                    
                                    #Exceptions
                                    if($co.Exceptions.FilePathCondition)
                                    {
                                        $RealExceptionsPath = Expand-PALPath -Path $($co.Exceptions.FilePathCondition.Path)
                                        $RulesObject | Add-Member NoteProperty 'PathExceptions' $RealExceptionsPath
                                        $RulesObject | Add-Member NoteProperty 'RulePathExceptions' $co.Conditions.FilePathCondition.Path
                                    }
                                    if($co.Exceptions.FileHashCondition)
                                    {
                                        $RulesObject | Add-Member NoteProperty 'HashExceptions' $co.Exceptions.FileHashCondition
                                    }
                                    if($co.Exceptions.FilePublisherCondition)
                                    {
                                        $RulesObject | Add-Member NoteProperty 'PublisherExceptions' $co.Exceptions.FilePublisherCondition
                                    }

                                    $RulesArray += $RulesObject
                                }
                            }
                        }
                    }
                }
            
                if($col.FilePathRule)
                {
                    if($OutputRules -eq "Path" -or $OutputRules -eq "All")
                    {
                        foreach($co in $col.FilePathRule)
                        {
                            if($co.action -eq $RuleActions -or $RuleActions -eq "All")
                            {
                                $RealPath = Expand-PALPath -Path $($co.Conditions.FilePathCondition.Path)
                                if($co.UserOrGroupSid -eq $SID -or $SID -eq "*")
                                {
                                    foreach($Path in $RealPath)
                                    {
                                        $RulesObject = New-Object PSObject
                                            
                                        #Common structure for all rule types
                                        $RulesObject | Add-Member NoteProperty 'Ruletype' "FilePathRule"
                                        $RulesObject | Add-Member NoteProperty 'Action' $co.Action
                                        $RulesObject | Add-Member NoteProperty 'SID' $co.UserOrGroupSid
                                        $RulesObject | Add-Member NoteProperty 'Description' $co.Description
                                        $RulesObject | Add-Member NoteProperty 'Name' $co.Name
                                        $RulesObject | Add-Member NoteProperty 'Id' $co.Id
                                
                                        #Special Path attributes
                                        $RulesObject | Add-Member NoteProperty 'Path' $Path
                                        $RulesObject | Add-Member NoteProperty 'RulePath' $co.Conditions.FilePathCondition.Path
                                        
                                        #Exceptions
                                        if($co.Exceptions.FilePathCondition)
                                        {
                                            $RealExceptionsPath = Expand-PALPath -Path $($co.Exceptions.FilePathCondition.Path)
                                            $RulesObject | Add-Member NoteProperty 'PathExceptions' $RealExceptionsPath
                                            $RulesObject | Add-Member NoteProperty 'RulePathExceptions' $co.Exceptions.FilePathCondition.Path
                                        }
                                        if($co.Exceptions.FileHashCondition)
                                        {
                                            $RulesObject | Add-Member NoteProperty 'HashExceptions' $co.Exceptions.FileHashCondition
                                        }
                                        if($co.Exceptions.FilePublisherCondition)
                                        {
                                            $RulesObject | Add-Member NoteProperty 'PublisherExceptions' $co.Exceptions.FilePublisherCondition
                                        }
                                
                                        $RulesArray += $RulesObject
                                    }
                                }
                            }
                        }
                    }
                }
                if($col.FileHashRule)
                {
                    if($OutputRules -eq "Hash" -or $OutputRules -eq "All")
                    {
                        foreach($co in $col.FileHashRule)
                        {
                            if($co.action -eq $RuleActions -or $RuleActions -eq "All")
                            {
                                if($co.UserOrGroupSid -eq $SID -or $SID -eq "*")
                                {
                                    $RulesObject = New-Object PSObject
                                        
            			            #Common structure for all rule types
            			            $RulesObject | Add-Member NoteProperty 'Ruletype' "FileHashRule"
            			            $RulesObject | Add-Member NoteProperty 'Action' $co.Action
            			            $RulesObject | Add-Member NoteProperty 'SID' $co.UserOrGroupSid
            			            $RulesObject | Add-Member NoteProperty 'Description' $co.Description
            			            $RulesObject | Add-Member NoteProperty 'Name' $co.Name
            			            $RulesObject | Add-Member NoteProperty 'Id' $co.Id
            
            			            #Special Hash attributes
            			            $RulesObject | Add-Member NoteProperty 'HashType' $co.Conditions.FileHashCondition.FileHash.Type
            			            $RulesObject | Add-Member NoteProperty 'Hash' $co.Conditions.FileHashCondition.FileHash.Hash
            			            $RulesObject | Add-Member NoteProperty 'Filename' $co.Conditions.FileHashCondition.FileHash.SourceFileName
            			            $RulesObject | Add-Member NoteProperty 'Sourcefile Length' $co.Conditions.FileHashCondition.FileHash.SourceFileLength
                                    
                                    #Exceptions
                                    if($co.Exceptions.FilePathCondition)
                                    {
                                        $RealExceptionsPath = Expand-PALPath -Path $($co.Exceptions.FilePathCondition.Path)
                                        $RulesObject | Add-Member NoteProperty 'PathExceptions' $RealExceptionsPath
                                        $RulesObject | Add-Member NoteProperty 'RulePathExceptions' $co.Conditions.FilePathCondition.Path
                                    }
                                    if($co.Exceptions.FileHashCondition)
                                    {
                                        $RulesObject | Add-Member NoteProperty 'HashExceptions' $co.Exceptions.FileHashCondition
                                    }
                                    if($co.Exceptions.FilePublisherCondition)
                                    {
                                        $RulesObject | Add-Member NoteProperty 'PublisherExceptions' $co.Exceptions.FilePublisherCondition
                                    }

                                    $RulesArray += $RulesObject
                                }
                            }
                        }
                    }
                }
                
		        # Only add to object if rules are found
		        if($RulesArray)
                {
		            $arrList=$RulesArray
		            #[System.Collections.ArrayList]$arrList=$RulesArray
		        	$ParentRulesObject | Add-Member NoteProperty -Name RulesList -Value $arrList
		        	$AllRulesarray += $ParentRulesObject
		        }
		    }

	        if($AllRulesArray)
            {
	        	return $AllRulesArray
	        }
        }
        Catch
        {
            Write-Error $_
        }
        Finally{}
    }
}