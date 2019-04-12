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