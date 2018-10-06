function Invoke-PALAllInfo
{
<#
.SYNOPSIS

Runs all information checks to display current status of AppLocker on the local machine.

Author: @oddvarmoe
License: BSD 3-Clause
Required Dependencies: Get-PALRulesStatus,Get-PALServiceStatus,Get-PALRules
Optional Dependencies: None

.DESCRIPTION

Checks AppLocker Rules status (Auditing,Enforced,Not configured), Service status (started,stopped,starttype) and show the AppLocker Rules

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
    [CmdletBinding()] Param ()
    Process
    {
        Try
        {
            "`n[*] Running Invoke-PALAllInfo"
            
            "`n`n[*] Checking AppLocker Rule status"
            $Result = Get-PALRulesStatus
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