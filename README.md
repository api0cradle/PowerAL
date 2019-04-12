# PowerAL

Current version: 0.90

A Powershell module for interacting with AppLocker.
Module is designed to be able to run in Constrained language mode.
This module is a work in progress. First version (0.63) was released at DerbyCon.

1. Run Powershell -ep unrestricted
2. Import-module PowerAL.psd1

Current list of functions:

- Expand-PALPath
- Get-PALPathStatus
- Get-PALPoshV2Installed
- Get-PALPublisherStatus
- Get-PALRules
- Get-PALRuleSectionStatus
- Get-PALServiceStatus
- Get-PALWriteableAllowedPaths
- Get-PALWriteablePaths
- Invoke-PALAllInfo
- Invoke-PALBypassPwn
- Invoke-PALCLMTempBypass
- Invoke-PALExploitableRules
- Invoke-PALKnownBypasses <- Not working


# Change log

version 0.90:
- Allowed pipe to expand-palpath
- Get-PALRulesNative created - Must still be used for OfflineXML checking
- Added rerun to Get-PALWriteableAllowedPaths
- Changed Get-PALWriteAblePaths to keep previous scans in Global variables (memory). Also it is optimalized to not scan the same area twice.
- Removed Invoke-PALRemoveCachedPath since all is done in memory
- ADS support on Expand-PALPath
- Changed name from Get-PALRulesStatus to Get-PALRuleSectionStatus
- Wrote Get-PALRules by getting AppLocker rules from Registry instead of using the native way leveraging Get-AppLockerPolicy
-  + many more things I forgot to write down
