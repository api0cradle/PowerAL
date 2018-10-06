# PowerAL

Current version: 0.64

A Powershell module for interacting with AppLocker.
Module is designed to be able to run in Constrained language mode.
This module is a work in progress. First version (0.63) was released at DerbyCon.

1. Run Powershell -ep unrestricted
2. Import-module PowerAL.psm1

Current list of functions:

- Expand-PALPath
- Get-PALPathStatus
- Get-PALPoshV2Installed
- Get-PALPublisherStatus
- Get-PALRules
- Get-PALRuleStatus
- Get-PALServiceStatus
- Get-PALWriteableAllowedPaths
- Get-PALWriteablePaths
- Invoke-PALAllInfo
- Invoke-PALBypassPwn
- Invoke-PALCLMTempBypass
- Invoke-PALExploitableRules
- Invoke-PALKnownBypasses <- Not working
- Invoke-PALRemoveCache