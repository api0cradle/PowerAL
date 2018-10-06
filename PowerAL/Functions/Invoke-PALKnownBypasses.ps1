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