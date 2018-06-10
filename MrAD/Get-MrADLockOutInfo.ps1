#Requires -Version 3.0

[CmdletBinding()] 
param ( 
	[ValidateNotNullOrEmpty()] 
	[string]$DomainName = $env:USERDOMAIN, 

	[ValidateNotNullOrEmpty()] 
	[string]$UserName = '*', 

	[ValidateNotNullOrEmpty()] 
	[datetime]$StartTime = (Get-Date).AddDays(-3),

	[System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

	[ValidateNotNullOrEmpty()]
	[string]$Id = 4740                           <# AMMEND HERE - REQUIRED ID PARAMETER, OR, PASS IN AS -id #>
)
	
	
function Get-MrADLockOutInfo {

<# 
.SYNOPSIS 
    Get-MrADLockOutInfo returns a list of users who were locked out in Active Directory. 
  
.DESCRIPTION 
    Get-MrADLockOutInfo is an advanced function that returns a list of users who were locked out in Active Directory 
    by querying the event logs on the PDC emulator in the domain. 
  
.PARAMETER UserName 
    The userid of the specific user you are looking for lockouts for. The default is all locked out users. 
  
.PARAMETER StartTime 
    The datetime to start searching the event logs from. The default is the past three days.
.PARAMETER Credential
    Specifies a user account that has permission to read the security event log on the PDC emulator. The default is
    the current user.
  
.EXAMPLE 
    Get-MrADLockOutInfo
.EXAMPLE
    Get-MrADLockOutInfo -Credential (Get-Credential)
  
.EXAMPLE 
    Get-MrADLockOutInfo -UserName 'mikefrobbins' 
  
.EXAMPLE 
    Get-MrADLockOutInfo -StartTime (Get-Date).AddDays(-1) 
  
.EXAMPLE 
    Get-MrADLockOutInfo -UserName 'mikefrobbins' -StartTime (Get-Date).AddDays(-1) -Credential (Get-Credential)

    DAVE NOTE: 4740 event (normal)
    DAVE NOTE: 4625 event (Log On type 3)
    DAVE NOTE: 4624 event - log on successful I think
    DAVE NOTE: SEE https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/
#> 

    try {
        $ErrorActionPreference = 'Stop'

        $PdcEmulator = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(( 
            New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $DomainName)) 
        ).PdcRoleOwner.name

        Write-Verbose -Message "The PDC emulator in your forest root domain is: $PdcEmulator"
        $ErrorActionPreference = 'Continue'
    }
    catch {
        Write-Error -Message 'Unable to query the domain. Verify the user running this script has read access to Active Directory and try again.'
    }
    
    $Params = @{}
    If ($PSBoundParameters['Credential']) {
        $Params.Credential = $Credential
    }

    $a = Invoke-Command -ComputerName $PdcEmulator { 
        Get-WinEvent -ErrorAction Ignore -FilterHashtable @{LogName='Security';Id=$Using:Id;StartTime=$Using:StartTime} |
        Where-Object {$_.Properties[0].Value -like "$Using:UserName"} |
        Select-Object -Property TimeCreated,
                                @{Label='UserName';Expression={$_.Properties[0].Value}},
                                @{Label='ClientName';Expression={$_.Properties[1].Value}}
    } @Params | 
    Select-Object -Property TimeCreated, UserName, ClientName <# -First 1 #>    

    Write-Host "<prtg>"
    Write-Host "<result>"
    "<channel>Locked Out Users</channel>"
    "<value>"+ @($a).Count +"</value>"
    "</result>"
    "<text>" + $Id + ", first one: " + @($a)[0] + "</text>"
    Write-Host "</prtg>"
    

}

Get-MrADLockOutInfo;
