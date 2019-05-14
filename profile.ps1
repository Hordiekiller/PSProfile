Import-Module ActiveDirectory

$profile1 = "CurrentUserAllHosts"

######################################################################
######################################################################
####  Functions Go Here
######################################################################
######################################################################


##############################################################################
##
##  Place Generic Utility Items BELOW Here
##
##############################################################################

# Useful shortcuts for traversing directories
function cd...  { cd ..\.. }
function cd.... { cd ..\..\.. }

# Compute file hashes - useful for checking successful downloads 
function md5    { Get-FileHash -Algorithm MD5 $args }
function sha1   { Get-FileHash -Algorithm SHA1 $args }
function sha256 { Get-FileHash -Algorithm SHA256 $args }

# Translation
function toBase64 { [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($args)) }
function fromBase64 { [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($args)) }

# Quick shortcut to start notepad
function n      { notepad $args }

# Drive shortcuts
function HKLM:  { Set-Location HKLM: }
function HKCU:  { Set-Location HKCU: }
function Env:   { Set-Location Env: }

# Set up command prompt and window title. Use UNIX-style convention for identifying 
# whether user is elevated (root) or not. Window title shows current version of PowerShell
# and appends [ADMIN] if appropriate for easy taskbar identification
function prompt 
{ 
    if ($isEA) 
    {
        "[" + ($PSConfig.ADDomain.ToUpper() ) + "] EA> " 
    }
    elseif ($isAdmin)
    {
        "[" + (Get-Location) + "] ADMIN> " 
    }
    else 
    {
        "[" + (Get-Location) + "] PS> "
    }
}


# Does the the rough equivalent of dir /s /b. For example, dirs *.png is dir /s /b *.png
function dirs
{
    if ($args.Count -gt 0)
    {
        Get-ChildItem -Recurse -Include "$args" | Foreach-Object FullName
    }
    else
    {
        Get-ChildItem -Recurse | Foreach-Object FullName
    }
}

# Simple function to start a new elevated process. If arguments are supplied then 
# a single command is started with admin rights; if not then a new admin instance
# of PowerShell is started.
function admin
{
    if ($args.Count -gt 0)
    {   
       $argList = "& '" + $args + "'"
       Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $argList
    }
    else
    {
       Start-Process "$psHome\powershell.exe" -Verb runAs
    }
}

# Start a new PowerShell session with an Enterprise Admin Account
function Start-EA
{
    param([string]$EAAccount)

    if ($EAAccount)
    {
        runas /user:$EAAccount /smartcard powershell   
    }
    else
    {
    }
}


# Make it easy to edit this profile once it's installed
function Edit-Profile
{
    if ($host.Name -match "ise")
    {
        $psISE.CurrentPowerShellTab.Files.Add($profile.CurrentUserAllHosts)
    }
    else
    {
        notepad $profile.CurrentUserAllHosts
    }
}

#Display computer information
function myGetComputerInfo 
{
    Get-ChildItem Env: | Sort-Object -Property Name
}

# Place Help Information Here
function Get-CmdletAlias ($cmdletname) {
  Get-Alias |
    Where-Object -FilterScript {$_.Definition -like "$cmdletname"} |
      Format-Table -Property Definition, Name -AutoSize
}

function mySetTitleBar
{
    $Host.UI.RawUI.WindowTitle = "PowerShell {0}" -f $PSVersionTable.PSVersion.ToString()
    if ($isAdmin)
    {
        $Host.UI.RawUI.WindowTitle += " [*ADMIN*]"
    }

    if ($isEA)
    {
        $Host.UI.RawUI.WindowTitle += " [***ENTERPRISE ADMIN***]"
    }

    #Set the AD Information
    $Host.UI.RawUI.WindowTitle += (" [Forest]:" + $PSConfig.ADForest + "  [Domain]:" + $PSConfig.ADDomain + "  [SITE]:" + $PSConfig.ADTargetDCSite + "  [DC]:" + $PSConfig.ADTargetDC + "(" + $PSConfig.ADTargetDCIP + ")"  )
}


##############################################################################
##
##  Place Active Directory Related Items BELOW Here
##
##############################################################################

function myGetUserInfo 
{
    if($PSDefaultParameterValues.ContainsKey("*-AD*:Credential"))
    {
        #Get Current Default User then...
        $sLdapFilter = '(UserPrincipalName=' + ($PSDefaultParameterValues.Item("*-AD*:Credential").UserName) + ')'

        #Pull Current Default User Info
        $oUserInfo = Get-ADUser -LDAPFilter $sLdapFilter -Properties *
        $oUserInfo | Select-Object DisplayName, SamAccountName, UserPrincipalName, DistinguishedName, SID, ObjectGUID, LastLogonDate, PasswordLastSet, LastBadPasswordAttempt
    }
    else
    {
        $oUserInfo = Get-ADUser -Identity ($env:USERNAME) -Server ($env:USERDNSDOMAIN) -Properties *
        $oUserInfo | Select-Object DisplayName, SamAccountName, UserPrincipalName, DistinguishedName, SID, ObjectGUID, LastLogonDate, PasswordLastSet, LastBadPasswordAttempt
    }
}



function myGetDomainInfo 
{
    $PSConfig.GetEnumerator() | Sort-Object -Property Name
}

function mySetTargetDomainController
{
    param ([string]$DomainController)

    #Get the Domain
    $sDomain = $DomainController.Substring($DomainController.IndexOf('.')+1)

    #Set Domain Information
    mySetDomain -Domain $sDomain -DomainController $DomainController
}

function mySetDomain
{
    param ([string]$Domain, [string]$DomainController = $null)

    #Target Domain Controller
    $oTargetDCInfo = $null
    #Clear the PSDefaultParameterVAlues
    Set-Variable -Name PSDefaultParameterValues -Value @{} -Option AllScope -Force -Scope global
    #Clear the PSConfig information
    $PSConfig = @{}
    
    $PSConfig.Add("ADDomain"  , $Domain)

    #See if the users credentials work, if not change the default values
    try
    {
        $PSConfig.Add("ADForest"  , ((Get-ADForest -Server $PSConfig.ADDomain).RootDomain))
    }
    catch [System.Security.Authentication.AuthenticationException]
    {
        if ($_.Exception.HResult -eq -2146233087) 
        {
            #Prompt for Creds
            $Creds = Get-Credential

            #Set as Default
            Set-Variable -Name PSDefaultParameterValues -Value @{"*-AD*:Credential"=($Creds)} -Option AllScope -Force -Scope global

            #Try again, with the "right" credentials for the target forest
            $PSConfig.Add("ADForest"  , ((Get-ADForest -Server $PSConfig.ADDomain).RootDomain))
        }
    }

    $PSConfig.Add("ADDn"      , ((Get-ADDomain -Server $PSConfig.ADDomain).Distinguishedname))
    $PSConfig.Add("ADPDC"     , ((Get-ADDomain -Server $PSConfig.ADDomain).PDCEmulator))

    #Get the Target Domain Controller Information
    if($DomainController)
    {
        $oTargetDCInfo = Get-ADDomainController -Identity $DomainController -Server $Domain
        $PSConfig.Add("ADTargetDC"    , $oTargetDCInfo.HostName)
    }
    else
    {
        $oTargetDCInfo = Get-ADDomainController -Discover -ForceDiscover -DomainName $Domain
        $PSConfig.Add("ADTargetDC"    , $oTargetDCInfo.HostName.Value)
    }

    $PSConfig.Add("ADTargetDCIP"  , $oTargetDCInfo.IPv4Address)
    $PSConfig.Add("ADTargetDCSite", $oTargetDCInfo.Site)

    #Set Defaults for ActiveDirectory Module Commandlets
    $oDefaults = @{}
    if ($PSDefaultParameterValues.Count -gt 0)
    {
        $oDefaults = $PSDefaultParameterValues
        $oDefaults.Add("*-AD*:Server", $PSConfig.ADTargetDC)
    }
    else
    {
        $oDefaults.Add("*-AD*:Server", $PSConfig.ADTargetDC)
    }
    Set-Variable -Name PSDefaultParameterValues -Value $oDefaults -Option AllScope -Force -Scope global -Description "Contains the Target Default Domain Controller"

    #Refesh the title bar with the new information
    mySetTitleBar

    #Display AD Connection Information
    "Active Directory Information"
    "========================================================="
    myGetDomainInfo

    #Display AD Defaults
    "`nPowerShell Default Values:"
    "========================================================="
    $PSDefaultParameterValues
}


######################################################################
######################################################################
####  Commands Go Here
######################################################################
######################################################################
Set-Variable -Name PSConfig -Value @{} -Option AllScope -Force -Scope global -Description "Contains All the Configuration Information"

# Set UNIX-like aliases for the admin command, so sudo <command> will run the command
# with elevated rights. 
Set-Alias -Name su -Value admin
Set-Alias -Name sudo -Value admin

# Create the "Tools" directory
if (! (Test-Path -Path "C:\Tools")) {mkdir -Path "C:\Tools"}
Set-Location C:\Tools

# Creates drive shortcut for Work Folders, if current user account is using it
if (Test-Path "$env:USERPROFILE\Work Folders")
{
    New-PSDrive -Name Work -PSProvider FileSystem -Root "$env:USERPROFILE\Work Folders" -Description "Work Folders"
    function Work: { Set-Location Work: }
}

# Find out if the current user identity is elevated (has admin rights)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$oUserInfo = Get-ADUser -Identity ($env:USERNAME) -Server $env:USERDNSDOMAIN -Properties *
$isEA = $oUserInfo.MemberOf.Contains((Get-ADGroup "Enterprise Admins" -Server ((Get-ADForest).RootDomain)).Distinguishedname)

# If so and the current host is a command line, then change to red color 
# as warning to user that they are operating in an elevated context
if(($host.Name -match "ConsoleHost") -and ($isEA))
{
     $host.UI.RawUI.BackgroundColor = "DarkRed"
     $host.UI.RawUI.ForegroundColor = "Yellow"
     $host.PrivateData.ErrorBackgroundColor = "Black"
     $host.PrivateData.ErrorForegroundColor = "Green"
     $host.UI.RawUI.BufferSize.Height = 9999
     $host.UI.RawUI.BufferSize.Width  = 120
     Clear-Host
}
elseif (($host.Name -match "ConsoleHost") -and ($isAdmin))
{
     $host.UI.RawUI.BackgroundColor = "Black"
     $host.UI.RawUI.ForegroundColor = "Green"
     $host.PrivateData.ErrorBackgroundColor = "White"
     $host.PrivateData.ErrorForegroundColor = "DarkRed"
     $host.UI.RawUI.BufferSize.Height = 9999
     $host.UI.RawUI.BufferSize.Width  = 120
     Clear-Host
}
else
{
     $host.UI.RawUI.BackgroundColor = "DarkBlue"
     $Host.UI.RawUI.ForegroundColor = "Yellow"
     $host.PrivateData.ErrorBackgroundColor = "Black"
     $host.PrivateData.ErrorForegroundColor = "Green"
     $host.UI.RawUI.BufferSize.Height = 9999
     $host.UI.RawUI.BufferSize.Width  = 120
     Clear-Host
}


# AD Stuff Here
########################
$FqdnADDomain = ((Get-ADDomain).Distinguishedname.Replace(",DC=",'.').Replace("DC=",""))

#Setting Default to the FQDN Domain, so we can find a domain controller
mySetDomain -Domain $FqdnADDomain
