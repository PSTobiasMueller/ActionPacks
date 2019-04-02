#Requires -Version 4.0
#Requires -Modules ActiveDirectory

<#
    .SYNOPSIS
         Lists users where Password is expired or will expire in the next x days

    .DESCRIPTION

    .NOTES
        This PowerShell script was developed and optimized for ScriptRunner. The use of the scripts requires ScriptRunner.
        The customer or user is authorized to copy the script from the repository and use them in ScriptRunner.
        The terms of use for ScriptRunner do not apply to this script. In particular, AppSphere AG assumes no liability for the function,
        the use and the consequences of the use of this freely available script.
        PowerShell is a product of Microsoft Corporation. ScriptRunner is a product of AppSphere AG.
        © AppSphere AG

    .COMPONENT
        Requires Module ActiveDirectory

    .LINK
        https://github.com/scriptrunner/ActionPacks/tree/master/ActiveDirectory/Users

    .Parameter OUPath
        Specifies the AD path

    .Parameter DomainAccount
        Active Directory Credential

    .Parameter Expired
        Show the users where password is expired

    .Parameter ExpiringIn
        Show the users where password is expiring in  the next x days.

    .Parameter DoNotExpire
        Show the users where password is set to not expire

    .Parameter DomainName
        Name of Active Directory Domain

    .Parameter SearchScope
        Specifies the scope of an Active Directory search

    .Parameter AuthType
        Specifies the authentication method to use
#>

param(
    [Parameter(Mandatory = $true, ParameterSetName = "Local or Remote DC")]
    [Parameter(Mandatory = $true, ParameterSetName = "Remote Jumphost")]
    [string]$OUPath,
    [Parameter(Mandatory = $true, ParameterSetName = "Remote Jumphost")]
    [PSCredential]$DomainAccount,
    [Parameter(ParameterSetName = "Local or Remote DC")]
    [Parameter(ParameterSetName = "Remote Jumphost")]
    [switch]$Expired,
    [Parameter(ParameterSetName = "Local or Remote DC")]
    [Parameter(ParameterSetName = "Remote Jumphost")]
    [string]$ExpiringIn,
    [Parameter(ParameterSetName = "Local or Remote DC")]
    [Parameter(ParameterSetName = "Remote Jumphost")]
    [switch]$DoNotExpire,
    [Parameter(ParameterSetName = "Local or Remote DC")]
    [Parameter(ParameterSetName = "Remote Jumphost")]
    [string]$DomainName,
    [Parameter(ParameterSetName = "Local or Remote DC")]
    [Parameter(ParameterSetName = "Remote Jumphost")]
    [ValidateSet('Base', 'OneLevel', 'SubTree')]
    [string]$SearchScope = 'SubTree',
    [Parameter(ParameterSetName = "Local or Remote DC")]
    [Parameter(ParameterSetName = "Remote Jumphost")]
    [ValidateSet('Basic', 'Negotiate')]
    [string]$AuthType = "Negotiate"
)

Import-Module ActiveDirectory

try
{
    $Script:resultMessage = @()
    [hashtable]$cmdArgs = @{'ErrorAction' = 'Stop'
        'AuthType'                        = $AuthType
    }
    if ($null -ne $DomainAccount)
    {
        $cmdArgs.Add("Credential", $DomainAccount)
    }
    if ([System.String]::IsNullOrWhiteSpace($DomainName))
    {
        $cmdArgs.Add("Current", 'LocalComputer')
    }
    else
    {
        $cmdArgs.Add("Identity", $DomainName)
    }
    $Domain = Get-ADDomain @cmdArgs

    $cmdArgs = @{'ErrorAction' = 'Stop'
        'Server'               = $Domain.PDCEmulator
        'AuthType'             = $AuthType
        'SearchBase'           = $OUPath
        'SearchScope'          = $SearchScope
    }
    $Filter = 'Enabled -eq $True -and PasswordNeverExpires -eq $False -and samAccountName -notlike "*$"'
    $Properties = "DisplayName", "SamAccountName", "msDS-UserPasswordExpiryTimeComputed"

    if ($null -ne $DomainAccount)
    {
        $cmdArgs.Add("Credential", $DomainAccount)
    }

    $users = Get-ADUser @cmdArgs -Filter $Filter -Properties $Properties |
    Where-Object { $_."msDS-UserPasswordExpiryTimeComputed" -ne 0 } |
    Select-Object -Property *, @{Name = "expiryDate"; Expression = { [datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed") } } |
    Sort-Object -Property expiryDate -Descending

    if ($Expired -eq $true)
    {
        if ($users)
        {
            foreach ($itm in  $users | Where-Object { $diff = New-TimeSpan (Get-Date) ($_.expiryDate)
                    $diff.Days -lt 0 })
            {
                $Script:resultMessage += ("Expired PW: " + $itm.DisplayName + ';' + $itm.SamAccountName + ';' + $itm.expiryDate.ToString())
            }
            $Script:resultMessage += ''
        }
    }

    if (!([System.String]::IsNullOrEmpty($ExpiringIn)))
    {
        if ($users)
        {
            foreach ($itm in  $users | Where-Object { $diff = New-TimeSpan (Get-Date) ($_.expiryDate)
                    $diff.Days -le $ExpiringIn -and $diff -gt 0 } | Sort-Object -Property expiryDate)
            {
                $Script:resultMessage += ("Expiring PW in: " + $itm.DisplayName + ';' + $itm.SamAccountName + ';' + $itm.expiryDate.ToString())
            }
        }
    }

    if ($DoNotExpire)
    {
        $users = Search-ADAccount @cmdArgs -PasswordNeverExpires | Select-Object Name, SAMAccountName | Sort-Object -Property SAMAccountName
        if ($users)
        {
            foreach ($itm in  $users)
            {
                $Script:resultMessage += ("PW never expire: " + $itm.Name + ';' + $itm.SamAccountName)
            }
        }
    }


    if ($SRXEnv)
    {
        $SRXEnv.ResultMessage = $resultMessage
    }
    else
    {
        Write-Output $resultMessage
    }
}
catch
{
    throw
}
finally
{
}