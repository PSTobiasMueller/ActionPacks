﻿#Requires -Version 4.0

<#
    .SYNOPSIS
        Connect to Exchange Online and gets the Mailboxes from the Universal distribution group
    
    .DESCRIPTION  

    .NOTES
        This PowerShell script was developed and optimized for ScriptRunner. The use of the scripts requires ScriptRunner. 
        The customer or user is authorized to copy the script from the repository and use them in ScriptRunner. 
        The terms of use for ScriptRunner do not apply to this script. In particular, AppSphere AG assumes no liability for the function, 
        the use and the consequences of the use of this freely available script.
        PowerShell is a product of Microsoft Corporation. ScriptRunner is a product of AppSphere AG.
        © AppSphere AG

    .COMPONENT       
        ScriptRunner Version 4.x or higher

    .LINK
        https://github.com/scriptrunner/ActionPacks/tree/master/O365/ExchangeOnline/DistributionGroups

    .Parameter GroupId
        Specifies the Alias, Display name, Distinguished name, Guid or Mail address of the Universal distribution group from which to get mailboxes
    
    .Parameter Nested
        Shows group members nested 
    
    .Parameter MemberObjectTypes
        Specifies the member object types
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$GroupId,
    [switch]$Nested,
    [ValidateSet('All','Users', 'Groups')]
    [string]$MemberObjectTypes='All'
)

#Clear
#$ErrorActionPreference='Stop'

try{
    $Script:Members=@()
    function Get-NestedGroupMember($group) { 
        $Script:Members += "Group: $($group.DisplayName), $($group.PrimarySmtpAddress)" 
        if(($MemberObjectTypes -eq 'All' ) -or ($MemberObjectTypes -eq 'Users')){
            Get-DistributionGroupMember -Identity $group.Name  | Where-Object {$_.RecipientType -EQ 'MailUser'} | `
                Sort-Object -Property DisplayName | ForEach-Object{
                    $Script:Members += "Mailbox: $($_.DisplayName), $($_.PrimarySmtpAddress)"
                }
        }
        if(($MemberObjectTypes -eq 'All' ) -or ($MemberObjectTypes -eq 'Groups')){
            Get-DistributionGroupMember -Identity $group.Name  | Where-Object {$_.RecipientType -EQ 'MailUniversalDistributionGroup'} | `
                Sort-Object -Property DisplayName | ForEach-Object{
                    if($Nested -eq $true){
                        Get-NestedGroupMember $_
                    }
                    else {
                        $Script:Members += "Group: $($_.DisplayName), $($_.PrimarySmtpAddress)"
                    }                
                }
        }
    }
    $Grp = Get-DistributionGroup -Identity $GroupId
    if($null -ne $Grp){
        Get-NestedGroupMember $Grp
    }
    else {
        if($SRXEnv) {
            $SRXEnv.ResultMessage = "Universal distribution group not found"
        } 
        Throw "Universal distribution group not found"
    }

    if($null -ne $Script:Members){
        if($SRXEnv) {
            $SRXEnv.ResultMessage = $Script:Members
        } 
        else{
            Write-Output $Script:Members 
        }
    }
    else {
        if($SRXEnv) {
            $SRXEnv.ResultMessage = "No Universal distribution group members found"
        } 
        else{
            Write-Output "No Universal distribution group members found"
        }
    }
}
Finally{
    
}