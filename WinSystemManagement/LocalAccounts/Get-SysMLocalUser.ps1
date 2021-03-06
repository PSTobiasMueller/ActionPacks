#Requires -Version 5.1

<#
.SYNOPSIS
    Gets local user accounts

.DESCRIPTION

.NOTES
    This PowerShell script was developed and optimized for ScriptRunner. The use of the scripts requires ScriptRunner. 
    The customer or user is authorized to copy the script from the repository and use them in ScriptRunner. 
    The terms of use for ScriptRunner do not apply to this script. In particular, AppSphere AG assumes no liability for the function, 
    the use and the consequences of the use of this freely available script.
    PowerShell is a product of Microsoft Corporation. ScriptRunner is a product of AppSphere AG.
    © AppSphere AG

.COMPONENT

.LINK
    https://github.com/scriptrunner/ActionPacks/tree/master/WinSystemManagement/LocalAccounts

.Parameter Name
    Specifies an name of user accounts, if the parameter empty all accounts retrieved. You can use the wildcard character

.Parameter SID
    Specifies an security ID (SID) of user accounts

.Parameter Properties
    List of properties to expand, comma separated e.g. Name,SID. Use * for all properties
 
.Parameter ComputerName
    Specifies an remote computer, if the name empty the local computer is used

.Parameter AccessAccount
    Specifies a user account that has permission to perform this action. If Credential is not specified, the current user account is used.
#>

[CmdLetBinding()]
Param(
    [Parameter(ParameterSetName = "ByName")]    
    [string]$Name,
    [Parameter(Mandatory = $true, ParameterSetName = "BySID")]    
    [string]$SID,
    [Parameter(ParameterSetName = "ByName")]   
    [Parameter(ParameterSetName = "BySID")]   
    [string]$Properties = "Name,Description,SID,Enabled,LastLogon",
    [Parameter(ParameterSetName = "ByName")]   
    [Parameter(ParameterSetName = "BySID")]     
    [string]$ComputerName,    
    [Parameter(ParameterSetName = "ByName")]   
    [Parameter(ParameterSetName = "BySID")]     
    [PSCredential]$AccessAccount
)

try{
    $Script:output
    if([System.String]::IsNullOrWhiteSpace($Properties)){
        $Properties=@('*')
    }
    if([System.String]::IsNullOrWhiteSpace($Name)){
        $Name='*'
    }
    $Script:props = $Properties.Split(',')
    if([System.String]::IsNullOrWhiteSpace($ComputerName) -eq $true){
        if($PSCmdlet.ParameterSetName  -eq "ByName"){
            $Script:output = Get-LocalUser -Name $Name | Select-Object $Script:props
        }
        else {
            $Script:output = Get-LocalUser -SID $SID | Select-Object $Script:props
        }
    }
    else {
        if($null -eq $AccessAccount){
            if($PSCmdlet.ParameterSetName  -eq "ByName"){
                $Script:output = Invoke-Command -ComputerName $ComputerName -ScriptBlock{
                    Get-LocalUser -Name $Using:Name | Select-Object $Using:props
                } -ErrorAction Stop
            }
            else {
                $Script:output = Invoke-Command -ComputerName $ComputerName -ScriptBlock{
                    Get-LocalUser -SID $Using:SID | Select-Object $Using:props
                } -ErrorAction Stop
            }
        }
        else {
            if($PSCmdlet.ParameterSetName  -eq "ByName"){
                $Script:output = Invoke-Command -ComputerName $ComputerName -Credential $AccessAccount -ScriptBlock{
                    Get-LocalUser -Name $Using:Name | Select-Object $Using:props
                } -ErrorAction Stop
            }
            else {
                $Script:output = Invoke-Command -ComputerName $ComputerName -Credential $AccessAccount -ScriptBlock{
                    Get-LocalUser -SID $Using:SID | Select-Object $Using:props
                } -ErrorAction Stop
            }
        }
    }          
    if($SRXEnv) {
        $SRXEnv.ResultMessage = $Script:output
    }
    else{
        Write-Output $Script:output
    }
}
catch{
    throw
}
finally{
}