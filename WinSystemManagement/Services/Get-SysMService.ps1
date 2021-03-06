#Requires -Version 4.0

<#
.SYNOPSIS
    Gets one or all services on a computer

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
    https://github.com/scriptrunner/ActionPacks/tree/master/WinSystemManagement/Services

.Parameter ComputerName
    Gets the service running on the specified computer. The default is the local computer

.Parameter ServiceName
    Specifies the name of service to be retrieved. If name and display name not specified, all services retrieved 

.Parameter ServiceDisplayName
    Specifies the display name of service to be retrieved. If name and display name not specified, all services retrieved 

.Parameter Properties
    List of properties to expand, comma separated e.g. Name,Description. Use * for all properties
#>

[CmdLetBinding()]
Param(
    [string]$ComputerName,
    [string]$ServiceName,
    [string]$ServiceDisplayName ,
    [string]$Properties="Name,DisplayName,Status,RequiredServices,DependentServices,CanStop,CanShutdown,CanPauseAndContinue"
)

try{
    $Script:output
    if([System.String]::IsNullOrWhiteSpace($ComputerName) -eq $true){
        $ComputerName = "."
    }
    if([System.String]::IsNullOrWhiteSpace($Properties) -eq $true){
        $Properties = '*'
    }
    else{
        if($null -eq ($Properties.Split(',') | Where-Object {$_ -like 'DisplayName'})){
            $Properties += ",DisplayName"
        }
    }
    [string[]]$Script:props=$Properties.Replace(' ','').Split(',')
    [hashtable]$cmdArgs = @{'ErrorAction' = 'Stop'
                            'ComputerName' = $ComputerName}
    if([System.String]::IsNullOrWhiteSpace($ServiceName) -eq $false){
        $cmdArgs.Add('Name', $ServiceName)
    }
    elseif([System.String]::IsNullOrWhiteSpace($ServiceDisplayName) -eq $false){
        $cmdArgs.Add('DisplayName', $ServiceDisplayName)
    }
    $Script:output = Get-Service @cmdArgs | Select-Object $Script:props `
                         | Sort-Object DisplayName | Format-List

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