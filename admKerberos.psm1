
function report-TS {
    <#
    .SYNOPSIS
        Verifica em todos os usuários no campo msTSExpireDate para determinar o usuários que utilizaram o acesso RDP.
         
    .EXAMPLE
         report-TS -report All -format Csv

     .EXAMPLE
         report-TS -report Count -format View
    #>
    [cmdletbinding()]
    param(
        [parameter(ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("Users", "Count", "All")]
        [string]$report = "Count",
        [parameter(ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("Csv", "View")]
        [string]$format = "View"
    )
    
    $adUserTs = Get-ADUser -Filter { (msTSManagingLS -like '*' -and msTSLicenseVersion -like '*') -or (terminalServer -like '*') } -Properties * | select -Property Name, DistinguishedName, sAMAccountName, msTS*
    $enabledUsers = @()
    
    foreach ($line in $adUserTs) {
        $msTSExpireDate = [DateTime]::ParseExact("$($line.msTSExpireDate)", "MM/dd/yyyy HH:mm:ss", [System.Globalization.DateTimeFormatInfo]::InvariantInfo, [System.Globalization.DateTimeStyles]::None)
        $diffTime = ($msTSExpireDate - (get-date) | Select-Object -ExpandProperty TotalMinutes)
        if ($diffTime -gt 0) {
            $enabledUsers += $line
        }
    }
    $adCliente = @()
    foreach ($line in $enabledUsers.DistinguishedName) {
        $adCliente += $line.Split(',')[1..50] -join ','
    }
    $adCliente = $adCliente | Group-Object | Sort-Object count -Descending | Select-Object count, name   
    Switch ($report) {
        "Users" {
            if ($format -eq "Csv") {
                $enabledUsers | ConvertTo-Csv -Delimiter ";" -NoTypeInformation | Out-File $env:temp\report-user-ts-list.csv -force
                Write-Output "Arquivo $env:temp\report-user-ts-list.csv"
            }
            if ($format -eq "View") {
                $enabledUsers | Out-GridView -Title "Users List"
            }
        }
        "Count" {
            if ($format -eq "Csv") {
                $adCliente | ConvertTo-Csv -Delimiter ";" -NoTypeInformation | Out-File "$env:temp\report-user-ts-count.csv" -force
                Write-Output "Arquivo $env:temp\report-user-ts-count.csv"
            }
            if ($format -eq "View") {
                $adCliente | Out-GridView -Title "OU Count"
            }
        }
        "All" {
            if ($format -eq "Csv") {
                $adCliente | ConvertTo-Csv -Delimiter ";" -NoTypeInformation | Out-File "$env:temp\report-user-ts-count.csv" -force
                $enabledUsers | ConvertTo-Csv -Delimiter ";" -NoTypeInformation | Out-File "$env:temp\report-user-ts-list.csv" -force
                Write-Output "Arquivo $env:temp\report-user-ts-list.csv"
                Write-Output "Arquivo $env:temp\report-user-ts-count.csv"
            }
            if ($format -eq "View") {
                $enabledUsers | Out-GridView -Title "Users List"
                $adCliente | Out-GridView -Title "OU Count"
            }
        }
        default { }
    }
}

function get-TSUser {
    <#
    .SYNOPSIS
    Busca propriedades EnableRemoteControl,allowLogon dos usuários
    
    .EXAMPLE
    Get-TSUser $(Get-ADUser -Filter * -SearchBase "OU=\#users,DC=contoso,DC=local" | Select-Object -ExpandProperty samaccountname)  
        Busca propriedades EnableRemoteControl,allowLogon dos usuários da OU informada.
    .EXAMPLE
    Get-TSUser $(get-content "LISTA.txt")
        Busca propriedades EnableRemoteControl,allowLogon da lista de usuários.
    .EXAMPLE
    Get-TSUser USUARIO
        Busca propriedades do usuario.
    .EXAMPLE
    Get-TSUser USUARIO1,USUARIO2,USUARIO3
        Busca propriedades doS usuarios.
#> 
    param(
        [parameter(Mandatory,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string[]]$usrs
    )
    $ErrorActionPreference = 'SilentlyContinue'
    $result = @()
    $result += "Enabled;Username;DistinguishedName;LastLogonDate;PasswordLastSet;Created;EnableTS"
    foreach ($usr in $usrs) {
        $info = Get-ADUser $usr -Properties * | Select-Object DistinguishedName,
        @{N = 'PasswordLastSet'; E = { $_.LastLogonDate.ToString('dd/MM/yyyy HH:mm:ss') } },
        @{N = 'LastLogonDate'; E = { $_.PasswordLastSet.ToString('dd/MM/yyyy HH:mm:ss') } },
        @{N = 'Created'; E = { $_.Created.ToString('dd/MM/yyyy HH:mm:ss') } },
        Enabled
        if ($info.enabled.count -ne 0 ) {
            $user = [ADSI]"LDAP://$($info.DistinguishedName)"
            $ts = "Enable"
            if (($user.EnableremoteControl -eq 0) -and ($user.allowlogon -eq 0)) { $ts = "Disable" }
            $result += "$($info.Enabled);$usr;$($info.DistinguishedName);$($info.LastLogonDate);$($info.PasswordLastSet);$($info.Created);$ts"
        }
        else {
            write-host "Usuário não encontrado."  -ForegroundColor red 
        }
    }
    if ($result.count -gt 1) {
        $result | ConvertFrom-Csv -Delimiter ";"
    }
}

function Disable-TSUser {
    <#
    .SYNOPSIS
    Desabilita as propriedades EnableRemoteControl,allowLogon dos usuários.

    .EXAMPLE
    Disable-TSUser $(Get-ADUser -Filter * -SearchBase "OU=\#users,DC=constoso,DC=local" | Select-Object -ExpandProperty samaccountname)  
        Desabilita as propriedades EnableRemoteControl,allowLogon dos usuários da OU.
    .EXAMPLE
    Disable-TSUser $(get-content "LISTA.txt")
        Desabilita as propriedades EnableRemoteControl,allowLogon da lista de usuários.
    .EXAMPLE
    Disable-TSUser USUARIO
        Desabilita a propriedades do usuario.
    .EXAMPLE
    Disable-TSUser USUARIO1,USUARIO2,USUARIO3
        Desabilita a propriedades doS usuario.
#>   
    param(
        [parameter(Mandatory,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string[]]$usrs
    )
    $ErrorActionPreference = 'SilentlyContinue'
    foreach ($usr in $usrs) {
        $info = Get-ADUser $usr -Properties * | Select-Object LastLogonDate, DistinguishedName, PasswordLastSet, Created, Enabled
        if ($info.enabled.count -ne 0 ) {
            $user = [ADSI]"LDAP://$($info.DistinguishedName)"
            $user.InvokeSet("EnableRemoteControl", 0)
            $user.SetInfo()
            $user.InvokeSet("allowLogon", 0)
            $user.SetInfo()
            $ts = "Enable"
            if (($user.EnableremoteControl -eq 0) -and ($user.allowlogon -eq 0)) { $ts = "Disable" }
            if ($ts -eq "Disable") {
                write-host "As propriedades EnableRemoteControl,allowLogon do $usr foram desabilitadas com sucesso." -ForegroundColor Green
            }
            else {
                write-host "As propriedades EnableRemoteControl,allowLogon do $usr estão ativas." -ForegroundColor Yellow
            }
        }
        else {
            write-host "Usuário não encontrado."  -ForegroundColor red 
        }
    }
}

function Enable-TSUser {
    <#
    .SYNOPSIS
    Habilita as propriedades EnableRemoteControl,allowLogon dos usuários.
    
    .EXAMPLE
    Enable-TSUser $(Get-ADUser -Filter * -SearchBase "OU=\#Users,DC=contoso,DC=local" | Select-Object -ExpandProperty samaccountname)  
        Habilita as propriedades EnableRemoteControl,allowLogon dos usuários da OU informada.
    .EXAMPLE
    Enable-TSUser $(get-content "LISTA.txt")
        Habilita as propriedades EnableRemoteControl,allowLogon da lista de usuários.
    .EXAMPLE
    Enable-TSUser USUARIO
        Habilita a propriedades do usuario.
    .EXAMPLE
    Enable-TSUser USUARIO1,USUARIO2,USUARIO3
        Habilita a propriedades doS usuario.
#>    
    param(
        [parameter(Mandatory,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string[]]$usrs
    )
    $ErrorActionPreference = 'SilentlyContinue'
    foreach ($usr in $usrs) {
        $info = Get-ADUser $usr -Properties * | Select-Object LastLogonDate, DistinguishedName, PasswordLastSet, Created, Enabled
        if ($info.enabled.count -ne 0 ) {
            $user = [ADSI]"LDAP://$($info.DistinguishedName)"
            $user.InvokeSet("EnableRemoteControl", 1)
            $user.SetInfo()
            $user.InvokeSet("allowLogon", 1)
            $user.SetInfo()
            $ts = "Enable"
            if (($user.EnableremoteControl -eq 0) -and ($user.allowlogon -eq 0)) { $ts = "Disable" }
            if ($ts -eq "Enable") {
                write-host "As propriedades EnableRemoteControl,allowLogon do $usr foram habilitadas com sucesso." -ForegroundColor Green
            }
            else {
                write-host "As propriedades EnableRemoteControl,allowLogon do $usr estão desativadas." -ForegroundColor Yellow
            }

        }
        else {
            write-host "usuário não encontrado $usr."  -ForegroundColor red 
        }
    }
}

