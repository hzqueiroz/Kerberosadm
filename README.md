# Kerberosadm
Desabilitar/Habilitar/Reports de usuários TS

Esse módulo tem como objetivo ajudar administradores de ambientes Windows a verificar a utilização de RDP.
Existem 4 funções nesse:

Report-TS
Verifica em todos os usuários no campo msTSExpireDate para determinar o usuários que utilizaram o acesso RDP.

Get-TSUser
Busca propriedades EnableRemoteControl,allowLogon dos usuários
 
Disable-TSUser
Desabilita as propriedades EnableRemoteControl,allowLogon dos usuários.
  
Enable-TSUser
Habilita as propriedades EnableRemoteControl,allowLogon dos usuários.
  
  
