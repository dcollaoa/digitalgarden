## Enumerating the Password Policy - from Linux - Credentialed

Como se mencionó en la sección anterior, podemos obtener la política de contraseñas del dominio de varias maneras, dependiendo de cómo esté configurado el dominio y si tenemos o no credenciales de dominio válidas. Con credenciales de dominio válidas, la política de contraseñas también se puede obtener de forma remota utilizando herramientas como [CrackMapExec](https://github.com/byt3bl33r/CrackMapExec) o `rpcclient`.

```r
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Dumping password info for domain: INLANEFREIGHT
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Minimum password length: 8
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Password history length: 24
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Maximum password age: Not Set
SMB         172.16.5.5      445    ACADEMY-EA-DC01  
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Password Complexity Flags: 000001
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Refuse Password Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password Store Cleartext: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password Lockout Admins: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password No Clear Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password No Anon Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password Complex: 1
SMB         172.16.5.5      445    ACADEMY-EA-DC01  
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Minimum password age: 1 day 4 minutes 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Reset Account Lockout Counter: 30 minutes 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Locked Account Duration: 30 minutes 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Account Lockout Threshold: 5
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Forced Log off Time: Not Set
```

---

## Enumerating the Password Policy - from Linux - SMB NULL Sessions

Sin credenciales, podemos obtener la política de contraseñas a través de una sesión NULL de SMB o una vinculación anónima de LDAP. La primera es a través de una sesión NULL de SMB. Las sesiones NULL de SMB permiten a un atacante no autenticado recuperar información del dominio, como una lista completa de usuarios, grupos, computadoras, atributos de cuentas de usuario y la política de contraseñas del dominio. Las configuraciones incorrectas de sesiones NULL de SMB a menudo son el resultado de Controladores de Dominio heredados que se actualizan in situ, lo que finalmente conlleva configuraciones inseguras que existían por defecto en versiones anteriores de Windows Server.

Al crear un dominio en versiones anteriores de Windows Server, se otorgaba acceso anónimo a ciertos recursos compartidos, lo que permitía la enumeración del dominio. Una sesión NULL de SMB se puede enumerar fácilmente. Para la enumeración, podemos utilizar herramientas como `enum4linux`, `CrackMapExec`, `rpcclient`, etc.

Podemos usar [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) para verificar un Domain Controller en busca de acceso a sesión NULL de SMB.

Una vez conectados, podemos emitir un comando RPC como `querydominfo` para obtener información sobre el dominio y confirmar el acceso a la sesión NULL.

### Using rpcclient

```r
rpcclient -U "" -N 172.16.5.5

rpcclient $> querydominfo
Domain:		INLANEFREIGHT
Server:		
Comment:	
Total Users:	3650
Total Groups:	0
Total Aliases:	37
Sequence No:	1
Force Logoff:	-1
Domain Server State:	0x1
Server Role:	ROLE_DOMAIN_PDC
Unknown 3:	0x1
```

También podemos obtener la política de contraseñas. Podemos ver que la política de contraseñas es relativamente débil, permitiendo una contraseña mínima de 8 caracteres.

### Obtaining the Password Policy using rpcclient

```r
rpcclient $> querydominfo

Domain:		INLANEFREIGHT
Server:		
Comment:	
Total Users:	3650
Total Groups:	0
Total Aliases:	37
Sequence No:	1
Force Logoff:	-1
Domain Server State:	0x1
Server Role:	ROLE_DOMAIN_PDC
Unknown 3:	0x1
rpcclient $> getdompwinfo
min_password_length: 8
password_properties: 0x00000001
	DOMAIN_PASSWORD_COMPLEX
```

---

Vamos a probar esto usando [enum4linux](https://labs.portcullis.co.uk/tools/enum4linux). `enum4linux` es una herramienta construida alrededor de la [suite de herramientas Samba](https://www.samba.org/samba/docs/current/man-html/samba.7.html) `nmblookup`, `net`, `rpcclient` y `smbclient` para usar en la enumeración de hosts y dominios Windows. Se puede encontrar preinstalada en muchas distribuciones de pruebas de penetración, incluyendo Parrot Security Linux. A continuación, tenemos un ejemplo de salida que muestra la información que puede proporcionar `enum4linux`. Aquí hay algunas herramientas comunes de enumeración y los puertos que utilizan:

| Herramienta | Puertos |
|---|---|
| nmblookup | 137/UDP |
| nbtstat | 137/UDP |
| net | 139/TCP, 135/TCP, TCP y UDP 135 y 49152-65535 |
| rpcclient | 135/TCP |
| smbclient | 445/TCP |

### Using enum4linux

```r
enum4linux -P 172.16.5.5

<SNIP>

 ================================================== 
|    Password Policy Information for 172.16.5.5    |
 ================================================== 

[+] Attaching to 172.16.5.5 using a NULL share
[+] Trying protocol 139/SMB...

	[!] Protocol failed: Cannot request session (Called Name:172.16.5.5)

[+] Trying protocol 445/SMB...
[+] Found domain(s):

	[+] INLANEFREIGHT
	[+] Builtin

[+] Password Info for Domain: INLANEFREIGHT

	[+] Minimum password length: 8
	[+] Password history length: 24
	[+] Maximum password age: Not Set
	[+] Password Complexity Flags: 000001

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 1

	[+] Minimum password age: 1 day 4 minutes 
	[+] Reset Account Lockout Counter: 30 minutes 
	[+] Locked Account Duration: 30 minutes 
	[+] Account Lockout Threshold: 5
	[+] Forced Log off Time: Not Set

[+] Retieved partial password policy with rpcclient:

Password Complexity: Enabled
Minimum Password Length: 8

enum4linux complete on Tue Feb 22 17:39:29 2022
```

La herramienta [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) es una reescritura de `enum4linux` en Python, pero tiene características adicionales como la capacidad de exportar datos como archivos YAML o JSON que luego se pueden usar para procesar los datos más adelante o alimentarlos a otras herramientas. También soporta salida con colores, entre otras características.

### Using enum4linux-ng

```r
enum4linux-ng -P 172.16.5.5 -oA ilfreight

ENUM4LINUX - next generation

<SNIP>

 =======================================
|    RPC Session Check on 172.16.5.5    |
 =======================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user session
[-] Could not establish random user session: STATUS_LOGON_FAILURE

 =================================================
|    Domain Information via RPC for 172.16.5.5    |
 =================================================
[+] Domain: INLANEFREIGHT
[+] SID: S-1-5-21-3842939050-3880317879-2865463114
[+] Host is part of a domain (not a workgroup)
 =========================================================
|    Domain Information via SMB session for 172.16.5.5    |
========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: ACADEMY-EA-DC01
NetBIOS domain name: INLANEFREIGHT
DNS domain: INLANEFREIGHT.LOCAL
FQDN: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

 =======================================
|    Policies via RPC for 172.16.5.5    |
 =======================================
[*] Trying port 445/tcp
[+] Found policy:
domain_password_information:
  pw_history_length: 24
  min_pw_length: 8
  min_pw_age: 1 day 4 minutes
  max_pw_age: not set
  pw_properties:
  - DOMAIN_PASSWORD_COMPLEX: true
  - DOMAIN_PASSWORD_NO_ANON_CHANGE: false
  - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
  - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
  - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
  - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
domain_lockout_information:
  lockout_observation_window: 30 minutes
  lockout_duration: 30 minutes
  lockout_threshold: 5
domain_logoff_information:
  force_logoff_time: not set

Completed after 5.41 seconds
```

Enum4linux-ng nos proporcionó una salida un poco más clara y una salida útil en formato JSON y YAML utilizando la flag `-oA`.

### Displaying the contents of ilfreight.json

```r
cat ilfreight.json 

{
    "target": {
        "host": "172.16.5.5",
        "workgroup": ""
    },
    "credentials": {
        "user": "",
        "password": "",
        "random_user": "yxditqpc"
    },
    "services": {
        "SMB": {
            "port": 445,
            "accessible": true
        },
        "SMB over NetBIOS": {
            "port": 139,
            "accessible": true
        }
    },
    "smb_dialects": {
        "SMB 1.0": false,
        "SMB 2.02": true,
        "SMB 2.1": true,
        "SMB 3.0": true,
        "SMB1 only": false,
        "Preferred dialect": "SMB 3.0",
        "SMB signing required": true
    },
    "sessions_possible": true,
    "null_session_possible": true,

<SNIP>
```

## Enumerating Null Session - from Windows

Es menos común realizar este tipo de ataque de sesión NULL desde Windows, pero podríamos usar el comando `net use \\host\ipc$ "" /u:""` para establecer una sesión NULL desde una máquina Windows y confirmar si podemos realizar más de este tipo de ataque.

### Establish a null session from windows

```r
C:\htb> net use \\DC01\ipc$ "" /u:""
The command completed successfully.
```

También podemos usar una combinación de nombre de usuario y contraseña para intentar conectarnos. Veamos algunos errores comunes al intentar autenticarnos:

### Error: Account is Disabled

```r
C:\htb> net use \\DC01\ipc$ "" /u:guest
System error 1331 has occurred.

This user can't sign in because this account is currently disabled.
```

### Error: Password is Incorrect

```r
C:\htb> net use \\DC01\ipc$ "password" /u:guest
System error 1326 has occurred.

The user name or password is incorrect.
```

### Error: Account is locked out (Password Policy)

```r
C:\htb> net use \\DC01\ipc$ "password" /u:guest
System error 1909 has occurred.

The referenced account is currently locked out and may not be logged on to.
```

## Enumerating the Password Policy - from Linux - LDAP Anonymous Bind

[LDAP anonymous binds](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations-active-directory-disabled) permiten a los atacantes no autenticados recuperar información del dominio, como una lista completa de usuarios, grupos, computadoras, atributos de cuentas de usuario y la política de contraseñas del dominio. Esta es una configuración heredada y, a partir de Windows Server 2003, solo se permite a los usuarios autenticados iniciar solicitudes LDAP. Todavía vemos esta configuración de vez en cuando, ya que un administrador puede haber necesitado configurar una aplicación específica para permitir enlaces anónimos y otorgar más acceso del que se pretendía, dando así a los usuarios no autenticados acceso a todos los objetos en AD.

Con un enlace anónimo LDAP, podemos usar herramientas específicas de enumeración LDAP como `windapsearch.py`, `ldapsearch`, `ad-ldapdomaindump.py`, etc., para obtener la política de contraseñas. Con [ldapsearch](https://linux.die.net/man/1/ldapsearch), puede ser un poco complicado pero factible. Un comando de ejemplo para obtener la política de contraseñas es el siguiente:

### Using ldapsearch

```r
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

forceLogoff: -9223372036854775808
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 5
maxPwdAge: -9223372036854775808
minPwdAge: -864000000000
minPwdLength: 8
modifiedCountAtLastProm: 0
nextRid: 1002
pwdProperties: 1
pwdHistoryLength: 24
```

Aquí podemos ver la longitud mínima de la contraseña de 8, el umbral de bloqueo de 5 y la complejidad de la contraseña está habilitada (`pwdProperties` configurado en `1`).

---
## Enumerating the Password Policy - from Windows

Si podemos autenticarnos en el dominio desde un host Windows, podemos usar binarios integrados de Windows como `net.exe` para recuperar la política de contraseñas. También podemos usar varias herramientas como PowerView, CrackMapExec portado a Windows, SharpMapExec, SharpView, etc.

Usar comandos integrados es útil si llegamos a un sistema Windows y no podemos transferir herramientas a él, o estamos posicionados en un sistema Windows por el cliente, pero no tenemos forma de obtener herramientas en él. Un ejemplo usando el binario integrado net.exe es:

### Using net.exe

```r
C:\htb> net accounts

Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          Unlimited
Minimum password length:                              8
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
The command completed successfully.
```

Aquí podemos obtener la siguiente información:

- Las contraseñas nunca caducan (la edad máxima de la contraseña está establecida en Ilimitada)
- La longitud mínima de la contraseña es 8, por lo que es probable que se usen contraseñas débiles
- El umbral de bloqueo es 5 contraseñas incorrectas
- Las cuentas permanecen bloqueadas durante 30 minutos

Esta política de contraseñas es excelente para password spraying. El mínimo de ocho caracteres significa que podemos probar contraseñas débiles comunes como `Welcome1`. El umbral de bloqueo de 5 significa que podemos intentar 2-3 (para estar seguros) rociados cada 31 minutos sin el riesgo de bloquear ninguna cuenta. Si una cuenta ha sido bloqueada, se desbloqueará automáticamente (sin intervención manual de un administrador) después de 30 minutos, pero debemos evitar bloquear `CUALQUIER` cuenta a toda costa.

PowerView también es muy útil para esto:

### Using PowerView

```r
PS C:\htb> import-module .\PowerView.ps1
PS C:\htb> Get-DomainPolicy

Unicode        : @{Unicode=yes}
SystemAccess   : @{MinimumPasswordAge=1; MaximumPasswordAge=-1; MinimumPasswordLength=8; PasswordComplexity=1;
                 PasswordHistorySize=24; LockoutBadCount=5; ResetLockoutCount=30; LockoutDuration=30;
                 RequireLogonToChangePassword=0; ForceLogoffWhenHourExpire=0; ClearTextPassword=0;
                 LSAAnonymousNameLookup=0}
KerberosPolicy : @{MaxTicketAge=10; MaxRenewAge=7; MaxServiceAge=600; MaxClockSkew=5; TicketValidateClient=1}
Version        : @{signature="$CHICAGO$"; Revision=1}
RegistryValues : @{MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=System.Object[]}
Path           : \\INLANEFREIGHT.LOCAL\sysvol\INLANEFREIGHT.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHI
                 NE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
GPOName        : {31B2F340-016D-11D2-945F-00C04FB984F9}
GPODisplayName : Default Domain Policy
```

PowerView nos dio la misma salida que nuestro comando `net accounts`, solo en un formato diferente, pero también reveló que la complejidad de la contraseña está habilitada (`PasswordComplexity=1`).

Al igual que con Linux, tenemos muchas herramientas a nuestra disposición para recuperar la política de contraseñas mientras estamos en un sistema Windows, ya sea nuestro sistema de ataque o un sistema proporcionado por el cliente. PowerView/SharpView siempre son buenas opciones, al igual que CrackMapExec, SharpMapExec y otras. La elección de herramientas depende del objetivo de la evaluación, las consideraciones de sigilo, cualquier antivirus o EDR en su lugar, y otras posibles restricciones en el host objetivo. Cubramos algunos ejemplos.

---

## Analyzing the Password Policy

Ahora hemos obtenido la política de contraseñas de varias maneras. Revisemos la política para el dominio INLANEFREIGHT.LOCAL pieza por pieza.

- La longitud mínima de la contraseña es 8 (8 es muy común, pero hoy en día, estamos viendo más y más organizaciones que hacen cumplir una contraseña de 10-14 caracteres, lo que puede eliminar algunas opciones de contraseña para nosotros, pero no mitiga completamente el vector de password spraying)
- El umbral de bloqueo de la cuenta es 5 (no es raro ver un umbral más bajo como 3 o incluso sin umbral de bloqueo configurado)
- La duración del bloqueo es de 30 minutos (esto puede ser mayor o menor dependiendo de la organización), por lo que si accidentalmente bloqueamos (¡evitar!!) una cuenta, se desbloqueará después de la ventana de 30 minutos
- Las cuentas se desbloquean automáticamente (en

 algunas organizaciones, un administrador debe desbloquear manualmente la cuenta). Nunca queremos bloquear cuentas mientras realizamos password spraying, pero especialmente queremos evitar bloquear cuentas en una organización donde un administrador tendría que intervenir y desbloquear cientos (o miles) de cuentas a mano/mediante script
- La complejidad de la contraseña está habilitada, lo que significa que un usuario debe elegir una contraseña con 3/4 de lo siguiente: una letra mayúscula, letra minúscula, número, carácter especial (`Password1` o `Welcome1` cumplirían con el requisito de "complejidad" aquí, pero aún son claramente contraseñas débiles).

La política de contraseñas predeterminada cuando se crea un nuevo dominio es la siguiente, y hay muchas organizaciones que nunca cambiaron esta política:

| Política                                                        | Valor predeterminado |
| --------------------------------------------------------------- | -------------------- |
| Aplicar historial de contraseñas                                | 24 días              |
| Edad máxima de la contraseña                                    | 42 días              |
| Edad mínima de la contraseña                                    | 1 día                |
| Longitud mínima de la contraseña                                | 7                    |
| Las contraseñas deben cumplir con los requisitos de complejidad | Habilitado           |
| Almacenar contraseñas utilizando cifrado reversible             | Deshabilitado        |
| Duración del bloqueo de la cuenta                               | No establecido       |
| Umbral de bloqueo de la cuenta                                  | 0                    |
| Restablecer el contador de bloqueo de la cuenta después de      | No establecido       |

---

## Next Steps

Ahora que tenemos la política de contraseñas en mano, necesitamos crear una lista de usuarios objetivo para realizar nuestro ataque de password spraying. Recuerda que a veces no podremos obtener la política de contraseñas si estamos realizando password spraying externo (o si estamos en una evaluación interna y no podemos recuperar la política utilizando ninguno de los métodos mostrados aquí). En estos casos, `DEBEMOS` ejercer extrema precaución para no bloquear cuentas. Siempre podemos pedir a nuestro cliente su política de contraseñas si el objetivo es una evaluación lo más completa posible. Si pedir la política no se ajusta a las expectativas de la evaluación o el cliente no quiere proporcionarla, debemos realizar uno, como máximo dos, intentos de password spraying (independientemente de si somos internos o externos) y esperar más de una hora entre intentos si decidimos intentar dos. Aunque la mayoría de las organizaciones tendrán un umbral de bloqueo de 5 intentos de contraseña incorrectos, una duración de bloqueo de 30 minutos y las cuentas se desbloquearán automáticamente, no siempre podemos contar con que esto sea lo normal. He visto muchas organizaciones con un umbral de bloqueo de 3, requiriendo que un administrador intervenga y desbloquee las cuentas manualmente.

`¡No queremos ser el pentester que bloquea todas las cuentas en la organización!`

Ahora preparémonos para lanzar nuestros ataques de password spraying recopilando una lista de usuarios objetivo.