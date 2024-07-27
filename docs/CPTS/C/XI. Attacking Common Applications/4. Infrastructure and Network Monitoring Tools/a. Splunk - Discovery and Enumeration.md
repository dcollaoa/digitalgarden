Splunk es una herramienta de análisis de logs utilizada para recopilar, analizar y visualizar datos. Aunque no fue diseñada originalmente como una herramienta SIEM, Splunk se utiliza a menudo para el monitoreo de seguridad y análisis empresarial. Las implementaciones de Splunk suelen albergar datos sensibles y pueden proporcionar una gran cantidad de información para un atacante si se ven comprometidas. Históricamente, Splunk no ha sufrido muchas vulnerabilidades conocidas, aparte de una vulnerabilidad de divulgación de información (CVE-2018-11409) y una vulnerabilidad de ejecución remota de código autenticado en versiones muy antiguas (CVE-2011-4642). Aquí hay algunos [detalles](https://www.splunk.com/en_us/customers.html) sobre Splunk:

- Splunk fue fundada en 2003, se volvió rentable por primera vez en 2009 y tuvo su oferta pública inicial (IPO) en 2012 en NASDAQ bajo el símbolo SPLK.
- Splunk tiene más de 7,500 empleados y un ingreso anual de casi $2.4 mil millones.
- En 2020, Splunk fue nombrada en la lista Fortune 1000.
- Los clientes de Splunk incluyen 92 compañías en la lista Fortune 100.
- [Splunkbase](https://splunkbase.splunk.com/) permite a los usuarios de Splunk descargar aplicaciones y complementos para Splunk. A partir de 2021, hay más de 2,000 aplicaciones disponibles.

A menudo veremos Splunk durante nuestras evaluaciones, especialmente en grandes entornos corporativos durante pruebas de penetración internas. Lo hemos visto expuesto externamente, pero esto es más raro. Splunk no sufre muchas vulnerabilidades explotables y es rápido para parchear cualquier problema. El mayor enfoque de Splunk durante una evaluación sería la autenticación débil o nula, porque el acceso de administrador a Splunk nos da la capacidad de desplegar aplicaciones personalizadas que pueden usarse para comprometer rápidamente un servidor Splunk y posiblemente otros hosts en la red, dependiendo de cómo esté configurado Splunk.

---

## Discovery/Footprinting

Splunk es prevalente en redes internas y a menudo se ejecuta como root en sistemas Linux o SYSTEM en sistemas Windows. Aunque no es común, a veces podemos encontrar Splunk expuesto externamente. Imaginemos que descubrimos una instancia olvidada de Splunk en nuestro informe de Aquatone que desde entonces se ha convertido automáticamente a la versión gratuita, que no requiere autenticación. Como aún no hemos conseguido un punto de apoyo en la red interna, centremos nuestra atención en Splunk y veamos si podemos convertir este acceso en RCE.

El servidor web de Splunk se ejecuta por defecto en el puerto 8000. En versiones más antiguas de Splunk, las credenciales predeterminadas son `admin:changeme`, que se muestran convenientemente en la página de inicio de sesión.

![image](https://academy.hackthebox.com/storage/modules/113/changme.png)

La última versión de Splunk establece credenciales durante el proceso de instalación. Si las credenciales predeterminadas no funcionan, vale la pena verificar contraseñas débiles comunes como `admin`, `Welcome`, `Welcome1`, `Password123`, etc.

![image](https://academy.hackthebox.com/storage/modules/113/splunk_login.png)

Podemos descubrir Splunk con un rápido escaneo de servicios de Nmap. Aquí podemos ver que Nmap identificó el servicio `Splunkd httpd` en el puerto 8000 y el puerto 8089, el puerto de gestión de Splunk para la comunicación con la API REST de Splunk.

```r
sudo nmap -sV 10.129.201.50

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-22 08:43 EDT
Nmap scan report for 10.129.201.50
Host is up (0.11s latency).
Not shown: 991 closed ports
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp open  ssl/http      Splunkd httpd
8080/tcp open  http          Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
8089/tcp open  ssl/http      Splunkd httpd
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.22 seconds
```

---

## Enumeration

La prueba de Splunk Enterprise se convierte en una versión gratuita después de 60 días, que no requiere autenticación. No es raro que los administradores de sistemas instalen una prueba de Splunk para probarla, que luego se olvida. Esto se convertirá automáticamente en la versión gratuita que no tiene ningún tipo de autenticación, introduciendo un agujero de seguridad en el entorno. Algunas organizaciones pueden optar por la versión gratuita debido a restricciones presupuestarias, sin comprender completamente las implicaciones de no tener gestión de usuarios/roles.

![image](https://academy.hackthebox.com/storage/modules/113/license_group.png)

Una vez que iniciamos sesión en Splunk (o hemos accedido a una instancia de Splunk Free), podemos navegar por los datos, ejecutar informes, crear paneles, instalar aplicaciones desde la biblioteca de Splunkbase e instalar aplicaciones personalizadas.

![](https://academy.hackthebox.com/storage/modules/113/splunk_home.png)

Splunk tiene múltiples formas de ejecutar código, como aplicaciones Django del lado del servidor, endpoints REST, entradas de scripts y scripts de alerta. Un método común para obtener ejecución remota de código en un servidor Splunk es mediante el uso de una entrada de script. Estas están diseñadas para ayudar a integrar Splunk con fuentes de datos como APIs o servidores de archivos que requieren métodos personalizados para acceder. Las entradas de script están destinadas a ejecutar estos scripts, con STDOUT proporcionado como entrada a Splunk.

Dado que Splunk se puede instalar en hosts Windows o Linux, se pueden crear entradas de script para ejecutar scripts Bash, PowerShell o Batch. Además, cada instalación de Splunk viene con Python instalado, por lo que se pueden ejecutar scripts Python en cualquier sistema Splunk. Una forma rápida de obtener RCE es creando una entrada de script que le indique a Splunk que ejecute un script de shell inverso en Python. Cubriremos esto en la siguiente sección.

Aparte de esta funcionalidad incorporada, Splunk ha sufrido varias vulnerabilidades públicas a lo largo de los años, como este [SSRF](https://www.exploit-db.com/exploits/40895) que podría usarse para obtener acceso no autorizado a la API REST de Splunk. En el momento de escribir este artículo, Splunk tiene [47](https://www.cvedetails.com/vulnerability-list/vendor_id-10963/Splunk.html) CVEs. Si realizamos un escaneo de vulnerabilidades contra Splunk durante una prueba de penetración, a menudo veremos muchas vulnerabilidades no explotables devueltas. Por eso es importante entender cómo abusar de la funcionalidad incorporada.