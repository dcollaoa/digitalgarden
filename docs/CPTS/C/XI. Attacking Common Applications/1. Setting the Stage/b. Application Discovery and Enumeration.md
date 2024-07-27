Para gestionar eficazmente su red, una organización debe mantener (y actualizar continuamente) un inventario de activos que incluya todos los dispositivos conectados a la red (servers, workstations, appliances de red, etc.), software instalado y aplicaciones en uso en todo el entorno. Si una organización no está segura de lo que está presente en su red, ¿cómo sabrá qué proteger y qué posibles agujeros existen? La organización debe saber si las aplicaciones están instaladas localmente o son alojadas por un tercero, su nivel de parche actual, si están al final de su vida útil o cerca de ello, ser capaz de detectar cualquier aplicación no autorizada en la red (o "shadow IT"), y tener suficiente visibilidad de cada aplicación para asegurarse de que estén adecuadamente protegidas con contraseñas fuertes (no predeterminadas), y, idealmente, que la autenticación multifactor esté habilitada. Ciertas aplicaciones tienen portales administrativos que pueden restringirse para ser accesibles solo desde direcciones IP específicas o desde el mismo host (localhost).

La realidad es que muchas organizaciones no conocen todo lo que hay en su red, y algunas tienen muy poca visibilidad, y podemos ayudarlas con esto. La enumeración que realizamos puede ser muy beneficiosa para nuestros clientes para ayudarlos a mejorar o comenzar a construir un inventario de activos. Es muy probable que identifiquemos aplicaciones que han sido olvidadas, versiones demo de software que quizás han expirado sus licencias de prueba y se han convertido a una versión que no requiere autenticación (en el caso de Splunk), aplicaciones con credenciales predeterminadas o débiles, aplicaciones no autorizadas o mal configuradas, y aplicaciones que sufren de vulnerabilidades públicas. Podemos proporcionar estos datos a nuestros clientes como una combinación de los hallazgos en nuestros informes (por ejemplo, una aplicación con credenciales predeterminadas `admin:admin`), como apéndices, tales como una lista de servicios identificados mapeados a hosts, o datos de escaneo complementarios. Incluso podemos ir un paso más allá y educar a nuestros clientes sobre algunas de las herramientas que usamos diariamente para que puedan comenzar a realizar recon periódicamente y de forma proactiva en sus redes y encontrar brechas antes de que los pentesters, o peor, los atacantes, las encuentren primero.

Como penetration testers, necesitamos tener fuertes habilidades de enumeración y ser capaces de obtener una "visión del terreno" de cualquier red comenzando con muy poca o ninguna información (black box discovery o solo un conjunto de rangos CIDR). Típicamente, cuando nos conectamos a una red, comenzaremos con un ping sweep para identificar "live hosts". A partir de ahí, usualmente comenzaremos con un escaneo de puertos dirigido y, eventualmente, un escaneo de puertos más profundo para identificar servicios en ejecución. En una red con cientos o miles de hosts, estos datos de enumeración pueden volverse difíciles de manejar. Digamos que realizamos un escaneo de puertos con Nmap para identificar servicios web comunes como:

### Nmap - Web Discovery

```bash
nmap -p 80,443,8000,8080,8180,8888,1000 --open -oA web_discovery -iL scope_list
```

Podemos encontrar una enorme cantidad de hosts con servicios ejecutándose en los puertos 80 y 443 solamente. ¿Qué hacemos con estos datos? Revisar los datos de enumeración a mano en un entorno grande sería demasiado laborioso, especialmente dado que la mayoría de las evaluaciones están bajo restricciones de tiempo.

Afortunadamente para nosotros, existen varias herramientas excelentes que pueden ayudar enormemente en este proceso. Dos herramientas fenomenales que todo tester debería tener en su arsenal son [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) y [Aquatone](https://github.com/michenriksen/aquatone). Ambas herramientas pueden alimentarse con la salida XML cruda de Nmap (Aquatone también puede tomar XML de Masscan; EyeWitness puede tomar salida XML de Nessus) y usarse para inspeccionar rápidamente todos los hosts que ejecutan aplicaciones web y tomar capturas de pantalla de cada una. Las capturas de pantalla luego se ensamblan en un informe que podemos revisar en el navegador web para evaluar la superficie de ataque web.

Estas capturas de pantalla pueden ayudarnos a reducir potencialmente cientos de hosts y construir una lista más dirigida de aplicaciones en las que deberíamos gastar más tiempo enumerando y atacando. Estas herramientas están disponibles tanto para Windows como para Linux, por lo que podemos utilizarlas en cualquier entorno que elijamos para nuestra caja de ataque en un entorno dado. Vamos a repasar algunos ejemplos de cada uno para crear un inventario de aplicaciones presentes en el dominio `INLANEFREIGHT.LOCAL`.

---

## Getting Organized

Aunque cubriremos la toma de notas, informes y documentación en un módulo separado, vale la pena aprovechar la oportunidad para seleccionar una aplicación de toma de notas si aún no lo hemos hecho y comenzar a configurarla para registrar mejor los datos que estamos recopilando en esta fase. El módulo [Getting Started](https://academy.hackthebox.com/course/preview/getting-started) discute varias aplicaciones de toma de notas. Si no has elegido una en este momento, sería un excelente momento para comenzar. Herramientas como OneNote, Evernote, Notion, Cherrytree, etc., son todas buenas opciones, y todo se reduce a la preferencia personal. Independientemente de la herramienta que elijas, deberíamos estar trabajando en nuestra metodología de toma de notas en este punto y creando plantillas que podamos usar en nuestra herramienta de elección configuradas para cada tipo de evaluación.

Para esta sección, dividiría la sección `Enumeration & Discovery` de mi cuaderno en una sección separada `Application Discovery`. Aquí crearía subsecciones para el scope, scans (Nmap, Nessus, Masscan, etc.), capturas de pantalla de aplicaciones, y hosts interesantes/notables para profundizar más adelante. Es importante sellar con fecha y hora cada escaneo que realizamos y guardar toda la salida y la sintaxis exacta del escaneo que se realizó y los hosts objetivo. Esto puede ser útil más adelante si el cliente tiene alguna pregunta sobre la actividad que vieron durante la evaluación. Estar organizados desde el principio y mantener registros y notas detalladas nos ayudará enormemente con el informe final. Típicamente configuro el esqueleto del informe al comienzo de la evaluación junto con mi cuaderno para poder comenzar a llenar ciertas secciones del informe mientras espero que termine un escaneo. Todo esto ahorrará tiempo al final del compromiso, nos dejará más tiempo para las cosas divertidas (¡probar configuraciones incorrectas y exploits!), y garantizará que seamos lo más minuciosos posible.

Un ejemplo de estructura en OneNote (también aplicable a otras herramientas) puede verse como lo siguiente para la fase de discovery:

`External Penetration Test - <Client Name>`

- `Scope` (incluyendo direcciones IP/rangos dentro del scope, URLs, cualquier host frágil, marcos de tiempo de prueba y cualquier limitación u otra información relativa que necesitemos a mano)
- `Client Points of Contact`
- `Credentials`
- `Discovery/Enumeration`
  - `Scans`
  - `Live hosts`
- `Application Discovery`
  - `Scans`
  - `Interesting/Notable Hosts`
- `Exploitation`
  - `<Hostname or IP>`
  - `<Hostname or IP>`
- `Post-Exploitation`
  - `<Hostname or IP>`
  - `<Hostname or IP>`

Nos referiremos a esta estructura a lo largo del módulo, por lo que sería un ejercicio muy beneficioso replicarla y registrar todo nuestro trabajo en este módulo como si estuviéramos trabajando en un compromiso real. Esto nos ayudará a refinar nuestra metodología de documentación, una habilidad esencial para un penetration tester exitoso. Tener notas a las que referirnos de cada sección será útil cuando lleguemos a las tres evaluaciones de habilidades al final del módulo y será extremadamente útil a medida que avancemos en la ruta de `Penetration Tester`.

---

## Initial Enumeration

Supongamos que nuestro cliente nos proporcionó el siguiente scope:

```plaintext
app.inlanefreight.local
dev.inlanefreight.local
drupal-dev.inlanefreight.local
drupal-qa.inlanefreight.local
drupal-acc.inlanefreight.local
drupal.inlanefreight.local
blog-dev.inlanefreight.local
blog.inlanefreight.local
app-dev.inlanefreight.local
jenkins-dev.inlanefreight.local
jenkins.inlanefreight.local
web01.inlanefreight.local
gitlab-dev.inlanefreight.local
gitlab.inlanefreight.local
support-dev.inlanefreight.local
support.inlanefreight.local
inlanefreight.local
10.129.201.50
```

Podemos comenzar con un escaneo de Nmap de puertos web comunes. Típicamente haré un escaneo inicial con puertos `80,443,8000,8080,8180,8888,10000` y luego ejecutaré EyeWitness o Aquatone (o ambos dependiendo de los resultados del primero) contra este escaneo inicial. Mientras reviso el informe de capturas de pantalla de los puertos más comunes, puedo ejecutar un escaneo más exhaustivo de Nmap contra los 10,000 puertos principales o todos los puertos TCP, dependiendo del tamaño del scope. Dado que la enumeración es un proceso iterativo, ejecutaremos una herramienta de captura de pantalla web contra cualquier escaneo posterior de Nmap que realicemos para asegurar la máxima cobertura.

En una prueba de

 penetración de alcance completo no invasiva, usualmente también ejecutaré un escaneo de Nessus para darle al cliente el mayor valor por su dinero, pero debemos ser capaces de realizar evaluaciones sin depender de herramientas de escaneo. Aunque la mayoría de las evaluaciones están limitadas por el tiempo (y a menudo no están adecuadamente definidas para el tamaño del entorno), podemos proporcionar el máximo valor a nuestros clientes estableciendo una metodología de enumeración repetible y exhaustiva que se pueda aplicar a todos los entornos que cubrimos. Necesitamos ser eficientes durante la etapa de recopilación de información/descubrimiento sin tomar atajos que podrían dejar fallas críticas sin descubrir. La metodología y las herramientas preferidas de cada uno variarán un poco, y debemos esforzarnos por crear una que funcione bien para nosotros mientras aún llegamos al mismo objetivo final.

Todos los escaneos que realizamos durante un compromiso no invasivo son para reunir datos como insumos para nuestra validación manual y proceso de pruebas manuales. No debemos confiar únicamente en los escáneres, ya que el elemento humano en la prueba de penetración es esencial. A menudo encontramos las vulnerabilidades y configuraciones incorrectas más únicas y severas solo a través de pruebas manuales minuciosas.

Vamos a profundizar en la lista de scope mencionada anteriormente con un escaneo de Nmap que típicamente descubrirá la mayoría de las aplicaciones web en un entorno. Por supuesto, realizaremos escaneos más profundos más adelante, pero esto nos dará un buen punto de partida.

Nota: No todos los hosts en la lista de scope anterior serán accesibles al iniciar el objetivo a continuación. Habrá ejercicios separados y similares al final de esta sección para reproducir gran parte de lo que se muestra aquí.

```bash
sudo nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-07 21:49 EDT
Stats: 0:00:07 elapsed; 1 hosts completed (4 up), 4 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 81.24% done; ETC: 21:49 (0:00:01 remaining)

Nmap scan report for app.inlanefreight.local (10.129.42.195)
Host is up (0.12s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for app-dev.inlanefreight.local (10.129.201.58)
Host is up (0.12s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt
8009/tcp open  ajp13
8080/tcp open  http-proxy
8180/tcp open  unknown
8888/tcp open  sun-answerbook

Nmap scan report for gitlab-dev.inlanefreight.local (10.129.201.88)
Host is up (0.12s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8081/tcp open  blackice-icecap

Nmap scan report for 10.129.201.50
Host is up (0.13s latency).
Not shown: 991 closed ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
5357/tcp open  wsdapi
8000/tcp open  http-alt
8080/tcp open  http-proxy
8089/tcp open  unknown

<SNIP>
```

Como podemos ver, identificamos varios hosts que ejecutan servidores web en varios puertos. A partir de los resultados, podemos inferir que uno de los hosts es Windows y el resto son Linux (pero no podemos estar 100% seguros en esta etapa). Presta especial atención a los nombres de los hosts también. En este laboratorio, estamos utilizando Vhosts para simular los subdominios de una empresa. Los hosts con `dev` como parte del FQDN valen la pena ser anotados, ya que pueden estar ejecutando características no probadas o tener cosas como el modo de depuración habilitado. A veces, los nombres de los hosts no nos dirán mucho, como `app.inlanefreight.local`. Podemos inferir que es un servidor de aplicaciones, pero necesitaríamos realizar una mayor enumeración para identificar qué aplicación(es) están ejecutando.

También querríamos agregar `gitlab-dev.inlanefreight.local` a nuestra lista de "hosts interesantes" para profundizar una vez que completemos la fase de discovery. Podemos acceder a repos públicos de Git que podrían contener información sensible como credenciales o pistas que nos lleven a otros subdominios/Vhosts. No es raro encontrar instancias de Gitlab que nos permitan registrar un usuario sin requerir la aprobación del administrador para activar la cuenta. Podemos encontrar repos adicionales después de iniciar sesión. También valdría la pena revisar commits anteriores para obtener datos como credenciales, lo que cubriremos con más detalle más adelante en este módulo cuando profundicemos en Gitlab.

Enumerar uno de los hosts más a fondo utilizando un escaneo de servicios de Nmap (`-sV`) contra los 1,000 puertos principales predeterminados puede decirnos más sobre lo que se está ejecutando en el servidor web.

```bash
sudo nmap --open -sV 10.129.201.50

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-07 21:58 EDT
Nmap scan report for 10.129.201.50
Host is up (0.13s latency).
Not shown: 991 closed ports
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp open  http          Splunkd httpd
8080/tcp open  http          Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
8089/tcp open  ssl/http      Splunkd httpd (free license; remote login disabled)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.63 seconds
```

A partir de la salida anterior, podemos ver que un servidor web IIS se está ejecutando en el puerto predeterminado 80, y parece que `Splunk` está ejecutándose en los puertos 8000/8089, mientras que `PRTG Network Monitor` está presente en el puerto 8080. Si estuviéramos en un entorno de tamaño mediano a grande, este tipo de enumeración sería ineficiente. Podría resultar en que pasáramos por alto una aplicación web que podría ser crítica para el éxito del compromiso.

---

## Using EyeWitness

Primero está EyeWitness. Como se mencionó antes, EyeWitness puede tomar la salida XML tanto de Nmap como de Nessus y crear un informe con capturas de pantalla de cada aplicación web presente en los varios puertos utilizando Selenium. También puede dar un paso más allá y categorizar las aplicaciones donde sea posible, identificarlas, y sugerir credenciales predeterminadas basadas en la aplicación. También puede recibir una lista de direcciones IP y URLs y ser configurado para pre-pend `http://` y `https://` al frente de cada una. Realizará la resolución de DNS para IPs y se le puede dar un conjunto específico de puertos a los que intentar conectarse y tomar capturas de pantalla.

Podemos instalar EyeWitness vía apt:

```bash
sudo apt install eyewitness
```

o clonar el [repositorio](https://github.com/FortyNorthSecurity/EyeWitness), navegar al directorio `Python/setup` y ejecutar el script instalador `setup.sh`. EyeWitness también puede ejecutarse desde un contenedor Docker, y hay una versión para Windows disponible que puede ser compilada utilizando Visual Studio.

Ejecutar `eyewitness -h` nos mostrará las opciones disponibles:

```bash
eyewitness -h

usage: EyeWitness.py [--web] [-f Filename] [-x Filename.xml]
                     [--single Single URL] [--no-dns] [--timeout Timeout]
                     [--jitter # of Seconds] [--delay # of Seconds]
                     [--threads # of Threads]
                     [--max-retries Max retries on a timeout]
                     [-d Directory Name] [--results Hosts Per Page]
                     [--no-prompt] [--user-agent User Agent]
                     [--difference Difference Threshold]
                     [--proxy-ip 127.0.0.1] [--proxy-port 808

0]
                     [--proxy-type socks5] [--show-selenium] [--resolve]
                     [--add-http-ports ADD_HTTP_PORTS]
                     [--add-https-ports ADD_HTTPS_PORTS]
                     [--only-ports ONLY_PORTS] [--prepend-https]
                     [--selenium-log-path SELENIUM_LOG_PATH] [--resume ew.db]
                     [--ocr]

EyeWitness is a tool used to capture screenshots from a list of URLs

Protocols:
  --web                 HTTP Screenshot using Selenium

Input Options:
  -f Filename           Line-separated file containing URLs to capture
  -x Filename.xml       Nmap XML or .Nessus file
  --single Single URL   Single URL/Host to capture
  --no-dns              Skip DNS resolution when connecting to websites

Timing Options:
  --timeout Timeout     Maximum number of seconds to wait while requesting a
                        web page (Default: 7)
  --jitter # of Seconds
                        Randomize URLs and add a random delay between requests
  --delay # of Seconds  Delay between the opening of the navigator and taking
                        the screenshot
  --threads # of Threads
                        Number of threads to use while using file based input
  --max-retries Max retries on timeouts

<SNIP>
```

Vamos a ejecutar la opción predeterminada `--web` para tomar capturas de pantalla utilizando la salida XML de Nmap del escaneo de discovery como entrada.

```bash
eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness

################################################################################
#                                  EyeWitness                                  #
################################################################################
#           FortyNorth Security - https://www.fortynorthsecurity.com           #
################################################################################

Starting Web Requests (26 Hosts)
Attempting to screenshot http://app.inlanefreight.local
Attempting to screenshot http://app-dev.inlanefreight.local
Attempting to screenshot http://app-dev.inlanefreight.local:8000
Attempting to screenshot http://app-dev.inlanefreight.local:8080
Attempting to screenshot http://gitlab-dev.inlanefreight.local
Attempting to screenshot http://10.129.201.50
Attempting to screenshot http://10.129.201.50:8000
Attempting to screenshot http://10.129.201.50:8080
Attempting to screenshot http://dev.inlanefreight.local
Attempting to screenshot http://jenkins-dev.inlanefreight.local
Attempting to screenshot http://jenkins-dev.inlanefreight.local:8000
Attempting to screenshot http://jenkins-dev.inlanefreight.local:8080
Attempting to screenshot http://support-dev.inlanefreight.local
Attempting to screenshot http://drupal-dev.inlanefreight.local
[*] Hit timeout limit when connecting to http://10.129.201.50:8000, retrying
Attempting to screenshot http://jenkins.inlanefreight.local
Attempting to screenshot http://jenkins.inlanefreight.local:8000
Attempting to screenshot http://jenkins.inlanefreight.local:8080
Attempting to screenshot http://support.inlanefreight.local
[*] Completed 15 out of 26 services
Attempting to screenshot http://drupal-qa.inlanefreight.local
Attempting to screenshot http://web01.inlanefreight.local
Attempting to screenshot http://web01.inlanefreight.local:8000
Attempting to screenshot http://web01.inlanefreight.local:8080
Attempting to screenshot http://inlanefreight.local
Attempting to screenshot http://drupal-acc.inlanefreight.local
Attempting to screenshot http://drupal.inlanefreight.local
Attempting to screenshot http://blog-dev.inlanefreight.local
Finished in 57.859838008880615 seconds

[*] Done! Report written in the /home/mrb3n/Projects/inlanfreight/inlanefreight_eyewitness folder!
Would you like to open the report now? [Y/n]
```

---

## Using Aquatone

[Aquatone](https://github.com/michenriksen/aquatone), como se mencionó antes, es similar a EyeWitness y puede tomar capturas de pantalla cuando se le proporciona un archivo `.txt` de hosts o un archivo `.xml` de Nmap con el flag `-nmap`. Podemos compilar Aquatone por nuestra cuenta o descargar un binario precompilado. Después de descargar el binario, solo necesitamos extraerlo y estamos listos para ir.

```bash
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
```

```bash
unzip aquatone_linux_amd64_1.7.0.zip 

Archive:  aquatone_linux_amd64_1.7.0.zip
  inflating: aquatone                
  inflating: README.md               
  inflating: LICENSE.txt 
```

Podemos moverlo a una ubicación en nuestro `$PATH` como `/usr/local/bin` para poder llamar a la herramienta desde cualquier lugar o simplemente dejar el binario en nuestro directorio de trabajo (digamos, de scans). Es preferencia personal, pero típicamente es más eficiente construir nuestras VMs de ataque con la mayoría de las herramientas disponibles para usarlas sin tener que cambiar constantemente de directorios o llamarlas desde otros directorios.

```bash
echo $PATH

/home/mrb3n/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```

En este ejemplo, proporcionamos a la herramienta la misma salida `web_discovery.xml` de Nmap especificando el flag `-nmap`, y nos ponemos en marcha.

```bash
cat web_discovery.xml | ./aquatone -nmap

aquatone v1.7.0 started at 2021-09-07T22:31:03-04:00

Targets    : 65
Threads    : 6
Ports      : 80, 443, 8000, 8080, 8443
Output dir : .

http://web01.inlanefreight.local:8000/: 403 Forbidden
http://app.inlanefreight.local/: 200 OK
http://jenkins.inlanefreight.local/: 403 Forbidden
http://app-dev.inlanefreight.local/: 200 
http://app-dev.inlanefreight.local/: 200 
http://app-dev.inlanefreight.local:8000/: 403 Forbidden
http://jenkins.inlanefreight.local:8000/: 403 Forbidden
http://web01.inlanefreight.local:8080/: 200 
http://app-dev.inlanefreight.local:8000/: 403 Forbidden
http://10.129.201.50:8000/: 200 OK

<SNIP>

http://web01.inlanefreight.local:8000/: screenshot successful
http://app.inlanefreight.local/: screenshot successful
http://app-dev.inlanefreight.local/: screenshot successful
http://jenkins.inlanefreight.local/: screenshot successful
http://app-dev.inlanefreight.local/: screenshot successful
http://app-dev.inlanefreight.local:8000/: screenshot successful
http://jenkins.inlanefreight.local:8000/: screenshot successful
http://app-dev.inlanefreight.local:8000/: screenshot successful
http://app-dev.inlanefreight.local:8080/: screenshot successful
http://app.inlanefreight.local/: screenshot successful

<SNIP>

Calculating page structures... done
Clustering similar pages... done
Generating HTML report... done

Writing session file...Time:
 - Started at  : 2021-09-07T22:31:03-04:00
 - Finished at : 2021-09-07T22:31:36-04:00
 - Duration    : 33s

Requests:
 - Successful : 65
 - Failed     : 0

 - 2xx : 47
 - 3xx : 0
 - 4xx : 18
 - 5xx : 0

Screenshots:
 - Successful : 65
 - Failed     : 0

Wrote HTML report to: aquatone_report.html
```

---

## Interpreting the Results

Incluso con los 26 hosts anteriores, este informe nos ahorrará tiempo. Ahora imagina un entorno con 500 o 5,000 hosts! Después de abrir el informe, vemos que el informe está organizado en categorías, con `High Value Targets` siendo primero y típicamente los hosts más "jugosos" para atacar. He ejecutado EyeWitness en entornos muy grandes y generado informes con cientos de páginas que toman horas para revisar. A menudo, los informes muy grandes tendrán hosts interesantes enterrados profundamente dentro de ellos, por lo que vale la pena revisar todo el informe y revisar/investigar cualquier aplicación con la que no estemos familiarizados. Encontré la aplicación `ManageEngine OpManager` mencionada en la sección de introducción enterrada profundamente en un informe muy grande durante una prueba de penetración externa. Esta instancia estaba configurada con las credenciales predeterminadas

 `admin:admin` y dejada completamente abierta a Internet. Pude iniciar sesión y lograr la ejecución de código ejecutando un script de PowerShell. La aplicación OpManager se estaba ejecutando en el contexto de una cuenta de Domain Admin lo que llevó a la toma de control completa de la red interna.

En el informe a continuación, estaría inmediatamente emocionado de ver Tomcat en cualquier evaluación (pero especialmente durante una prueba de penetración externa) y probaría las credenciales predeterminadas en los endpoints `/manager` y `/host-manager`. Si podemos acceder a cualquiera, podemos subir un archivo WAR malicioso y lograr la ejecución de código remoto en el host subyacente utilizando [JSP code](https://en.wikipedia.org/wiki/Jakarta_Server_Pages). Más sobre esto más adelante en el módulo.

![image](https://academy.hackthebox.com/storage/modules/113/eyewitness4.png)

Continuando con el informe, parece que el sitio web principal `http://inlanefreight.local` está siguiente. Las aplicaciones web personalizadas siempre valen la pena ser probadas ya que pueden contener una amplia variedad de vulnerabilidades. Aquí también estaría interesado en ver si el sitio web está ejecutando un CMS popular como WordPress, Joomla o Drupal. La siguiente aplicación, `http://support-dev.inlanefreight.local`, es interesante porque parece estar ejecutando [osTicket](https://osticket.com/), que ha sufrido varias vulnerabilidades severas a lo largo de los años. Los sistemas de tickets de soporte son de particular interés porque podríamos iniciar sesión y obtener acceso a información sensible. Si la ingeniería social está en el scope, podríamos interactuar con el personal de soporte al cliente o incluso manipular el sistema para registrar una dirección de correo válida para el dominio de la empresa que podríamos usar para obtener acceso a otros servicios.

Esta última pieza fue demostrada en la caja de lanzamiento semanal de HTB [Delivery](https://0xdf.gitlab.io/2021/05/22/htb-delivery.html) por [IppSec](https://www.youtube.com/watch?v=gbs43E71mFM). Esta caja en particular vale la pena estudiarla ya que muestra lo que es posible explorando la funcionalidad incorporada de ciertas aplicaciones comunes. Cubriremos osTicket más en profundidad más adelante en este módulo.

![image](https://academy.hackthebox.com/storage/modules/113/eyewitness3.png)

Durante una evaluación, continuaría revisando el informe, anotando hosts interesantes, incluyendo la URL y el nombre/versión de la aplicación para más adelante. Es importante en este punto recordar que todavía estamos en la fase de recopilación de información, y cada pequeño detalle podría hacer o deshacer nuestra evaluación. No deberíamos ser descuidados y comenzar a atacar hosts de inmediato, ya que podríamos terminar en un callejón sin salida y perder algo crucial más adelante en el informe. Durante una prueba de penetración externa, esperaría ver una mezcla de aplicaciones personalizadas, algunos CMS, quizás aplicaciones como Tomcat, Jenkins y Splunk, portales de acceso remoto como Remote Desktop Services (RDS), endpoints SSL VPN, Outlook Web Access (OWA), O365, quizás algún tipo de página de inicio de sesión de dispositivo de red, etc.

Tu experiencia puede variar, y a veces nos encontraremos con aplicaciones que absolutamente no deberían estar expuestas, como una página única con un botón de carga de archivos que encontré una vez con un mensaje que decía "Please only upload .zip and .tar.gz files". Por supuesto, no hice caso a esta advertencia (ya que esto estaba dentro del alcance durante una prueba de penetración sancionada por el cliente) y procedí a subir un archivo `.aspx` de prueba. Para mi sorpresa, no había ningún tipo de validación del lado del cliente o del back-end, y el archivo parecía subir. Haciendo un rápido brute-forcing de directorios, pude localizar un directorio `/files` que tenía habilitada la lista de directorios, y mi archivo `test.aspx` estaba allí. Desde aquí, procedí a subir una web shell `.aspx` y obtuve un punto de apoyo en el entorno interno. Este ejemplo muestra que no debemos dejar piedra sin remover y que puede haber un tesoro absoluto de datos para nosotros en nuestros datos de discovery de aplicaciones.

Durante una prueba de penetración interna, veremos mucho de lo mismo, pero a menudo también veremos muchas páginas de inicio de sesión de impresoras (que a veces podemos aprovechar para obtener credenciales LDAP en texto claro), portales de inicio de sesión de ESXi y vCenter, portales de inicio de sesión de iLO e iDRAC, una plétora de dispositivos de red, dispositivos IoT, teléfonos IP, repositorios de código internos, SharePoint y portales intranet personalizados, appliances de seguridad, y mucho más.

---

## Moving On

Ahora que hemos trabajado a través de nuestra metodología de discovery de aplicaciones y configurado nuestra estructura de toma de notas, profundicemos en algunas de las aplicaciones más comunes que encontraremos una y otra vez. Ten en cuenta que este módulo no puede cubrir todas las aplicaciones que enfrentaremos. Más bien, nuestro objetivo es cubrir las más prevalentes y aprender sobre vulnerabilidades comunes, configuraciones incorrectas, y abusar de su funcionalidad incorporada.

Puedo garantizar que enfrentarás al menos algunas, si no todas, de estas aplicaciones durante tu carrera como penetration tester. La metodología y la mentalidad de explorar estas aplicaciones son aún más importantes, que desarrollaremos y mejoraremos a lo largo de este módulo y pondremos a prueba durante las evaluaciones de habilidades al final. Muchos testers tienen grandes habilidades técnicas, pero las habilidades blandas como una metodología sólida y repetible junto con organización, atención al detalle, comunicación fuerte, y toma de notas/documentación e informes minuciosos pueden diferenciarnos y ayudar a generar confianza en nuestras habilidades tanto por parte de nuestros empleadores como de nuestros clientes.