Las aplicaciones de cliente pesado con una arquitectura de tres capas tienen una ventaja de seguridad sobre aquellas con una arquitectura de dos capas, ya que evita que el usuario final se comunique directamente con el servidor de la base de datos. Sin embargo, las aplicaciones de tres capas pueden ser susceptibles a ataques web específicos como **SQL Injection** y **Path Traversal**.

Durante una prueba de penetración, es común encontrar una aplicación de cliente pesado que se conecta a un servidor para comunicarse con la base de datos. El siguiente escenario demuestra un caso en el que el tester ha encontrado los siguientes archivos mientras enumeraba un servidor FTP que proporciona acceso a usuarios `anonymous`.

- fatty-client.jar
- note.txt
- note2.txt
- note3.txt

Leyendo el contenido de todos los archivos de texto, se revela que:

- Un servidor ha sido reconfigurado para ejecutarse en el puerto `1337` en lugar de `8000`.
- Esto podría ser una arquitectura de cliente pesado/delgado donde la aplicación cliente aún necesita ser actualizada para usar el nuevo puerto.
- La aplicación cliente depende de `Java 8`.
- Las credenciales de inicio de sesión para la aplicación cliente son `qtc / clarabibi`.

Vamos a ejecutar el archivo `fatty-client.jar` haciendo doble clic en él. Una vez iniciada la aplicación, podemos iniciar sesión usando las credenciales `qtc / clarabibi`.

![err](https://academy.hackthebox.com/storage/modules/113/thick_clients_web/err.png)

Esto no es exitoso y se muestra el mensaje `Connection Error!`. Esto probablemente se debe a que el puerto que apunta a los servidores necesita ser actualizado de `8000` a `1337`. Vamos a capturar y analizar el tráfico de red usando Wireshark para confirmar esto. Una vez iniciado Wireshark, hacemos clic en `Login` nuevamente.

![wireshark](https://academy.hackthebox.com/storage/modules/113/thick_clients_web/wireshark.png)

A continuación se muestra un ejemplo de cómo abordar las solicitudes DNS desde las aplicaciones a tu favor. Verifica el contenido del archivo `C:\Windows\System32\drivers\etc\hosts` donde la IP 172.16.17.114 apunta a fatty.htb y server.fatty.htb.

El cliente intenta conectarse al subdominio `server.fatty.htb`. Vamos a iniciar un símbolo del sistema como administrador y agregar la siguiente entrada al archivo `hosts`.

```r
C:\> echo 10.10.10.174    server.fatty.htb >> C:\Windows\System32\drivers\etc\hosts
```

Inspeccionar el tráfico nuevamente revela que el cliente está intentando conectarse al puerto `8000`.

![port](https://academy.hackthebox.com/storage/modules/113/thick_clients_web/port.png)

El `fatty-client.jar` es un archivo Java Archive, y su contenido puede ser extraído haciendo clic derecho sobre él y seleccionando `Extract files`.

```r
C:\> ls fatty-client\

<SNIP>
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/30/2019  12:10 PM                htb
d-----       10/30/2019  12:10 PM                META-INF
d-----        4/26/2017  12:09 AM                org
------       10/30/2019  12:10 PM           1550 beans.xml
------       10/30/2019  12:10 PM           2230 exit.png
------       10/30/2019  12:10 PM           4317 fatty.p12
------       10/30/2019  12:10 PM            831 log4j.properties
------        4/26/2017  12:08 AM            299 module-info.class
------       10/30/2019  12:10 PM          41645 spring-beans-3.0.xsd
```

Vamos a ejecutar PowerShell como administrador, navegar al directorio extraído y usar el comando `Select-String` para buscar todos los archivos con el puerto `8000`.

```r
C:\> ls fatty-client\ -recurse | Select-String "8000" | Select Path, LineNumber | Format-List

Path       : C:\Users\cybervaca\Desktop\fatty-client\beans.xml
LineNumber : 13
```

Hay una coincidencia en `beans.xml`. Este es un archivo de configuración de **Spring** que contiene metadatos de configuración. Vamos a leer su contenido.

```r
C:\> cat fatty-client\beans.xml

<SNIP>
<!-- Aquí tenemos una inyección basada en constructor, donde Spring inyecta los argumentos necesarios dentro de la función constructor. -->
   <bean id="connectionContext" class = "htb.fatty.shared.connection.ConnectionContext">
      <constructor-arg index="0" value = "server.fatty.htb"/>
      <constructor-arg index="1" value = "8000"/>
   </bean>

<!-- Los siguientes dos beans usan inyección por setter. Para este tipo de inyección, uno necesita definir un constructor por defecto para el objeto (sin argumentos) y uno necesita definir métodos setter para las propiedades. -->
   <bean id="trustedFatty" class = "htb.fatty.shared.connection.TrustedFatty">
      <property name = "keystorePath" value = "fatty.p12"/>
   </bean>

   <bean id="secretHolder" class = "htb.fatty.shared.connection.SecretHolder">
      <property name = "secret" value = "clarabibiclarabibiclarabibi"/>
   </bean>
<SNIP>
```

Vamos a editar la línea `<constructor-arg index="1" value = "8000"/>` y establecer el puerto en `1337`. Leyendo el contenido cuidadosamente, también notamos que el valor del `secret` es `clarabibiclarabibiclarabibi`. Ejecutar la aplicación editada fallará debido a una discrepancia en el digest `SHA-256`. El JAR está firmado, validando los hashes `SHA-256` de cada archivo antes de ejecutarse. Estos hashes están presentes en el archivo `META-INF/MANIFEST.MF`.

```r
C:\> cat fatty-client\META-INF\MANIFEST.MF

Manifest-Version: 1.0
Archiver-Version: Plexus Archiver
Built-By: root
Sealed: True
Created-By: Apache Maven 3.3.9
Build-Jdk: 1.8.0_232
Main-Class: htb.fatty.client.run.Starter

Name: META-INF/maven/org.slf4j/slf4j-log4j12/pom.properties
SHA-256-Digest: miPHJ+Y50c4aqIcmsko7Z/hdj03XNhHx3C/pZbEp4Cw=

Name: org/springframework/jmx/export/metadata/ManagedOperationParamete
 r.class
SHA-256-Digest: h+JmFJqj0MnFbvd+LoFffOtcKcpbf/FD9h2AMOntcgw=
<SNIP>
```

Vamos a eliminar los hashes de `META-INF/MANIFEST.MF` y borrar los archivos `1.RSA` y `1.SF` del directorio `META-INF`. El `MANIFEST.MF` modificado debe terminar con una nueva línea.

```r
Manifest-Version: 1.0
Archiver-Version: Plexus Archiver
Built-By: root
Sealed: True
Created-By: Apache Maven 3.3.9
Build-Jdk: 1.8.0_232
Main-Class: htb.fatty.client.run.Starter

```

Podemos actualizar y ejecutar el archivo `fatty-client.jar` emitiendo los siguientes comandos.

```r
C:\> cd .\fatty-client
C:\> jar -cmf .\META-INF\MANIFEST.MF ..\fatty-client-new.jar *
```

Luego, hacemos doble clic en el archivo `fatty-client-new.jar` para iniciarlo y probamos iniciar sesión usando las credenciales `qtc / clarabibi`.

![login](https://academy.hackthebox.com/storage/modules/113/thick_clients_web/login.png)

Esta vez obtenemos el mensaje `Login Successful!`.

---

## Foothold

Hacer clic en `Profile` -> `Whoami` revela que el usuario `qtc` tiene asignado el rol `user`.

![profile1](https://academy.hackthebox.com/storage/modules/113/thick_clients_web/profile1.png)

Al hacer clic en `ServerStatus`, notamos que no podemos hacer clic en ninguna opción.

![status](https://academy.hackthebox.com/storage/modules/113/thick_clients_web/status.png)

Esto implica que podría haber otro usuario con mayores privilegios que tiene permitido usar esta función. Al hacer clic en `FileBrowser` -> `Notes.txt`, se revela el archivo `security.txt`. Al hacer clic en la opción `Open` en la parte inferior de la ventana, se muestra el siguiente contenido.

![security](https://academy.hackthebox.com/storage/modules/113/thick_clients_web/security.png)

Esta nota nos informa que aún deben solucionarse algunos problemas críticos en la aplicación. Navegando a la opción `FileBrowser` -> `Mail`, se revela el archivo `dave.txt` que contiene información interesante. Podemos leer su contenido haciendo clic en la opción `