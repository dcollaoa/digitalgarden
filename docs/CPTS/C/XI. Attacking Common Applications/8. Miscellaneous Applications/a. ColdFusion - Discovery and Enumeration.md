ColdFusion es un lenguaje de programación y una plataforma de desarrollo de aplicaciones web basada en Java. ColdFusion fue desarrollado inicialmente por la Corporación Allaire en 1995 y fue adquirida por Macromedia en 2001. Más tarde, Macromedia fue adquirida por Adobe Systems, que ahora posee y desarrolla ColdFusion.

Se utiliza para construir aplicaciones web dinámicas e interactivas que pueden conectarse a varias APIs y bases de datos como MySQL, Oracle y Microsoft SQL Server. ColdFusion se lanzó por primera vez en 1995 y desde entonces ha evolucionado hasta convertirse en una plataforma potente y versátil para el desarrollo web.

ColdFusion Markup Language (`CFML`) es el lenguaje de programación propietario utilizado en ColdFusion para desarrollar aplicaciones web dinámicas. Tiene una sintaxis similar a HTML, lo que facilita su aprendizaje para los desarrolladores web. CFML incluye etiquetas y funciones para la integración de bases de datos, servicios web, gestión de correo electrónico y otras tareas comunes de desarrollo web. Su enfoque basado en etiquetas simplifica el desarrollo de aplicaciones al reducir la cantidad de código necesario para realizar tareas complejas. Por ejemplo, la etiqueta `cfquery` puede ejecutar sentencias SQL para recuperar datos de una base de datos:

```r
<cfquery name="myQuery" datasource="myDataSource">
  SELECT *
  FROM myTable
</cfquery>
```

Luego, los desarrolladores pueden usar la etiqueta `cfloop` para iterar a través de los registros recuperados de la base de datos:

```r
<cfloop query="myQuery">
  <p>#myQuery.firstName# #myQuery.lastName#</p>
</cfloop>
```

Gracias a sus funciones y características integradas, CFML permite a los desarrolladores crear lógica empresarial compleja utilizando un código mínimo. Además, ColdFusion admite otros lenguajes de programación, como JavaScript y Java, lo que permite a los desarrolladores utilizar su lenguaje de programación preferido dentro del entorno de ColdFusion.

ColdFusion también ofrece soporte para correo electrónico, manipulación de PDF, gráficos y otras características comúnmente utilizadas. Las aplicaciones desarrolladas con ColdFusion pueden ejecutarse en cualquier servidor que soporte su runtime. Está disponible para su descarga desde el sitio web de Adobe y se puede instalar en sistemas operativos Windows, Mac o Linux. Las aplicaciones de ColdFusion también pueden desplegarse en plataformas en la nube como Amazon Web Services o Microsoft Azure. Algunos de los propósitos y beneficios principales de ColdFusion incluyen:

|**Benefits**|**Description**|
|---|---|
|`Developing data-driven web applications`|ColdFusion permite a los desarrolladores construir aplicaciones web ricas y responsivas fácilmente. Ofrece gestión de sesiones, manejo de formularios, depuración y más características. ColdFusion te permite aprovechar tu conocimiento existente del lenguaje y combinarlo con características avanzadas para ayudarte a construir aplicaciones web robustas rápidamente.|
|`Integrating with databases`|ColdFusion se integra fácilmente con bases de datos como Oracle, SQL Server y MySQL. ColdFusion proporciona conectividad avanzada de bases de datos y está diseñado para facilitar la recuperación, manipulación y visualización de datos desde una base de datos y la web.|
|`Simplifying web content management`|Uno de los objetivos principales de ColdFusion es agilizar la gestión de contenido web. La plataforma ofrece generación dinámica de HTML y simplifica la creación de formularios, reescritura de URL, carga de archivos y manejo de formularios grandes. Además, ColdFusion también admite AJAX manejando automáticamente la serialización y deserialización de componentes habilitados para AJAX.|
|`Performance`|ColdFusion está diseñado para ser altamente performante y está optimizado para baja latencia y alto rendimiento. Puede manejar un gran número de solicitudes simultáneas manteniendo un alto nivel de rendimiento.|
|`Collaboration`|ColdFusion ofrece características que permiten a los desarrolladores trabajar juntos en proyectos en tiempo real. Esto incluye compartir código, depuración, control de versiones y más. Esto permite un desarrollo más rápido y eficiente, reduciendo el tiempo de lanzamiento al mercado y la entrega rápida de proyectos.|

A pesar de ser menos popular que otras plataformas de desarrollo web, ColdFusion sigue siendo ampliamente utilizado por desarrolladores y organizaciones a nivel mundial. Gracias a su facilidad de uso, capacidades de desarrollo rápido de aplicaciones e integración con otras tecnologías web, es una elección ideal para construir aplicaciones web rápida y eficientemente. ColdFusion ha evolucionado, con nuevas versiones lanzadas periódicamente desde su inicio.

La versión estable más reciente de ColdFusion, al momento de escribir esto, es ColdFusion 2021, con ColdFusion 2023 a punto de entrar en Alpha. Las versiones anteriores incluyen ColdFusion 2018, ColdFusion 2016 y ColdFusion 11, cada una con nuevas características y mejoras como mejor rendimiento, integración más sencilla con otras plataformas, mejor seguridad y usabilidad mejorada.

Como cualquier tecnología web, ColdFusion ha sido históricamente vulnerable a varios tipos de ataques, como SQL injection, XSS, directory traversal, authentication bypass y arbitrary file uploads. Para mejorar la seguridad de ColdFusion, los desarrolladores deben implementar prácticas de codificación segura, controles de validación de entrada y configurar adecuadamente los servidores web y firewalls. Aquí hay algunas vulnerabilidades conocidas de ColdFusion:

1. CVE-2021-21087: Arbitrary disallow of uploading JSP source code
2. CVE-2020-24453: Active Directory integration misconfiguration
3. CVE-2020-24450: Command injection vulnerability
4. CVE-2020-24449: Arbitrary file reading vulnerability
5. CVE-2019-15909: Cross-Site Scripting (XSS) Vulnerability

ColdFusion expone bastantes puertos por defecto:

|Port Number|Protocol|Description|
|---|---|---|
|80|HTTP|Utilizado para la comunicación HTTP no segura entre el servidor web y el navegador web.|
|443|HTTPS|Utilizado para la comunicación HTTP segura entre el servidor web y el navegador web. Cifra la comunicación entre el servidor web y el navegador web.|
|1935|RPC|Utilizado para la comunicación cliente-servidor. El protocolo Remote Procedure Call (RPC) permite a un programa solicitar información de otro programa en un dispositivo de red diferente.|
|25|SMTP|Simple Mail Transfer Protocol (SMTP) se utiliza para enviar mensajes de correo electrónico.|
|8500|SSL|Utilizado para la comunicación del servidor a través de Secure Socket Layer (SSL).|
|5500|Server Monitor|Utilizado para la administración remota del servidor ColdFusion.|

Es importante tener en cuenta que los puertos predeterminados se pueden cambiar durante la instalación o configuración.

---

## Enumeration

Durante una enumeración de penetration testing, existen varias formas de identificar si una aplicación web utiliza ColdFusion. Aquí hay algunos métodos que se pueden usar:

|**Method**|**Description**|
|---|---|
|`Port Scanning`|ColdFusion normalmente utiliza el puerto 80 para HTTP y el puerto 443 para HTTPS por defecto. Por lo tanto, escanear estos puertos puede indicar la presencia de un servidor ColdFusion. Nmap podría identificar ColdFusion durante un escaneo de servicios específicamente.|
|`File Extensions`|Las páginas de ColdFusion suelen usar las extensiones de archivo ".cfm" o ".cfc". Si encuentras páginas con estas extensiones de archivo, podría ser un indicador de que la aplicación está utilizando ColdFusion.|
|`HTTP Headers`|Revisa los encabezados de respuesta HTTP de la aplicación web. ColdFusion suele establecer encabezados específicos, como "Server: ColdFusion" o "X-Powered-By: ColdFusion", que pueden ayudar a identificar la tecnología que se está utilizando.|
|`Error Messages`|Si la aplicación utiliza ColdFusion y hay errores, los mensajes de error pueden contener referencias a etiquetas o funciones específicas de ColdFusion.|
|`Default Files`|ColdFusion crea varios archivos predeterminados durante la instalación, como "admin.cfm" o "CFIDE/administrator/index.cfm". Encontrar estos archivos en el servidor web puede indicar que la aplicación web se está ejecutando en ColdFusion.|

### NMap ports and service scan results

```r
nmap -p- -sC -Pn 10.129.247.30 --open

Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-13 11:45 GMT
Nmap scan report for 10.129.247.30
Host is up (0.028s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
135/tcp   open  msrpc
8500/tcp  open  fmtp
49154/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 350.38 seconds
```

Los resultados del escaneo de puertos muestran tres puertos abiertos. Dos servicios Windows RPC y uno en el puerto `8500`. Como sabemos, `8500` es un puerto predeterminado que ColdFusion utiliza para SSL. Navegar al `IP:8500` muestra dos directorios, `CFIDE` y `cfdocs`, en la raíz, lo que indica que ColdFusion se está ejecutando en el puerto 8500.

Navegar un poco por la estructura muestra mucha información interesante, desde archivos con una clara extensión `.cfm` hasta mensajes de error y páginas de inicio de sesión.

![](https://academy.hackthebox.com/storage/modules/113/coldfusion/CFIDE.png)

![](https://academy.hackthebox.com/storage/modules/113/coldfusion/CFError.png)

El path `/CFIDE/administrator`, sin embargo, carga la página de inicio de sesión del administrador de ColdFusion 8. Ahora sabemos con certeza que `ColdFusion 8` está ejecutándose en el server.

![](https://academy.hackthebox.com/storage/modules/113/coldfusion/CF8.png)
