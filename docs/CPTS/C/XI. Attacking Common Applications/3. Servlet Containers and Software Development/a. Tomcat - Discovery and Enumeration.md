[Apache Tomcat](https://tomcat.apache.org/) es un servidor web de código abierto que aloja aplicaciones escritas en Java. Tomcat fue diseñado inicialmente para ejecutar Java Servlets y Java Server Pages (JSP). Sin embargo, su popularidad aumentó en los frameworks basados en Java y ahora es ampliamente utilizado por frameworks como Spring y herramientas como Gradle. Según datos recopilados por [BuiltWith](https://trends.builtwith.com/Web-Server/Apache-Tomcat-Coyote), hay más de 220,000 sitios web en vivo usando Tomcat en este momento. Aquí hay algunas estadísticas más interesantes:

- BuiltWith ha recopilado datos que muestran que más de 904,000 sitios web han usado Tomcat en algún momento.
- 1.22% de los sitios web en el top 1 millón están usando Tomcat, mientras que el 3.8% de los sitios web en el top 100k lo están usando.
- Tomcat ocupa la posición [#13](https://webtechsurvey.com/technology/apache-tomcat) en servidores web por cuota de mercado.
- Algunas organizaciones que usan Tomcat incluyen Alibaba, la Oficina de Patentes y Marcas de Estados Unidos (USPTO), la Cruz Roja Americana y el LA Times.

Tomcat a menudo es menos propenso a ser expuesto a internet (aunque). Lo vemos de vez en cuando en pentests externos y puede ser un excelente punto de entrada a la red interna. Es mucho más común ver Tomcat (y múltiples instancias, para el caso) durante pentests internos. Usualmente ocupará el primer lugar bajo "High Value Targets" dentro de un informe de EyeWitness, y más a menudo que no, al menos una instancia interna está configurada con credenciales débiles o por defecto. Más sobre eso más adelante.

---

## Discovery/Footprinting

Durante nuestro test de penetración externo, ejecutamos EyeWitness y vemos un host listado bajo "High Value Targets". La herramienta cree que el host está ejecutando Tomcat, pero debemos confirmar para planificar nuestros ataques. Si estamos tratando con Tomcat en la red externa, esto podría ser un fácil punto de entrada a la red interna.

Los servidores Tomcat se pueden identificar por el encabezado Server en la respuesta HTTP. Si el servidor está operando detrás de un proxy inverso, solicitar una página inválida debería revelar el servidor y la versión. Aquí podemos ver que se está utilizando la versión `9.0.30` de Tomcat.

`http://app-dev.inlanefreight.local:8080/invalid`

![](https://academy.hackthebox.com/storage/modules/113/tomcat_invalid.png)

Es posible que se estén utilizando páginas de error personalizadas que no revelen esta información de versión. En este caso, otro método para detectar un servidor Tomcat y su versión es a través de la página `/docs`.

```r
curl -s http://app-dev.inlanefreight.local:8080/docs/ | grep Tomcat 

<html lang="en"><head><META http-equiv="Content-Type" content="text/html; charset=UTF-8"><link href="./images/docs-stylesheet.css" rel="stylesheet" type="text/css"><title>Apache Tomcat 9 (9.0.30) - Documentation Index</title><meta name="author" 

<SNIP>
```

Esta es la página de documentación por defecto, que puede no ser eliminada por los administradores. Aquí está la estructura general de carpetas de una instalación de Tomcat.

```r
├── bin
├── conf
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib
├── logs
├── temp
├── webapps
│   ├── manager
│   │   ├── images
│   │   ├── META-INF
│   │   └── WEB-INF
|   |       └── web.xml
│   └── ROOT
│       └── WEB-INF
└── work
    └── Catalina
        └── localhost
```

La carpeta `bin` almacena scripts y binarios necesarios para iniciar y ejecutar un servidor Tomcat. La carpeta `conf` almacena varios archivos de configuración utilizados por Tomcat. El archivo `tomcat-users.xml` almacena credenciales de usuario y sus roles asignados. La carpeta `lib` contiene los varios archivos JAR necesarios para el correcto funcionamiento de Tomcat. Las carpetas `logs` y `temp` almacenan archivos de registro temporales. La carpeta `webapps` es la raíz web por defecto de Tomcat y alberga todas las aplicaciones. La carpeta `work` actúa como caché y se utiliza para almacenar datos durante el tiempo de ejecución.

Cada carpeta dentro de `webapps` se espera que tenga la siguiente estructura.

```r
webapps/customapp
├── images
├── index.jsp
├── META-INF
│   └── context.xml
├── status.xsd
└── WEB-INF
    ├── jsp
    |   └── admin.jsp
    └── web.xml
    └── lib
    |    └── jdbc_drivers.jar
    └── classes
        └── AdminServlet.class   
```

El archivo más importante entre estos es `WEB-INF/web.xml`, que se conoce como el descriptor de despliegue. Este archivo almacena información sobre las rutas utilizadas por la aplicación y las clases que manejan estas rutas. Todas las clases compiladas utilizadas por la aplicación deben almacenarse en la carpeta `WEB-INF/classes`. Estas clases pueden contener lógica de negocio importante así como información sensible. Cualquier vulnerabilidad en estos archivos puede llevar a la completa compromisión del sitio web. La carpeta `lib` almacena las bibliotecas necesarias para esa aplicación en particular. La carpeta `jsp` almacena [Jakarta Server Pages (JSP)](https://en.wikipedia.org/wiki/Jakarta_Server_Pages), anteriormente conocidas como `JavaServer Pages`, que se pueden comparar con archivos PHP en un servidor Apache.

Aquí hay un ejemplo de archivo web.xml.

```r
<?xml version="1.0" encoding="ISO-8859-1"?>

<!DOCTYPE web-app PUBLIC "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN" "http://java.sun.com/dtd/web-app_2_3.dtd">

<web-app>
  <servlet>
    <servlet-name>AdminServlet</servlet-name>
    <servlet-class>com.inlanefreight.api.AdminServlet</servlet-class>
  </servlet>

  <servlet-mapping>
    <servlet-name>AdminServlet</servlet-name>
    <url-pattern>/admin</url-pattern>
  </servlet-mapping>
</web-app>   
```

La configuración `web.xml` anterior define un nuevo servlet llamado `AdminServlet` que está asignado a la clase `com.inlanefreight.api.AdminServlet`. Java utiliza la notación de puntos para crear nombres de paquetes, lo que significa que la ruta en disco para la clase definida anteriormente sería:

- `classes/com/inlanefreight/api/AdminServlet.class`

A continuación, se crea una nueva asignación de servlet para mapear solicitudes a `/admin` con `AdminServlet`. Esta configuración enviará cualquier solicitud recibida para `/admin` a la clase `AdminServlet.class` para su procesamiento. El descriptor `web.xml` contiene mucha información sensible y es un archivo importante para revisar cuando se aprovecha una vulnerabilidad de Local File Inclusion (LFI).

El archivo `tomcat-users.xml` se utiliza para permitir o denegar el acceso a las páginas de administración `/manager` y `/host-manager`.

```r
<?xml version="1.0" encoding="UTF-8"?>

<SNIP>
  
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<!--
  By default, no user is included in the "manager-gui" role required
  to operate the "/manager/html" web application.  If you wish to use this app,
  you must define such a user - the username and password are arbitrary.

  Built-in Tomcat manager roles:
    - manager-gui    - allows access to the HTML GUI and the status pages
    - manager-script - allows access to the HTTP API and the status pages
    - manager-jmx    - allows access to the JMX proxy and the status pages
    - manager-status - allows access to the status pages only

  The users below are wrapped in a comment and are therefore ignored. If you
  wish to configure one or more of these users for use with the manager web
  application, do not forget to remove the <!.. ..> that surrounds them. You
  will also need to set the passwords to something appropriate.
-->

   
 <SNIP>
  
!-- user manager can access only manager section -->
<role rolename="manager-gui" />
<user username="tomcat" password="tomcat" roles="manager-gui" />

<!-- user admin can access manager and admin section both -->
<role rolename="admin-gui" />
<user username="admin" password="admin" roles="manager-gui,admin-gui" />


</tomcat-users>
```

El archivo nos muestra a qué tiene acceso cada uno de los roles `manager-gui`, `manager-script`, `manager

-jmx` y `manager-status`. En este ejemplo, podemos ver que un usuario `tomcat` con la contraseña `tomcat` tiene el rol `manager-gui`, y una segunda contraseña débil `admin` está establecida para la cuenta de usuario `admin`.

---

## Enumeration

Después de identificar la instancia de Tomcat, a menos que tenga una vulnerabilidad conocida, normalmente querríamos buscar las páginas `/manager` y `/host-manager`. Podemos intentar localizarlas con una herramienta como `Gobuster` o simplemente navegar directamente a ellas.

```r
gobuster dir -u http://web01.inlanefreight.local:8180/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt 

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://web01.inlanefreight.local:8180/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/09/21 17:34:54 Starting gobuster
===============================================================
/docs (Status: 302)
/examples (Status: 302)
/manager (Status: 302)
Progress: 49959 / 87665 (56.99%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2021/09/21 17:44:29 Finished
===============================================================
```

Podemos intentar iniciar sesión en una de estas usando credenciales débiles como `tomcat:tomcat`, `admin:admin`, etc. Si estos primeros intentos no funcionan, podemos intentar un ataque de fuerza bruta de contraseñas contra la página de inicio de sesión, cubierto en la siguiente sección. Si logramos iniciar sesión, podemos subir un [Web Application Resource o Web Application ARchive (WAR)](https://en.wikipedia.org/wiki/WAR_(file_format)#:~:text=In%20software%20engineering%2C%20a%20WAR,that%20together%20constitute%20a%20web) que contenga una web shell JSP y obtener ejecución remota de código en el servidor Tomcat.

Ahora que hemos aprendido sobre la estructura y función de Tomcat, ataquémoslo abusando de la funcionalidad incorporada y explotando una vulnerabilidad conocida que afectó a versiones específicas de Tomcat.