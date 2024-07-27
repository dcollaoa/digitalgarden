Las aplicaciones web basadas en la web son comunes en la mayoría, si no en todos los entornos que encontramos como penetration testers. Durante nuestras evaluaciones, nos encontraremos con una amplia variedad de aplicaciones web, como Content Management Systems (CMS), aplicaciones web personalizadas, portales intranet utilizados por desarrolladores y sysadmins, repositorios de código, herramientas de monitoreo de red, sistemas de tickets, wikis, bases de conocimiento, rastreadores de problemas, aplicaciones de contenedores de servlets, y más. Es común encontrar las mismas aplicaciones en diferentes entornos. Mientras que una aplicación puede no ser vulnerable en un entorno, puede estar mal configurada o sin parches en otro. Un evaluador necesita tener un conocimiento firme de cómo enumerar y atacar las aplicaciones comunes cubiertas en este módulo.

Las aplicaciones web son aplicaciones interactivas a las que se puede acceder a través de navegadores web. Las aplicaciones web suelen adoptar una arquitectura cliente-servidor para ejecutarse y manejar las interacciones. Por lo general, están compuestas de componentes front-end (la interfaz del sitio web, o "lo que el usuario ve") que se ejecutan en el lado del cliente (navegador) y otros componentes back-end (código fuente de la aplicación web) que se ejecutan en el lado del servidor (servidores/databases back-end). Para un estudio en profundidad de la estructura y función de las aplicaciones web, consulta el módulo [Introduction to Web Applications](https://academy.hackthebox.com/course/preview/introduction-to-web-applications).

Todos los tipos de aplicaciones web (comerciales, open-source y personalizadas) pueden sufrir de los mismos tipos de vulnerabilidades y configuraciones incorrectas, a saber, los 10 principales riesgos de aplicaciones web cubiertos en el [OWASP Top 10](https://owasp.org/www-project-top-ten/). Si bien podemos encontrar versiones vulnerables de muchas aplicaciones comunes que sufren de vulnerabilidades conocidas (públicas) como SQL injection, XSS, remote code execution bugs, local file read, y unrestricted file upload, es igualmente importante para nosotros entender cómo podemos abusar de la funcionalidad incorporada de muchas de estas aplicaciones para lograr remote code execution.

A medida que las organizaciones continúan endureciendo su perímetro externo y limitando los servicios expuestos, las aplicaciones web se están convirtiendo en un objetivo más atractivo tanto para los actores maliciosos como para los penetration testers. Cada vez más empresas están transitando hacia el trabajo remoto y exponiendo (intencionalmente o no) aplicaciones al mundo exterior. Las aplicaciones discutidas en este módulo son típicamente tan probables de ser expuestas en la red externa como en la red interna. Estas aplicaciones pueden servir como un punto de entrada al entorno interno durante una evaluación externa o como un punto de entrada, movimiento lateral o problema adicional para informar a nuestro cliente durante una evaluación interna.

[The state of application security in 2021](https://blog.barracuda.com/2021/05/18/report-the-state-of-application-security-in-2021/) fue una encuesta de investigación encargada por Barracuda para recopilar información de los responsables de decisiones relacionadas con la seguridad de aplicaciones. La encuesta incluye respuestas de 750 responsables de decisiones en empresas con 500 o más empleados en todo el mundo. Los hallazgos de la encuesta fueron asombrosos: el 72% de los encuestados declaró que su organización sufrió al menos una brecha debido a una vulnerabilidad en una aplicación, el 32% sufrió dos brechas y el 14% sufrió tres. Las organizaciones encuestadas desglosaron sus desafíos de la siguiente manera: ataques de bots (43%), ataques a la cadena de suministro de software (39%), detección de vulnerabilidades (38%) y aseguramiento de APIs (37%). Este módulo se enfocará en vulnerabilidades y configuraciones incorrectas conocidas en aplicaciones open-source y comerciales (versiones gratuitas demostradas en este módulo), que conforman un gran porcentaje de los ataques exitosos que enfrentan regularmente las organizaciones.

---

## Application Data

Este módulo estudiará varias aplicaciones comunes en profundidad mientras cubre brevemente otras menos comunes (pero aún así vistas a menudo). Algunas de las categorías de aplicaciones que podemos encontrar durante una evaluación y que podemos aprovechar para obtener un punto de entrada o acceder a datos sensibles incluyen:

|**Category**|**Applications**|
|---|---|
|[Web Content Management](https://enlyft.com/tech/web-content-management)|Joomla, Drupal, WordPress, DotNetNuke, etc.|
|[Application Servers](https://enlyft.com/tech/application-servers)|Apache Tomcat, Phusion Passenger, Oracle WebLogic, IBM WebSphere, etc.|
|[Security Information and Event Management (SIEM)](https://enlyft.com/tech/security-information-and-event-management-siem)|Splunk, Trustwave, LogRhythm, etc.|
|[Network Management](https://enlyft.com/tech/network-management)|PRTG Network Monitor, ManageEngine Opmanger, etc.|
|[IT Management](https://enlyft.com/tech/it-management-software)|Nagios, Puppet, Zabbix, ManageEngine ServiceDesk Plus, etc.|
|[Software Frameworks](https://enlyft.com/tech/software-frameworks)|JBoss, Axis2, etc.|
|[Customer Service Management](https://enlyft.com/tech/customer-service-management)|osTicket, Zendesk, etc.|
|[Search Engines](https://enlyft.com/tech/search-engines)|Elasticsearch, Apache Solr, etc.|
|[Software Configuration Management](https://enlyft.com/tech/software-configuration-management)|Atlassian JIRA, GitHub, GitLab, Bugzilla, Bugsnag, Bitbucket, etc.|
|[Software Development Tools](https://enlyft.com/tech/software-development-tools)|Jenkins, Atlassian Confluence, phpMyAdmin, etc.|
|[Enterprise Application Integration](https://enlyft.com/tech/enterprise-application-integration)|Oracle Fusion Middleware, BizTalk Server, Apache ActiveMQ, etc.|

Como puedes ver al navegar por los enlaces de cada categoría arriba, hay [miles de aplicaciones](https://enlyft.com/tech/) que podemos encontrar durante una evaluación. Muchas de estas sufren de exploits conocidos públicamente o tienen funcionalidades que pueden ser abusadas para obtener remote code execution, robar credenciales o acceder a información sensible con o sin credenciales válidas. Este módulo cubrirá las aplicaciones más prevalentes que vemos repetidamente durante evaluaciones internas y externas.

Veamos el sitio web de Enlyft. Podemos ver, por ejemplo, que pudieron recopilar datos de más de 3.7 millones de empresas que utilizan [WordPress](https://enlyft.com/tech/products/wordpress), lo que constituye casi el 70% de la cuota de mercado mundial para aplicaciones de Web Content Management para todas las empresas encuestadas. Para la herramienta SIEM [Splunk](https://enlyft.com/tech/products/splunk) fue utilizada por 22,174 de las empresas encuestadas y representó casi el 30% de la cuota de mercado para herramientas SIEM. Mientras que las aplicaciones restantes que cubriremos representan una cuota de mercado mucho más pequeña para su respectiva categoría, aún las veo a menudo, y las habilidades aprendidas aquí pueden aplicarse a muchas situaciones diferentes.

Mientras trabajas en los ejemplos, preguntas y evaluaciones de habilidades de la sección, haz un esfuerzo concertado para aprender cómo funcionan estas aplicaciones y por qué existen vulnerabilidades y configuraciones incorrectas específicas en lugar de simplemente reproducir los ejemplos para avanzar rápidamente a través del módulo. Estas habilidades te beneficiarán enormemente y probablemente te ayudarán a identificar caminos de ataque en diferentes aplicaciones que encuentres durante una evaluación por primera vez. Todavía encuentro aplicaciones que solo he visto unas pocas veces o nunca antes, y abordarlas con esta mentalidad a menudo me ha ayudado a llevar a cabo ataques o encontrar una manera de abusar de la funcionalidad incorporada.

---

## A Quick Story

Por ejemplo, durante una prueba de penetración externa, encontré la aplicación [Nexus Repository OSS](https://www.sonatype.com/products/repository-oss) de Sonatype, que nunca había visto antes. Rápidamente descubrí que las credenciales de administrador predeterminadas de `admin:admin123` para esa versión no se habían cambiado y pude iniciar sesión y explorar la funcionalidad de administración. En esta versión, aproveché la API como un usuario autenticado para obtener remote code execution en el sistema. Encontré esta aplicación en otra evaluación, pude iniciar sesión con credenciales predeterminadas una vez más. Esta vez pude abusar de la funcionalidad de [Tasks](https://help.sonatype.com/repomanager3/system-configuration/tasks#Tasks-Admin-Executescript) (que estaba deshabilitada la primera vez que encontré esta aplicación) y escribir un script rápido en [Groovy](https://groovy-lang.org/) en sintaxis Java para ejecutar un script y obtener remote code execution. Esto es similar a cómo abusaremos de la [script console](https://www.jenkins.io/doc/book/managing/script-console/) de Jenkins más adelante en este módulo. He encontrado muchas otras aplicaciones, como [OpManager](https://www.manageengine.com/products/applications_manager/me-opmanager-monitoring.html) de ManageEngine, que permiten ejecutar un script como el usuario bajo el cual se está ejecutando la aplicación (generalmente la cuenta poderosa NT AUTHORITY\SYSTEM) y obtener un punto de entrada. Nunca debemos pasar por alto las aplicaciones durante una evaluación interna y externa, ya que pueden ser nuestra única forma de "entrar" en un entorno relativamente bien mantenido.

---

## Common Applications

Generalmente me encuentro

 con al menos una de las aplicaciones a continuación, que cubriremos en profundidad a lo largo de las secciones del módulo. Aunque no podemos cubrir todas las aplicaciones posibles que podamos encontrar, las habilidades enseñadas en este módulo nos prepararán para abordar todas las aplicaciones con un ojo crítico y evaluarlas para detectar vulnerabilidades públicas y configuraciones incorrectas.

|Application|Description|
|---|---|
|WordPress|[WordPress](https://wordpress.org/) es un Content Management System (CMS) open-source que puede ser utilizado para múltiples propósitos. A menudo se usa para alojar blogs y foros. WordPress es altamente personalizable y amigable con SEO, lo que lo hace popular entre las empresas. Sin embargo, su naturaleza personalizable y extensible lo hace propenso a vulnerabilidades a través de temas y plugins de terceros. WordPress está escrito en PHP y generalmente se ejecuta en Apache con MySQL como back-end.|
|Drupal|[Drupal](https://www.drupal.org/) es otro CMS open-source que es popular entre las empresas y desarrolladores. Drupal está escrito en PHP y admite el uso de MySQL o PostgreSQL para el back-end. Además, se puede usar SQLite si no hay ningún DBMS instalado. Al igual que WordPress, Drupal permite a los usuarios mejorar sus sitios web mediante el uso de temas y módulos.|
|Joomla|[Joomla](https://www.joomla.org/) es otro CMS open-source escrito en PHP que generalmente utiliza MySQL, pero puede configurarse para funcionar con PostgreSQL o SQLite. Joomla puede usarse para blogs, foros de discusión, comercio electrónico y más. Joomla puede personalizarse en gran medida con temas y extensiones, y se estima que es el tercer CMS más utilizado en Internet después de WordPress y Shopify.|
|Tomcat|[Apache Tomcat](https://tomcat.apache.org/) es un servidor web open-source que aloja aplicaciones escritas en Java. Tomcat fue diseñado inicialmente para ejecutar Java Servlets y Java Server Pages (JSP) scripts. Sin embargo, su popularidad aumentó con los frameworks basados en Java y ahora es ampliamente utilizado por frameworks como Spring y herramientas como Gradle.|
|Jenkins|[Jenkins](https://jenkins.io/) es un servidor de automatización open-source escrito en Java que ayuda a los desarrolladores a construir y probar continuamente sus proyectos de software. Es un sistema basado en servidor que se ejecuta en contenedores de servlets como Tomcat. A lo largo de los años, los investigadores han descubierto varias vulnerabilidades en Jenkins, incluidas algunas que permiten remote code execution sin requerir autenticación.|
|Splunk|Splunk es una herramienta de análisis de registros utilizada para recopilar, analizar y visualizar datos. Aunque originalmente no se pensó como una herramienta SIEM, Splunk se usa a menudo para monitoreo de seguridad y análisis empresarial. Las implementaciones de Splunk a menudo se utilizan para albergar datos sensibles y podrían proporcionar una gran cantidad de información para un atacante si se comprometieran. Históricamente, Splunk no ha sufrido una gran cantidad de vulnerabilidades conocidas, aparte de una vulnerabilidad de divulgación de información ([CVE-2018-11409](https://nvd.nist.gov/vuln/detail/CVE-2018-11409)) y una vulnerabilidad de remote code execution autenticada en versiones muy antiguas ([CVE-2011-4642](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-4642)).|
|PRTG Network Monitor|[PRTG Network Monitor](https://www.paessler.com/prtg) es un sistema de monitoreo de red sin agente que puede usarse para monitorear métricas como tiempo de actividad, uso de ancho de banda y más desde una variedad de dispositivos como routers, switches, servidores, etc. Utiliza un modo de descubrimiento automático para escanear una red y luego aprovecha protocolos como ICMP, WMI, SNMP y NetFlow para comunicarse con y recopilar datos de los dispositivos descubiertos. PRTG está escrito en [Delphi](https://en.wikipedia.org/wiki/Delphi_(software)).|
|osTicket|[osTicket](https://osticket.com/) es un sistema de tickets de soporte open-source ampliamente utilizado. Puede usarse para gestionar tickets de servicio al cliente recibidos por correo electrónico, teléfono y la interfaz web. osTicket está escrito en PHP y puede ejecutarse en Apache o IIS con MySQL como back-end.|
|GitLab|[GitLab](https://about.gitlab.com/) es una plataforma de desarrollo de software open-source con un gestor de repositorios Git, control de versiones, seguimiento de problemas, revisión de código, integración y despliegue continuos, y más. Originalmente fue escrito en Ruby, pero ahora utiliza Ruby on Rails, Go y Vue.js. GitLab ofrece versiones tanto comunitarias (gratuitas) como empresariales del software.|

---

## Module Targets

A lo largo de las secciones del módulo, nos referiremos a URLs como `http://app.inlanefreight.local`. Para simular un entorno grande y realista con múltiples servidores web, utilizamos Vhosts para alojar las aplicaciones web. Dado que estos Vhosts se asignan a diferentes directorios en el mismo host, tenemos que hacer entradas manuales en nuestro archivo `/etc/hosts` en el Pwnbox o VM de ataque local para interactuar con el laboratorio. Esto debe hacerse para cualquier ejemplo que muestre escaneos o capturas de pantalla utilizando un FQDN. Las secciones como Splunk que solo usan la IP del objetivo generado no requerirán una entrada en el archivo de hosts, y puedes interactuar simplemente con la dirección IP generada y el puerto asociado.

Para hacer esto rápidamente, podríamos ejecutar lo siguiente:



```r
IP=10.129.42.195
printf "%s\t%s\n\n" "$IP" "app.inlanefreight.local dev.inlanefreight.local blog.inlanefreight.local" | sudo tee -a /etc/hosts
```

Después de este comando, nuestro archivo `/etc/hosts` se vería como el siguiente (en un Pwnbox recién generado):



```r
cat /etc/hosts

# Your system has configured 'manage_etc_hosts' as True.
# As a result, if you wish for changes to this file to persist
# then you will need to either
# a.) make changes to the master file in /etc/cloud/templates/hosts.debian.tmpl
# b.) change or remove the value of 'manage_etc_hosts' in
#     /etc/cloud/cloud.cfg or cloud-config from user-data
#
127.0.1.1 htb-9zftpkslke.htb-cloud.com htb-9zftpkslke
127.0.0.1 localhost

# The following lines are desirable for IPv6 capable hosts
::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts

10.129.42.195	app.inlanefreight.local dev.inlanefreight.local blog.inlanefreight.local
```

Puedes desear escribir tu propio script o editar el archivo de hosts a mano, lo cual está bien.

Si generas un objetivo durante una sección y no puedes acceder a él directamente a través de la IP, asegúrate de revisar tu archivo de hosts y actualizar cualquier entrada.

¡Las ejercicios del módulo que requieran vhosts mostrarán una lista que puedes usar para editar tu archivo de hosts después de generar la VM de destino al final de la sección correspondiente!