El `Metasploit Project` es una plataforma modular de pruebas de penetración basada en Ruby que permite escribir, probar y ejecutar código de exploits. Este código de exploit puede ser personalizado por el usuario o tomado de una base de datos que contiene los últimos exploits ya descubiertos y modularizados. El `Metasploit Framework` incluye un conjunto de herramientas que puedes usar para probar vulnerabilidades de seguridad, enumerar redes, ejecutar ataques y evadir la detección. En su núcleo, el `Metasploit Project` es una colección de herramientas comúnmente utilizadas que proporcionan un entorno completo para pruebas de penetración y desarrollo de exploits.

![img](https://academy.hackthebox.com/storage/modules/39/S02_SS01.png)

Los `modules` mencionados son pruebas de concepto de exploits reales que ya se han desarrollado y probado en el campo y se han integrado dentro del framework para proporcionar a los pentesters un acceso fácil a diferentes vectores de ataque para diferentes plataformas y servicios. Metasploit no es un todoterreno, pero es una navaja suiza con las herramientas suficientes para abordar las vulnerabilidades no parcheadas más comunes.

Su punto fuerte es que proporciona una gran cantidad de objetivos y versiones disponibles, todos a unos pocos comandos de un acceso exitoso. Estos, combinados con un exploit hecho a medida para esas versiones vulnerables y con un payload que se envía después del exploit, lo cual nos dará acceso real al sistema, nos proporcionan una forma fácil y automatizada de cambiar entre conexiones de objetivos durante nuestras actividades de post-explotación.

---

## Metasploit Pro

`Metasploit` como producto se divide en dos versiones. La versión `Metasploit Pro` es diferente de `Metasploit Framework` y tiene algunas características adicionales:

- Task Chains
- Social Engineering
- Vulnerability Validations
- GUI
- Quick Start Wizards
- Nexpose Integration

Si prefieres usar la línea de comandos y disfrutar de las características adicionales, la versión Pro también contiene su propia consola, muy similar a `msfconsole`.

Para tener una idea general de lo que las características más recientes de Metasploit Pro pueden lograr, consulta la siguiente lista:

|**Infiltrate**|**Collect Data**|**Remediate**|
|---|---|---|
|Manual Exploitation|Import and Scan Data|Bruteforce|
|Anti-virus Evasion|Discovery Scans|Task Chains|
|IPS/IDS Evasion|Meta-Modules|Exploitation Workflow|
|Proxy Pivot|Nexpose Scan Integration|Session Rerun|
|Post-Exploitation||Task Replay|
|Session Clean-up||Project Sonar Integration|
|Credentials Reuse||Session Management|
|Social Engineering||Credential Management|
|Payload Generator||Team Collaboration|
|Quick Pen-testing||Web Interface|
|VPN Pivoting||Backup and Restore|
|Vulnerability Validation||Data Export|
|Phishing Wizard||Evidence Collection|
|Web App Testing||Reporting|
|Persistent Sessions||Tagging Data|

---

## Metasploit Framework Console

La `msfconsole` es probablemente la interfaz más popular del `Metasploit Framework` `(MSF)`. Proporciona una consola centralizada "todo en uno" y te permite acceder de manera eficiente a prácticamente todas las opciones disponibles en el `MSF`. `Msfconsole` puede parecer intimidante al principio, pero una vez que aprendas la sintaxis de los comandos, apreciarás el poder de utilizar esta interfaz.

Las características que `msfconsole` generalmente ofrece son las siguientes:

- Es la única forma soportada de acceder a la mayoría de las características dentro de `Metasploit`.
    
- Proporciona una interfaz basada en consola para el `Framework`.
    
- Contiene la mayoría de las características y es la interfaz `MSF` más estable.
    
- Soporte completo de readline, tabulación y autocompletado de comandos.
    
- Ejecución de comandos externos en `msfconsole`.
    

Ambos productos mencionados anteriormente vienen con una base de datos extensa de módulos disponibles para usar en nuestras evaluaciones. Estos, combinados con el uso de comandos externos como escáneres, kits de herramientas de ingeniería social y generadores de payloads, pueden convertir nuestra configuración en una máquina lista para atacar que nos permitirá controlar y manipular diferentes vulnerabilidades en el campo de manera continua utilizando sesiones y trabajos de la misma manera que veríamos pestañas en un navegador de Internet.

El término clave aquí es usabilidad—experiencia del usuario. La facilidad con la que podemos controlar la consola puede mejorar nuestra experiencia de aprendizaje. Por lo tanto, profundicemos en los detalles.

---

## Understanding the Architecture

Para operar completamente cualquier herramienta que estemos usando, primero debemos mirar bajo su capó. Es una buena práctica y puede ofrecernos una mejor comprensión de lo que sucederá durante nuestras evaluaciones de seguridad cuando esa herramienta entre en juego. Es esencial no tener [ningún comodín que pueda dejarte a ti o a tu cliente expuestos a violaciones de datos](https://blog.cobaltstrike.com/2016/09/28/cobalt-strike-rce-active-exploitation-reported/).

Por defecto, todos los archivos base relacionados con Metasploit Framework se pueden encontrar en `/usr/share/metasploit-framework` en nuestra distro `ParrotOS Security`.

### Data, Documentation, Lib

Estos son los archivos base para el Framework. Los archivos Data y Lib son las partes funcionales de la interfaz msfconsole, mientras que la carpeta Documentation contiene todos los detalles técnicos sobre el proyecto.

### Modules

Los módulos detallados anteriormente están divididos en categorías separadas en esta carpeta. Detallaremos estos en las siguientes secciones. Se encuentran en las siguientes carpetas:

```r
ls /usr/share/metasploit-framework/modules

auxiliary  encoders  evasion  exploits  nops  payloads  post
```

### Plugins

Los plugins ofrecen al pentester más flexibilidad al usar la `msfconsole`, ya que se pueden cargar manual o automáticamente según sea necesario para proporcionar funcionalidad adicional y automatización durante nuestra evaluación.

```r
ls /usr/share/metasploit-framework/plugins/

aggregator.rb      ips_filter.rb  openvas.rb           sounds.rb
alias.rb           komand.rb      pcap_log.rb          sqlmap.rb
auto_add_route.rb  lab.rb         request.rb           thread.rb
beholder.rb        libnotify.rb   rssfeed.rb           token_adduser.rb
db_credcollect.rb  msfd.rb        sample.rb            token_hunter.rb
db_tracker.rb      msgrpc.rb      session_notifier.rb  wiki.rb
event_tester.rb    nessus.rb      session_tagger.rb    wmap.rb
ffautoregen.rb     nexpose.rb     socket_logger.rb
```

### Scripts

Funcionalidad de Meterpreter y otros scripts útiles.

```r
ls /usr/share/metasploit-framework/scripts/

meterpreter  ps  resource  shell
```

### Tools

Utilidades de línea de comandos que se pueden llamar directamente desde el menú `msfconsole`.

```r
ls /usr/share/metasploit-framework/tools/

context  docs     hardware  modules   payloads
dev      exploit  memdump   password  recon
```

Ahora que conocemos todas estas ubicaciones, nos será fácil referenciarlas en el futuro cuando decidamos importar nuevos módulos o incluso crear nuevos desde cero.