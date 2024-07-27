Los plugins son software disponible que ha sido lanzado por terceros y que han dado aprobación a los creadores de Metasploit para integrar su software dentro del framework. Estos pueden representar productos comerciales que tienen una `Community Edition` para uso gratuito pero con funcionalidad limitada, o pueden ser proyectos individuales desarrollados por personas individuales.

El uso de plugins facilita aún más la vida de un pentester, trayendo la funcionalidad de software conocido al entorno de `msfconsole` o Metasploit Pro. Antes, necesitábamos alternar entre diferentes software para importar y exportar resultados, configurando opciones y parámetros una y otra vez. Ahora, con el uso de plugins, todo se documenta automáticamente por msfconsole en la base de datos que estamos usando y los hosts, servicios y vulnerabilidades están disponibles a simple vista para el usuario. [Plugins](https://www.rubydoc.info/github/rapid7/metasploit-framework/Msf/Plugin) trabajan directamente con la API y pueden ser usados para manipular todo el framework. Pueden ser útiles para automatizar tareas repetitivas, agregar nuevos comandos a `msfconsole` y extender el ya poderoso framework.

---

## Using Plugins

Para empezar a usar un plugin, necesitaremos asegurarnos de que esté instalado en el directorio correcto en nuestra máquina. Navegar a `/usr/share/metasploit-framework/plugins`, que es el directorio predeterminado para cada nueva instalación de `msfconsole`, debería mostrarnos qué plugins tenemos disponibles:

```r
ls /usr/share/metasploit-framework/plugins

aggregator.rb      beholder.rb        event_tester.rb  komand.rb     msfd.rb    nexpose.rb   request.rb  session_notifier.rb  sounds.rb  token_adduser.rb  wmap.rb
alias.rb           db_credcollect.rb  ffautoregen.rb   lab.rb        msgrpc.rb  openvas.rb   rssfeed.rb  session_tagger.rb    sqlmap.rb  token_hunter.rb
auto_add_route.rb  db_tracker.rb      ips_filter.rb    libnotify.rb  nessus.rb  pcap_log.rb  sample.rb   socket_logger.rb     thread.rb  wiki.rb
```

Si el plugin se encuentra aquí, podemos cargarlo dentro de `msfconsole` y veremos la salida de saludo para ese plugin específico, señalando que se cargó correctamente y ahora está listo para usar:

### MSF - Load Nessus

```r
msf6 > load nessus

[*] Nessus Bridge for Metasploit
[*] Type nessus_help for a command listing
[*] Successfully loaded Plugin: Nessus


msf6 > nessus_help

Command                     Help Text
-------                     ---------
Generic Commands            
-----------------           -----------------
nessus_connect              Connect to a Nessus server
nessus_logout               Logout from the Nessus server
nessus_login                Login into the connected Nessus server with a different username and 

<SNIP>

nessus_user_del             Delete a Nessus User
nessus_user_passwd          Change Nessus Users Password
                            
Policy Commands             
-----------------           -----------------
nessus_policy_list          List all policies
nessus_policy_del           Delete a policy
```

Si el plugin no está instalado correctamente, recibiremos el siguiente error al intentar cargarlo.

```r
msf6 > load Plugin_That_Does_Not_Exist

[-] Failed to load plugin from /usr/share/metasploit-framework/plugins/Plugin_That_Does_Not_Exist.rb: cannot load such file -- /usr/share/metasploit-framework/plugins/Plugin_That_Does_Not_Exist.rb
```

Para empezar a usar el plugin, empecemos a emitir los comandos disponibles en el menú de ayuda de ese plugin específico. Cada integración multiplataforma nos ofrece un conjunto único de interacciones que podemos usar durante nuestras evaluaciones, por lo que es útil leer sobre cada una de ellas antes de emplearlas para aprovechar al máximo tenerlas a nuestro alcance.

---
## Installing new Plugins

Nuevos plugins más populares se instalan con cada actualización de la distro de Parrot OS a medida que se publican al público por sus creadores, recopilados en el repositorio de actualizaciones de Parrot. Para instalar nuevos plugins personalizados no incluidos en nuevas actualizaciones de la distro, podemos tomar el archivo .rb proporcionado en la página del creador y colocarlo en la carpeta en `/usr/share/metasploit-framework/plugins` con los permisos adecuados.

Por ejemplo, intentemos instalar [DarkOperator's Metasploit-Plugins](https://github.com/darkoperator/Metasploit-Plugins.git). Luego, siguiendo el enlace anterior, obtenemos un par de archivos Ruby (`.rb`) que podemos colocar directamente en la carpeta mencionada anteriormente.

### Downloading MSF Plugins

```r
git clone https://github.com/darkoperator/Metasploit-Plugins
ls Metasploit-Plugins

aggregator.rb      ips_filter.rb  pcap_log.rb          sqlmap.rb
alias.rb           komand.rb      pentest.rb           thread.rb
auto_add_route.rb  lab.rb         request.rb           token_adduser.rb
beholder.rb        libnotify.rb   rssfeed.rb           token_hunter.rb
db_credcollect.rb  msfd.rb        sample.rb            twitt.rb
db_tracker.rb      msgrpc.rb      session_notifier.rb  wiki.rb
event_tester.rb    nessus.rb      session_tagger.rb    wmap.rb
ffautoregen.rb     nexpose.rb     socket_logger.rb
growl.rb           openvas.rb     sounds.rb
```

Aquí podemos tomar el plugin `pentest.rb` como ejemplo y copiarlo a `/usr/share/metasploit-framework/plugins`.

### MSF - Copying Plugin to MSF

```r
sudo cp ./Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/pentest.rb
```

Después, inicia `msfconsole` y verifica la instalación del plugin ejecutando el comando `load`. Después de que el plugin se haya cargado, el `help menu` en `msfconsole` se extiende automáticamente con funciones adicionales.

### MSF - Load Plugin

```r
msfconsole -q

msf6 > load pentest

       ___         _          _     ___ _           _
      | _ \___ _ _| |_ ___ __| |_  | _ \ |_  _ __ _(_)_ _
      |  _/ -_) ' \  _/ -_|_-<  _| |  _/ | || / _` | | ' \ 
      |_| \___|_||_\__\___/__/\__| |_| |_|\_,_\__, |_|_||_|
                                              |___/
      
Version 1.6
Pentest Plugin loaded.
by Carlos Perez (carlos_perez[at]darkoperator.com)
[*] Successfully loaded plugin: pentest


msf6 > help

Tradecraft Commands
===================

    Command          Description
    -------          -----------
    check_footprint  Checks the possible footprint of a post module on a target system.


auto_exploit Commands
=====================

    Command           Description
    -------           -----------
    show_client_side  Show matched client side exploits from data imported from vuln scanners.
    vuln_exploit      Runs exploits based on data imported from vuln scanners.


Discovery Commands
==================

    Command                 Description
    -------                 -----------
    discover_db             Run discovery modules against current hosts in the database.
    network_discover        Performs a port-scan and enumeration of services found for non pivot networks.
    pivot_network_discover  Performs enumeration of networks available to a specified Meterpreter session.
    show_session_networks   Enumerate the networks one could pivot thru Meterpreter in the active sessions.


Project Commands
================

    Command       Description
    -------       -----------
    project       Command for managing projects.


Postauto Commands
=================

    Command             Description
    -------             -----------
    app_creds           Run application password collection modules against specified sessions.
    get_lhost           List local IP addresses that can be used for LHOST.
    multi_cmd           Run shell command against several sessions
    multi_meter_cmd     Run a Meterpreter Console Command against specified sessions.
    multi_meter_cmd_rc  Run resource file with Meterpreter Console Commands against specified sessions.
    multi_post          Run a post module against specified sessions.
    multi_post_rc       Run resource file with post modules and options against specified sessions.
    sys_creds           Run system password collection modules against specified sessions.

<SNIP>
```

Mucha gente escribe muchos plugins diferentes para el framework de Metasploit. Todos tienen un propósito específico y pueden ser de gran ayuda para ahorrar tiempo después de familiarizarnos con ellos. Echa un vistazo a la lista de plugins populares a continuación:

||||
|---|---|---|
|[nMap (pre-instalado)](https://nmap.org/)|[NexPose (pre-instalado)](https://sectools.org/tool/nexpose/)|[Nessus (pre-instalado)](https://www.tenable.com/products/nessus)|
|[Mimikatz (pre-instalado V.1)](http://blog.gentilkiwi.com/mimikatz)|[Stdapi (pre-instalado)](https://www.rubydoc.info/github/rapid7/metasploit-framework/Rex/Post/Meterpreter/Extensions/Stdapi/Stdapi)|[Railgun](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-Railgun-for-Windows-post-exploitation)|
|[Priv](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/post/meterpreter/extensions/priv/priv.rb)|[Incognito (pre-instalado)](https://www.offensive-security.com/metasploit-unleashed/fun-incognito/)|

[Darkoperator's](https://github.com/darkoperator/Metasploit-Plugins)|

---

## Mixins

El Metasploit Framework está escrito en Ruby, un lenguaje de programación orientado a objetos. Esto juega un papel importante en lo que hace que `msfconsole` sea excelente de usar. Mixins son una de esas características que, cuando se implementan, ofrecen una gran cantidad de flexibilidad tanto al creador del script como al usuario.

Mixins son clases que actúan como métodos para ser usados por otras clases sin tener que ser la clase padre de esas otras clases. Por lo tanto, sería inapropiado llamarlo herencia, sino más bien inclusión. Se usan principalmente cuando:

1. Queremos proporcionar muchas características opcionales para una clase.
2. Queremos usar una característica particular para una multitud de clases.

La mayoría del lenguaje de programación Ruby gira en torno a Mixins como Módulos. El concepto de Mixins se implementa usando la palabra `include`, a la que pasamos el nombre del módulo como un `parámetro`. Podemos leer más sobre mixins [aquí](https://en.wikibooks.org/wiki/Metasploit/UsingMixins).

Si recién estamos comenzando con Metasploit, no deberíamos preocuparnos por el uso de Mixins o su impacto en nuestra evaluación. Sin embargo, se mencionan aquí como una nota de cuán compleja puede llegar a ser la personalización de Metasploit.