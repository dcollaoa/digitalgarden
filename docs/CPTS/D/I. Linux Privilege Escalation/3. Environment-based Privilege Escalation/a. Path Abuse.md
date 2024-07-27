[PATH](http://www.linfo.org/path_env_var.html) es una variable de entorno que especifica el conjunto de directorios donde se puede encontrar un ejecutable. La variable PATH de una cuenta es un conjunto de rutas absolutas, lo que permite a un usuario escribir un comando sin especificar la ruta absoluta del binario. Por ejemplo, un usuario puede escribir `cat /tmp/test.txt` en lugar de especificar la ruta absoluta `/bin/cat /tmp/test.txt`. Podemos comprobar el contenido de la variable PATH escribiendo `env | grep PATH` o `echo $PATH`.

```r
htb_student@NIX02:~$ echo $PATH

/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```

Crear un script o programa en un directorio especificado en el PATH lo hará ejecutable desde cualquier directorio en el sistema.

```r
htb_student@NIX02:~$ pwd && conncheck 

/usr/local/sbin
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1189/sshd       
tcp        0     88 10.129.2.12:22          10.10.14.3:43218        ESTABLISHED 1614/sshd: mrb3n [p
tcp6       0      0 :::22                   :::*                    LISTEN      1189/sshd       
tcp6       0      0 :::80                   :::*                    LISTEN      1304/apache2    
```

Como se muestra a continuación, el script `conncheck` creado en `/usr/local/sbin` aún se ejecutará cuando esté en el directorio `/tmp` porque se creó en un directorio especificado en el PATH.

```r
htb_student@NIX02:~$ pwd && conncheck 

/tmp
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1189/sshd       
tcp        0    268 10.129.2.12:22          10.10.14.3:43218        ESTABLISHED 1614/sshd: mrb3n [p
tcp6       0      0 :::22                   :::*                    LISTEN      1189/sshd       
tcp6       0      0 :::80                   :::*                    LISTEN      1304/apache2     
```

Agregar `.` al PATH de un usuario agrega su directorio de trabajo actual a la lista. Por ejemplo, si podemos modificar el PATH de un usuario, podríamos reemplazar un binario común como `ls` con un script malicioso como un reverse shell. Si agregamos `.` al PATH emitiendo el comando `PATH=.:$PATH` y luego `export PATH`, podremos ejecutar binarios ubicados en nuestro directorio de trabajo actual simplemente escribiendo el nombre del archivo (es decir, al escribir `ls` se llamará al script malicioso llamado `ls` en el directorio de trabajo actual en lugar del binario ubicado en `/bin/ls`).

```r
htb_student@NIX02:~$ echo $PATH

/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```

```r
htb_student@NIX02:~$ PATH=.:${PATH}
htb_student@NIX02:~$ export PATH
htb_student@NIX02:~$ echo $PATH

.:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```

En este ejemplo, modificamos el PATH para ejecutar un simple comando `echo` cuando se escribe el comando `ls`.

```r
htb_student@NIX02:~$ touch ls
htb_student@NIX02:~$ echo 'echo "PATH ABUSE!!"' > ls
htb_student@NIX02:~$ chmod +x ls
```

```r
htb_student@NIX02:~$ ls

PATH ABUSE!!
```