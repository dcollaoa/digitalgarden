Una vez que tenemos acceso a una máquina Windows objetivo a través de la GUI o CLI, podemos beneficiarnos significativamente al incorporar la búsqueda de credenciales en nuestro enfoque. `Credential Hunting` es el proceso de realizar búsquedas detalladas a través del sistema de archivos y diversas aplicaciones para descubrir credenciales. Para entender este concepto, pongámonos en un escenario. Hemos obtenido acceso a la estación de trabajo de un administrador de TI con Windows 10 a través de RDP.

---

## Search Centric

Muchas de las herramientas disponibles en Windows tienen funcionalidad de búsqueda. En esta era, hay características centradas en la búsqueda integradas en la mayoría de las aplicaciones y sistemas operativos, por lo que podemos usar esto a nuestro favor en un compromiso. Un usuario puede haber documentado sus contraseñas en algún lugar del sistema. Incluso puede haber credenciales predeterminadas que podrían encontrarse en varios archivos. Sería prudente basar nuestra búsqueda de credenciales en lo que sabemos sobre cómo se está utilizando el sistema objetivo. En este caso, sabemos que tenemos acceso a la estación de trabajo de un administrador de TI.

`¿Qué podría estar haciendo un administrador de TI en su día a día y cuáles de esas tareas podrían requerir credenciales?`

Podemos usar esta pregunta y consideración para refinar nuestra búsqueda y reducir la necesidad de adivinanzas al mínimo posible.

### Key Terms to Search

Ya sea que tengamos acceso a la GUI o CLI, sabemos que tendremos algunas herramientas para buscar, pero igual de importante es lo que exactamente estamos buscando. Aquí hay algunos términos clave útiles que podemos usar para ayudarnos a descubrir algunas credenciales:

| Passwords     | Passphrases   | Keys        |
|---------------|---------------|-------------|
| Username      | User account  | Creds       |
| Users         | Passkeys      | Passphrases |
| configuration | dbcredential  | dbpassword  |
| pwd           | Login         | Credentials |

Usemos algunos de estos términos clave para buscar en la estación de trabajo del administrador de TI.

---

## Search Tools

Con acceso a la GUI, vale la pena intentar usar `Windows Search` para encontrar archivos en el objetivo usando algunas de las palabras clave mencionadas anteriormente.

![Windows Search](https://academy.hackthebox.com/storage/modules/147/WindowsSearch.png)

Por defecto, buscará varias configuraciones del sistema operativo y el sistema de archivos para archivos y aplicaciones que contengan el término clave ingresado en la barra de búsqueda.

También podemos aprovechar herramientas de terceros como [Lazagne](https://github.com/AlessandroZ/LaZagne) para descubrir rápidamente credenciales que los navegadores web u otras aplicaciones instaladas puedan almacenar de manera insegura. Sería beneficioso tener una [copia autónoma](https://github.com/AlessandroZ/LaZagne/releases/) de Lazagne en nuestro host de ataque para poder transferirla rápidamente al objetivo. `Lazagne.exe` nos servirá bien en este escenario. Podemos usar nuestro cliente RDP para copiar el archivo al objetivo desde nuestro host de ataque. Si estamos usando `xfreerdp`, todo lo que debemos hacer es copiar y pegar en la sesión RDP que hemos establecido.

Una vez que Lazagne.exe esté en el objetivo, podemos abrir el símbolo del sistema o PowerShell, navegar al directorio donde se subió el archivo y ejecutar el siguiente comando:

### Running Lazagne All

```r
C:\Users\bob\Desktop> start lazagne.exe all
```

Esto ejecutará Lazagne y correrá todos los módulos incluidos. Podemos incluir la opción `-vv` para estudiar lo que está haciendo en segundo plano. Una vez que presionamos enter, se abrirá otro prompt y mostrará los resultados.

### Lazagne Output

```r
|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|


########## User: bob ##########

------------------- Winscp passwords -----------------

[+] Password found !!!
URL: 10.129.202.51
Login: admin
Password: SteveisReallyCool123
Port: 22
```

Si usamos la opción `-vv`, veríamos intentos de recopilar contraseñas de todo el software compatible con Lazagne. También podemos mirar en la página de GitHub en la sección de software compatible para ver todo el software del que Lazagne intentará recopilar credenciales. Puede ser un poco impactante ver lo fácil que puede ser obtener credenciales en texto claro. Gran parte de esto puede atribuirse a la forma insegura en que muchas aplicaciones almacenan credenciales.

### Using findstr

También podemos usar [findstr](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr) para buscar patrones en muchos tipos de archivos. Teniendo en cuenta los términos clave comunes, podemos usar variaciones de este comando para descubrir credenciales en un objetivo Windows:

```r
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

---

## Additional Considerations

Hay miles de herramientas y términos clave que podríamos usar para buscar credenciales en sistemas operativos Windows. Sepa que las que elijamos usar estarán principalmente basadas en la función de la computadora. Si llegamos a un sistema operativo Windows Server, podemos usar un enfoque diferente al de un sistema operativo de escritorio Windows. Siempre tenga en cuenta cómo se está utilizando el sistema, y esto nos ayudará a saber dónde buscar. A veces, incluso podemos encontrar credenciales navegando y listando directorios en el sistema de archivos mientras nuestras herramientas están en funcionamiento.

Aquí hay algunos otros lugares que debemos tener en cuenta al buscar credenciales:

- Contraseñas en Group Policy en el SYSVOL share
- Contraseñas en scripts en el SYSVOL share
- Contraseña en scripts en IT shares
- Contraseñas en archivos web.config en máquinas de desarrollo y IT shares
- unattend.xml
- Contraseñas en los campos de descripción del usuario o computadora de AD
- Bases de datos KeePass --> extraer hash, crackear y obtener mucho acceso.
- Encontradas en sistemas y comparticiones de usuarios
- Archivos como pass.txt, passwords.docx, passwords.xlsx encontrados en sistemas de usuarios, comparticiones, [Sharepoint](https://www.microsoft.com/en-us/microsoft-365/sharepoint/collaboration)

---

Has obtenido acceso a la estación de trabajo con Windows 10 de un administrador de TI y comienzas tu proceso de búsqueda de credenciales buscando credenciales en ubicaciones comunes de almacenamiento.

`Conéctate al objetivo y usa lo que has aprendido para descubrir las respuestas a las preguntas del desafío`.