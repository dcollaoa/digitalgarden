Para comenzar a interactuar con el Metasploit Framework, necesitamos escribir `msfconsole` en la terminal de nuestra elección. Muchas distribuciones orientadas a la seguridad como Parrot Security y Kali Linux vienen con `msfconsole` preinstalado. Podemos usar varias otras opciones al lanzar el script, como con cualquier otra herramienta de línea de comandos. Estas varían desde opciones de visualización gráfica hasta opciones procedimentales.

---
## Preparation

Al iniciar el `msfconsole`, nos encontramos con su característico arte de bienvenida y el prompt de la línea de comandos, esperando nuestro primer comando.

### Launching MSFconsole

```r
msfconsole
                                                  
                                              `:oDFo:`                            
                                           ./ymM0dayMmy/.                          
                                        -+dHJ5aGFyZGVyIQ==+-                    
                                    `:sm⏣~~Destroy.No.Data~~s:`                
                                 -+h2~~Maintain.No.Persistence~~h+-              
                             `:odNo2~~Above.All.Else.Do.No.Harm~~Ndo:`          
                          ./etc/shadow.0days-Data'%20OR%201=1--.No.0MN8'/.      
                       -++SecKCoin++e.AMd`       `.-://///+hbove.913.ElsMNh+-    
                      -~/.ssh/id_rsa.Des-                  `htN01UserWroteMe!-  
                      :dopeAW.No<nano>o                     :is:TЯiKC.sudo-.A:  
                      :we're.all.alike'`                     The.PFYroy.No.D7:  
                      :PLACEDRINKHERE!:                      yxp_cmdshell.Ab0:    
                      :msf>exploit -j.                       :Ns.BOB&ALICEes7:    
                      :---srwxrwx:-.`                        `MS146.52.No.Per:    
                      :<script>.Ac816/                        sENbove3101.404:    
                      :NT_AUTHORITY.Do                        `T:/shSYSTEM-.N:    
                      :09.14.2011.raid                       /STFU|wall.No.Pr:    
                      :hevnsntSurb025N.                      dNVRGOING2GIVUUP:    
                      :#OUTHOUSE-  -s:                       /corykennedyData:    
                      :$nmap -oS                              SSo.6178306Ence:    
                      :Awsm.da:                            /shMTl#beats3o.No.:    
                      :Ring0:                             `dDestRoyREXKC3ta/M:    
                      :23d:                               sSETEC.ASTRONOMYist:    
                       /-                        /yo-    .ence.N:(){ :|: & };:    
                                                 `:Shall.We.Play.A.Game?tron/    
                                                 ```-ooy.if1ghtf0r+ehUser5`    
                                               ..th3.H1V3.U2VjRFNN.jMh+.`          
                                              `MjM~~WE.ARE.se~~MMjMs              
                                               +~KANSAS.CITY's~-`                  
                                                J~HAKCERS~./.`                    
                                                .esc:wq!:`                        
                                                 +++ATH`                            
                                                  `


       =[ metasploit v6.1.9-dev                           ]
+ -- --=[ 2169 exploits - 1149 auxiliary - 398 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Use sessions -1 to interact with the last opened session

msf6 > 
```

Alternativamente, podemos usar la opción `-q`, que no muestra el banner.

```r
msfconsole -q

msf6 > 
```

Para ver mejor todos los comandos disponibles, podemos escribir el comando `help`. Primero que nada, nuestras herramientas deben estar afiladas. Una de las primeras cosas que debemos hacer es asegurarnos de que los módulos que componen el framework estén actualizados y que cualquier nuevo módulo disponible para el público pueda ser importado.

La forma antigua era ejecutar `msfupdate` en nuestra terminal del sistema operativo (fuera de `msfconsole`). Sin embargo, el gestor de paquetes `apt` puede manejar actualmente la actualización de módulos y características sin esfuerzo.

### Installing MSF

```r
sudo apt update && sudo apt install metasploit-framework

<SNIP>

(Reading database ... 414458 files and directories currently installed.)
Preparing to unpack .../metasploit-framework_6.0.2-0parrot1_amd64.deb ...
Unpacking metasploit-framework (6.0.2-0parrot1) over (5.0.88-0kali1) ...
Setting up metasploit-framework (6.0.2-0parrot1) ...
Processing triggers for man-db (2.9.1-1) ...
Scanning application launchers
Removing duplicate launchers from Debian
Launchers are updated
```

Uno de los primeros pasos que cubriremos en este módulo es buscar un `exploit` adecuado para nuestro `target`. Sin embargo, necesitamos tener una perspectiva detallada del `target` antes de intentar cualquier explotación. Esto implica el proceso de `Enumeration`, que precede cualquier tipo de intento de explotación.

Durante la `Enumeration`, debemos observar nuestro objetivo e identificar qué servicios públicos están ejecutándose en él. Por ejemplo, ¿es un servidor HTTP? ¿Es un servidor FTP? ¿Es una base de datos SQL? Estos diferentes `target` varían sustancialmente en el mundo real. Necesitaremos comenzar con un `scan` exhaustivo de la dirección IP del objetivo para determinar qué servicio se está ejecutando y qué versión está instalada para cada servicio.

Notaremos a medida que avancemos que las versiones son los componentes clave durante el proceso de `Enumeration` que nos permitirán determinar si el objetivo es vulnerable o no. Las versiones no parcheadas de servicios previamente vulnerables o el código desactualizado en una plataforma accesible públicamente serán a menudo nuestro punto de entrada al sistema objetivo.

---
## MSF Engagement Structure

La estructura de compromiso de MSF puede dividirse en cinco categorías principales.

- Enumeration
- Preparation
- Exploitation
- Privilege Escalation
- Post-Exploitation

Esta división facilita encontrar y seleccionar las características adecuadas de MSF de una manera más estructurada y trabajar con ellas en consecuencia. Cada una de estas categorías tiene diferentes subcategorías que están destinadas a propósitos específicos. Estas incluyen, por ejemplo, Validación de Servicios e Investigación de Vulnerabilidades.

Por lo tanto, es crucial que nos familiaricemos con esta estructura. Examinaremos los componentes de este framework para comprender mejor cómo están relacionados.

![image](https://academy.hackthebox.com/storage/modules/39/S04_SS03.png)

Revisaremos cada una de estas categorías durante el módulo, pero recomendamos mirar los componentes individuales por nuestra cuenta y profundizar más. Experimentar con las diferentes funciones es una parte integral del aprendizaje de una nueva herramienta o habilidad. Por lo tanto, deberíamos probar todo lo imaginable aquí en los siguientes laboratorios y analizar los resultados de manera independiente.