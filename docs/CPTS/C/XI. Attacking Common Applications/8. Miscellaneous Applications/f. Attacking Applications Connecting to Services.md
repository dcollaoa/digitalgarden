## ELF Executable Examination

El binary `octopus_checker` se encuentra en una máquina remota durante la prueba. Ejecutar la aplicación localmente revela que se conecta a instancias de base de datos para verificar que estén disponibles.

```r
./octopus_checker 

Program had started..
Attempting Connection 
Connecting ... 

The driver reported the following diagnostics whilst running SQLDriverConnect

01000:1:0:[unixODBC][Driver Manager]Can't open lib 'ODBC Driver 17 for SQL Server' : file not found
connected
```

El binary probablemente se conecta utilizando una SQL connection string que contiene credenciales. Utilizando herramientas como [PEDA](https://github.com/longld/peda) (Python Exploit Development Assistance for GDB) podemos examinar más a fondo el archivo. Esta es una extensión del GNU Debugger (GDB) estándar, que se usa para depurar programas en C y C++. GDB es una herramienta de línea de comandos que permite recorrer el código, establecer breakpoints y examinar y cambiar variables. Ejecutando el siguiente comando podemos ejecutar el binary a través de él.

```r
gdb ./octopus_checker

GNU gdb (Debian 9.2-1) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./octopus_checker...
(No debugging symbols found in ./octopus_checker)
```

Una vez que el binary está cargado, configuramos el `disassembly-flavor` para definir el estilo de visualización del código, y procedemos a desensamblar la función principal del programa.

```r
gdb-peda$ set disassembly-flavor intel
gdb-peda$ disas main

Dump of assembler code for function main:
   0x0000555555555456 <+0>:	endbr64 
   0x000055555555545a <+4>:	push   rbp
   0x000055555555545b <+5>:	mov    rbp,rsp
 
 <SNIP>
 
   0x0000555555555625 <+463>:	call   0x5555555551a0 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
   0x000055555555562a <+468>:	mov    rdx,rax
   0x000055555555562d <+471>:	mov    rax,QWORD PTR [rip+0x299c]        # 0x555555557fd0
   0x0000555555555634 <+478>:	mov    rsi,rax
   0x0000555555555637 <+481>:	mov    rdi,rdx
   0x000055555555563a <+484>:	call   0x5555555551c0 <_ZNSolsEPFRSoS_E@plt>
   0x000055555555563f <+489>:	mov    rbx,QWORD PTR [rbp-0x4a8]
   0x0000555555555646 <+496>:	lea    rax,[rbp-0x4b7]
   0x000055555555564d <+503>:	mov    rdi,rax
   0x0000555555555650 <+506>:	call   0x555555555220 <_ZNSaIcEC1Ev@plt>
   0x0000555555555655 <+511>:	lea    rdx,[rbp-0x4b7]
   0x000055555555565c <+518>:	lea    rax,[rbp-0x4a0]
   0x0000555555555663 <+525>:	lea    rsi,[rip+0xa34]        # 0x55555555609e
   0x000055555555566a <+532>:	mov    rdi,rax
   0x000055555555566d <+535>:	call   0x5555555551f0 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3_@plt>
   0x0000555555555672 <+540>:	lea    rax,[rbp-0x4a0]
   0x0000555555555679 <+547>:	mov    edx,0x2
   0x000055555555567e <+552>:	mov    rsi,rbx
   0x0000555555555681 <+555>:	mov    rdi,rax
   0x0000555555555684 <+558>:	call   0x555555555329 <_Z13extract_errorNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPvs>
   0x0000555555555689 <+563>:	lea    rax,[rbp-0x4a0]
   0x0000555555555690 <+570>:	mov    rdi,rax
   0x0000555555555693 <+573>:	call   0x555555555160 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev@plt>
   0x0000555555555698 <+578>:	lea    rax,[rbp-0x4b7]
   0x000055555555569f <+585>:	mov    rdi,rax
   0x00005555555556a2 <+588>:	call   0x5555555551d0 <_ZNSaIcED1Ev@plt>
   0x00005555555556a7 <+593>:	cmp    WORD PTR [rbp-0x4b2],0x0

<SNIP>

   0x0000555555555761 <+779>:	mov    rbx,QWORD PTR [rbp-0x8]
   0x0000555555555765 <+783>:	leave  
   0x0000555555555766 <+784>:	ret    
End of assembler dump.
```

Esto revela varias instrucciones de llamada que apuntan a direcciones que contienen strings. Parecen ser secciones de una SQL connection string, pero las secciones no están en orden y la endianess implica que el texto de la cadena está invertido. La endianess define el orden en que se leen los bytes en diferentes arquitecturas. Más adelante en la función, vemos una llamada a SQLDriverConnect.

```r
   0x00005555555555ff <+425>:	mov    esi,0x0
   0x0000555555555604 <+430>:	mov    rdi,rax
   0x0000555555555607 <+433>:	call   0x5555555551b0 <SQLDriverConnect@plt>
   0x000055555555560c <+438>:	add    rsp,0x10
   0x0000555555555610 <+442>:	mov    WORD PTR [rbp-0x4b4],ax
```

Agregar un breakpoint en esta dirección y ejecutar el programa una vez más, revela una SQL connection string en la dirección del registro RDX, que contiene las credenciales para una instancia de base de datos local.

```r
gdb-peda$ b *0x5555555551b0

Breakpoint 1 at 0x5555555551b0


gdb-peda$ run

Starting program: /htb/rollout/octopus_checker 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Program had started..
Attempting Connection 
[----------------------------------registers-----------------------------------]
RAX: 0x55555556c4f0 --> 0x4b5a ('ZK')
RBX: 0x0 
RCX: 0xfffffffd 
RDX: 0x7fffffffda70 ("DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost, 1401;UID=username;PWD=password;")
RSI: 0x0 
RDI: 0x55555556c4f0 --> 0x4b5a ('ZK')

<SNIP>
```

Además de intentar conectarse al servicio MS SQL, los penetration testers también pueden verificar si la contraseña es reutilizable por usuarios de la misma red.

---

## DLL File Examination

Un archivo DLL es una `Dynamically Linked Library` y contiene código que es llamado por otros programas mientras están en ejecución. El binary `MultimasterAPI.dll` se encuentra en una máquina remota durante el proceso de enumeración. El examen del archivo revela que se trata de un ensamblado .Net.

```r
C:\> Get-FileMetaData .\MultimasterAPI.dll

<SNIP>
M .NETFramework,Version=v4.6.1 TFrameworkDisplayName.NET Framework 4.6.1    api/getColleagues        ! htt
p://localhost:8081*POST         Ò^         øJ  ø,  RSDSœ»¡ÍuqœK£"Y¿bˆ   C:\Users\Hazard\Desktop\Stuff\Multimast
<SNIP>
```

Utilizando el debugger y .NET assembly editor [dnSpy](https://github.com/0xd4d/dnSpy), podemos ver el código fuente directamente. Esta herramienta permite leer, editar y depurar el código fuente de un ensamblado .NET (C# y Visual Basic). La inspección de `MultimasterAPI.Controllers` -> `ColleagueController` revela una database connection string que contiene la contraseña.

![dnspy_hidden](https://academy.hackthebox.com/storage/modules/113/apps_conn_to_services/dnspy_hidden.png)

Además de intentar conectarse al servicio MS SQL, ataques como password spraying también pueden ser utilizados para probar la seguridad de otros servicios.
