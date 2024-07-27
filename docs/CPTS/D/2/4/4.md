The [Hyper-V Administrators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#hyper-v-administrators) group has full access to all [Hyper-V features](https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/use/manage-virtual-machines). If Domain Controllers have been virtualized, then the virtualization admins should be considered Domain Admins. They could easily create a clone of the live Domain Controller and mount the virtual disk offline to obtain the NTDS.dit file and extract NTLM password hashes for all users in the domain.

También está bien documentado en este [blog](https://decoder.cloud/2020/01/20/from-hyper-v-admin-to-system/), que al eliminar una máquina virtual, `vmms.exe` intenta restaurar los permisos de archivo originales en el archivo `.vhdx` correspondiente y lo hace como `NT AUTHORITY\SYSTEM`, sin suplantar al usuario. Podemos eliminar el archivo `.vhdx` y crear un enlace físico (hard link) nativo para apuntar este archivo a un archivo del sistema protegido, al cual tendremos permisos completos.

Si el sistema operativo es vulnerable a [CVE-2018-0952](https://www.tenable.com/cve/CVE-2018-0952) o [CVE-2019-0841](https://www.tenable.com/cve/CVE-2019-0841), podemos aprovechar esto para obtener privilegios de SYSTEM. De lo contrario, podemos intentar aprovechar una aplicación en el servidor que haya instalado un servicio que se ejecute en el contexto de SYSTEM, y que pueda ser iniciado por usuarios sin privilegios.

### Target File

Un ejemplo de esto es Firefox, que instala el `Mozilla Maintenance Service`. Podemos actualizar [este exploit](https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1) (una prueba de concepto para NT hard link) para otorgar a nuestro usuario actual permisos completos sobre el siguiente archivo:

```r
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```

### Taking Ownership of the File

Después de ejecutar el script de PowerShell, deberíamos tener control total de este archivo y podemos tomar posesión de él.

```r
C:\htb> takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```

### Starting the Mozilla Maintenance Service

A continuación, podemos reemplazar este archivo con un `maintenanceservice.exe` malicioso, iniciar el servicio de mantenimiento y obtener la ejecución de comandos como SYSTEM.

```r
C:\htb> sc.exe start MozillaMaintenance
```

Nota: Este vector ha sido mitigado por las actualizaciones de seguridad de Windows de marzo de 2020, que cambiaron el comportamiento relacionado con los hard links.