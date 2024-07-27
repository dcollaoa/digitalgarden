[OpenVAS](https://openvas.org/), de Greenbone Networks, es un escáner de vulnerabilidades disponible públicamente. Greenbone Networks tiene un completo Gestor de Vulnerabilidades, parte del cual es el escáner OpenVAS. El Gestor de Vulnerabilidades de Greenbone también está abierto al público y es gratuito. OpenVAS tiene la capacidad de realizar escaneos de red, incluidos los tests autenticados y no autenticados.

![image](https://academy.hackthebox.com/storage/modules/108/openvas/Greenbone_Security_Assistant.png)

Empezaremos a usar OpenVAS siguiendo las instrucciones de instalación a continuación para Parrot Security. La herramienta está preinstalada en el host proporcionado en una sección posterior.

---

## Installing Package

Primero, podemos empezar instalando la herramienta:

```r
sudo apt-get update && apt-get -y full-upgrade
sudo apt-get install gvm && openvas
```

A continuación, para comenzar el proceso de instalación, podemos ejecutar el siguiente comando:

```r
gvm-setup
```

Esto comenzará el proceso de configuración y tomará hasta 30 minutos.

![image](https://academy.hackthebox.com/storage/modules/108/openvas/gvmsetup.png)

---

## Starting OpenVAS

Finalmente, podemos iniciar OpenVAS:

```r
gvm-start
```

![image](https://academy.hackthebox.com/storage/modules/108/openvas/gvmstart.png)

**Nota:** La VM proporcionada en la sección `OpenVAS Skills Assessment` tiene OpenVAS preinstalado y los objetivos en ejecución. Puedes ir a esa sección, iniciar la VM y usar OpenVAS a lo largo del módulo, al que se puede acceder en `https://< IP >:8080`. Las credenciales de OpenVAS son: `htb-student`:`HTB_@cademy_student!`. También puedes usar estas credenciales para hacer SSH en la VM objetivo para configurar OpenVAS.