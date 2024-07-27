OpenVAS proporciona los resultados del escaneo en un informe que se puede acceder cuando estás en la página `Scans`, como se muestra a continuación.

![viewreport](https://academy.hackthebox.com/storage/modules/108/openvas/viewingreport.png)

Una vez que haces clic en el informe, puedes ver los resultados del escaneo e información del sistema operativo, puertos abiertos, servicios, etc., en otras pestañas del informe de escaneo.

![results](https://academy.hackthebox.com/storage/modules/108/openvas/openvas_reports.png)

---

## Exporting Formats

Hay varios formatos de exportación para fines de informes, incluyendo XML, CSV, PDF, ITG y TXT. Si eliges exportar tu informe como XML, puedes utilizar varios analizadores de XML para ver los datos en un formato más fácil de leer.

![openvas_reportformats](https://academy.hackthebox.com/storage/modules/108/openvas/reportformat.png)

Exportaremos nuestros resultados en XML y usaremos la herramienta [openvasreporting](https://github.com/TheGroundZero/openvasreporting) de TheGroundZero. La herramienta `openvasreporting` ofrece varias opciones al generar la salida. Usaremos la opción estándar para un archivo Excel para este informe.

```r
python3 -m openvasreporting -i report-2bf466b5-627d-4659-bea6-1758b43235b1.xml -f xlsx
```

Este comando generará un documento Excel similar al siguiente:

![openvas_reportexcel](https://academy.hackthebox.com/storage/modules/108/openvas/openvas_report.png)

![report_toc](https://academy.hackthebox.com/storage/modules/108/openvas/report_toc.png)
