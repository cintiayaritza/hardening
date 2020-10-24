
# pacheco Mex cintya yaritza

#! / bin / sh
# ############################################## ####
# ############################################## #
# cis_ suse_enterprice_15_benchmark_v1.0.0.0

# 1 ° configuración inicial
# ############################################## #####

# En este scrip debes de tener en cuenta estos factores
#instalar opensuse de la pagina oficial 


# 1.1.1 el montaje de los sistemas de archivos squashfs esté deshabilitado

# crear el archivo 0 editar el archivo  squashfs / bin / true
  vi etc/modprobe.d/squashfs.conf
  #agregar la linea el siguiente comando
  install squashfs /bin/true
  #correr el programa con el siguiente comando para ejecutar el mudulo squashfs
  modprobe -r squashfs 

#1.1.1.2  Asegúrese de que el montaje de sistemas de archivos udt sea limitado (manual)
# crear el archivo o editar  udfc etc/modprobe en directorio conf 
vi etc/modprobe.d/udt.conf
 #agregar la linea el siguiente comando
  install udt /bin/true
  #correr el programa con el siguiente comando para ejecutar el mudulo udt
  modprobe -r udt
  
#1.1.1.3  Asegúrese de que el montaje de sistemas de archivos FAT sea limitado (manual)
#El formato del sistema de archivos FAT se usa principalmente en sistemas Windows más antiguos y USB portátil
#unidades o módulos flash. Viene en tres tipos FAT12, FAT16 y FAT32, todos los cuales son
#soportado por el módulo del kernel vfat.
 #crear el archivo o editar /etc/modprobe.d/ de archivo fat y ponerle directorio .conf
vi etc/modprobe.d/fat.conf
 #agregar la linea el siguiente comando
  install fat /bin/true
install vfat /bin/true
install msdos /bin/true
  
  #correr el programa con el siguiente comando para ejecutar el modulo fat
  modprobe -r fat
   modprobe -r msdos
modprobe -r vfat
 
#1.1.2 Asegúrese de que / tmp esté configurado (automatizado)

#El directorio / tmp es un directorio de escritura mundial utilizado para almacenamiento temporal por todos los usuarios
#y algunas aplicaciones.

#Ejecute el siguiente comando y verifique que la salida shows / tmp esté montada:
mount | grep -E '\s/tmp\s'
tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)

#Ejecute el siguiente comando y verifique que tmpfs se haya montado en un sistemase ha creado la partición para / tmp
 grep -E '\s/tmp\s' /etc/fstab | grep -E -v '^\s*#'
  tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0
  
  # Ejecute el siguiente comando y verifique que tmp.mount esté habilitado
   systemctl is-enabled tmp.mount
enabled

#Ejecute el siguiente comando para crear el archivo /etc/systemd/system/tmp.mount sino existe
  [ ! -f /etc/systemd/system/tmp.mount ] && cp -v
/usr/share/systemd/tmp.mount /etc/systemd/system/


#Edit the file /etc/systemd/system/tmp.mount:
vim  /tmp/etc/systemd/tmp.mount

#correr el siguiente comando para cargar sistema de nuevo 
 systemctl daemon-reload
#Ejecute el siguiente comando para desenmascarar tmp.mount:
 systemctl unmask tmp.mpunt
#Ejecute el siguiente comando para habilitar e iniciar tmp.mount:
 systemctl enable --now tmp.mount
 
# 1.1.4 Asegúrese de que la opción nodev esté configurada en la partición / tmp (automatizada)
#Edite el archivo / etc / fstab O el archivo /etc/systemd/system/localfs.target.wants/tmp.mount:
SI / etc / fstab se usa para montar / tmp:
#Edite el archivo / etc / fstab y agregue nodev al cuarto campo (opciones de montaje) para / tmp
vim /tmp/etc/systemd/system/local-fs.target.wants/tmp.mount

montar -o volver a montar, nodev/tmp/etc/systemd/system/local-fs.target.wants/tmp.mount


# 1.1.5 Asegúrese de que la opción nosuid esté configurada en la partición / tmp (automatizada)
vim etc/systemd/system/local-fs.target.wants/tmp.mountnosuid/tmp
vim etc/systemd/system/local-fs.target.wants/tmp.mount
montar -o volver a montar, nosuid /tmp/etc/systemd/system/local-fs.target.wants/tmp.mount

#1.1.6 Asegúrese de que / dev / shm esté configurado (automatizado)
#/ dev / shm es un concepto tradicional de memoria compartida. Un programa creará una memoriaporción, a la que otros procesos (si están permitidos) pueden acceder. Si / dev / shm no está configurado,
#tmpfs será montado en / dev / shm por systemd.
#Notas:
#Una entrada para / dev / shm en / etc / fstab tendrá prioridad.
 #Se puede cambiar el tamaño de tmpfs usando el parámetro size = {size} en / etc / fstab. Si no especificamos el tamaño, será la mitad de la RAM
 
 #editar el archivo etc/fstab y agregarle la linea lo siguiente
 
 tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid 0 0
 #Ejecute el siguiente comando para volver a montar / dev / shm
  mount ,noexec,nodev,nosuid /dev/shm

# 1.1.7 Asegúrese de que la opción noexec esté configurada en la partición / dev / shm
#Edite el archivo / etc / fstab y agregue noexec al cuarto campo (opciones de montaje) para el Partición / dev / shm. Ver el fstab (5)
vim / dev / shm / etc / fstab
montar -o remontar,
vim  noexec / dev / shm / etc / fstab
# 1.1.8 Asegúrese de que la opción nodev esté configurada en la partición / dev / shm
vim  nodev / dev / shm / etc / fstab
# 1.1.9 Asegúrese de que la opción nosuid esté configurada en la partición / dev / shm
vim  nosuid/ dev / shm / etc / fstab

# 1.1.10 Asegúrese de que exista una partición separada para / var
#Para nuevas instalaciones, durante la instalación, cree una configuración de partición personalizada y especifique un partición separada para / var.
#Para los sistemas que se instalaron previamente, cree una nueva partición y configure / etc / fstab según corresponda.
echo  " crear var / fstab "
> / var / etc / fstab
# 1.1.11 Asegúrese de que exista una partición separada para / var / tmp
echo  " crear var / tmp "
> / var / tmp / etc / fstab

#
# 1.1.12 Asegúrese de que la opción noexec esté configurada en la partición / var / tmp
#Edite el archivo / etc / fstab y agregue noexec al cuarto campo (opciones de montaje) 
vim / var / tmp / etc / fstab
montar -o remontar, noexec / var / tmp / etc / fstab
 #1.1.13 Asegúrese de que la opción nodev esté configurada en la partición / var / tmp
 #Edite el archivo / etc / fstab y agregue noexec al cuarto campo (opciones de montaje)
vim /nodev/ var / tmp / etc / fstab
 
# 1.1.14 Asegúrese de que la opción nosuid esté configurada en la partición / var / tmp
#Edite el archivo / etc / fstab y agregue noexec al cuarto campo (opciones de montaje)
vim nosuid / var / tmp / etc / fstab

# 1.1.15 Asegúrese de que exista una partición separada para / var / log
#Para nuevas instalaciones, durante la instalación, cree una configuración de partición personalizada y especifique un
#partición separada para / var / log.
#Para los sistemas que se instalaron previamente, cree una nueva partición y configure
/ etc / fstab según corresponda
echo  " crear / var / log "
< / var / log / etc / fsbat

# 1.1.16 Asegúrese de que exista una partición separada para / var / log / audit
#Para nuevas instalaciones, durante la instalación, cree una configuración de partición personalizada y especifique un
#partición separada para / var / log / audit.
#Para los sistemas que se instalaron previamente, cree una nueva partición y configure
/ etc / fstab según corresponda
echo  " crear / var / log / audit "
< / var / log / audit / etc / fstab

# 1.1.17 Asegúrese de que exista una partición separada para / home
#Para nuevas instalaciones, durante la instalación, cree una configuración de partición personalizada y especifique un Partición separada para / home.
#Para los sistemas que se instalaron previamente, cree una nueva partición y configure / etc / fstab según corresponda.
echo  " crear / home "
< / home / etc / fstab

# 1.1.18 Asegúrese de que la opción nodev esté configurada en la partición / home
#Edite el archivo / etc / fstab y agregue nodev al cuarto campo (opciones de montaje) para / home dividir. 
#Ejecute el siguiente comando para volver a montar / home / con la opción de montaje nodev
vi /home/etc/fstab

vi nodev/home/etc/fstab/
#1.1.19 Asegúrese de que la opción noexec esté configurada en particiones de medios extraíbles
#Establecer esta opción en un sistema de archivos evita que los usuarios ejecuten programas desde media removible. Esto disuade a los usuarios de poder introducir software en el sistema.

#Edite el archivo / etc / fstab y agregue noexec al cuarto campo (opciones de montaje) de todos
#particiones de medios extraíbles. Busque entradas que tengan puntos de montaje que contengan palabras como disquete o cdrom.
 grep <cada punto de montaje de medio extraíble> / etc / fstab
 grep <noexec> / etc / fstab

montar -o volver a montar, noexec/tmp/etc/systemd/system/local-fs.target.wants/tmp.mount


#1.1.20 Asegúrese de que la opción nodev esté configurada en particiones de medios extraíbles
 grep <cada punto de montaje de medio extraíble> / etc / fstab
 grep <nodev> / etc / fstab

#1.1.21 Asegúrese de que la opción nosuid esté configurada en particiones de medios extraíbles
 grep <cada punto de montaje de medio extraíble> / etc / fstab
 





# 1.1.22 Asegúrese de que el bit world-writable esté configurado en todos los directorios de escritura
#Esta característica evita la capacidad de eliminar o cambiar el nombre de archivos en directorios de escritura mundial (como / tmp) que son propiedad de otro usuario
df --local -P | awk { ' if (NR! = 1) print $ 6 ' } | xargs -I ' {} ' buscar ' {} ' -xdev
-tipo d -perm -0002 2> / dev / null | xargs chmod a + t

# 1.1.19 Deshabilitar el montaje automático
#Con el montaje automático habilitado, cualquier persona con acceso físico podría conectar una unidad USB o un disco
#y tener su contenido disponible en el sistema incluso si no tenían permisos para montarlo sí mismos.
systemctl  is-enabled autofs
systemctl systemctl --now mask autofs


# ############################################## ################################################ ######
# 1.2 Configurar actualizaciones de software
# ############################################## ################################################ ##

# 1.2.2 Asegúrese de que las claves GPG estén configuradas
#Verifique que las claves GPG estén configuradas correctamente para su administrador de paquetes. Dependiendo de
#gestión de paquetes en uso, uno de los siguientes grupos de comandos puede proporcionar información:
 rpm -q gpg-pubkey --qf ' % {nombre} -% {versión} -% {versión} ->% {resumen} \ n '
 
# 1.2.1 Asegúrese de que los repositorios del administrador de paquetes estén configurados
#Ejecute el siguiente comando para verificar que los repositorios estén configurados correctamente:
 zypper repos

# 1.2.3 Asegúrese de que gpgcheck esté activado globalmente
#Es importante asegurarse de que la firma del paquete de un RPM siempre se verifique antes de instalación para garantizar que el software se obtenga de una fuente confiable
 grep ^\s*gpgcheck /etc/zypp/zypp.conf
gpgcheck=1


#Edite /etc/zypp/zypp.conf y configure 'gpgcheck = 1' en la sección [principal].
#Edite los archivos que fallan en /etc/zypp/repos.d/*.repo y configure todas las instancias de gpgcheck en 1.
vim /etc/zypp.sed -l ' s / gpgcheck = 0 / gpgcheck = 1 / g ' /etc/zypp/zypp.conf

