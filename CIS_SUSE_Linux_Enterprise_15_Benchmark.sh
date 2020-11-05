
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


# #################################################### ###########################################################
# 1. 3 CONFIGURACION SUDO 
# #################################################################################################################

# 1.3.1 Asegúrese de que sudo esté instalado (automatizado)
 # sudo permite a un usuario autorizado ejecutar un comando como superusuario u otro usuario, como especificado por la política de seguridad.
 rpm -q sudo
#Ejecute el siguiente comando para instalar sudo.
 zypper install sudo

#1.3.2 Asegúrese de que los comandos sudo usen pty (automatizado)

# Los atacantes pueden ejecutar un programa malicioso usando sudo, que nuevamente bifurcaría un fondo proceso que permanece incluso cuando el programa principal ha terminado de ejecutarse.
#Esto se puede mitigar configurando sudo para ejecutar otros comandos solo desde un pseudo-pty, si el registro de E / S está activado o no.

#Edite el archivo / etc / sudoers o un archivo en /etc/sudoers.d/ con visudo o visudo -f <PATH ARCHIVO> y agregue la siguiente línea: Defaults use_pty
vim etc/sudoers.d/
#agrega la siguiente linea 
visudo -f <Defaults use_pty>

#1.3.3 Asegúrese de que el archivo de registro de sudo exista (automatizado)
# sudo puede usar un archivo de registro personalizado

#Verifique que sudo tenga un archivo de registro personalizado configurado Ejecute el siguiente comando:
# grep -Ei '^\s*Defaults\s+([^#;]+,\s*)?logfile\s*=\s*(")?[^#;]+(")?'
/etc/sudoers /etc/sudoers.d/*Defaults logfile="/var/log/sudo.log"

# edite el archivo / etc / sudoers o un archivo en /etc/sudoers.d/ con visudo o visudo -f <PATH ARCHIVO> y agregue la siguiente línea:
Defaults logfile="/var/log/sudo.log"
vi/etc/sudoers.d/
visudo -f <Defaults logfile="/var/log/sudo.log">

####################################################################################################
# 1.4 Comprobación de la integridad del sistema de archivos
#AIDE es una herramienta de verificación de integridad de archivos
###############################################################################################################

# 1.4.1  Asegúrese de que AIDE esté instalado (automatizado)

#AIDE toma una instantánea del estado del sistema de archivos, incluidos los tiempos de modificación, los permisos yhashes de archivos que luego se pueden usar para comparar con el estado actual del sistema de archivos para
#detectar modificaciones en el sistema.

#Ejecute el siguiente comando y verifique que el asistente esté instalado:
 rpm -q aide
#Configure AIDE según corresponda a su entorno Ejecute el siguiente comando para instalar AIDE
  zypper install aide 
  #Ejecute los siguientes comandos para inicializar AIDE:
   aide --init
 mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
 
 # 1.4.2 Asegúrese de que la integridad del sistema de archivos se verifique con regularidad (automatizado)
 
 #La verificación periódica de archivos permite al administrador del sistema determinar de forma regular si Los archivos críticos se han modificado de forma no autorizada.
 
 #Ejecute los siguientes comandos para determinar si hay un trabajo cron programado para ejecutar el asistente
  crontab -u root -l | grep aide
  grep -r aide /etc/cron.* /etc/crontab
  
  #Ejecute los siguientes comandos para verificar que aidecheck.service y aidcheck.timer estén habilitado y aidecheck.timer se está ejecutando
  systemctl is-enabled aidecheck.service
systemctl is-enabled aidecheck.timer
systemctl status aidecheck.timer

#Si cron se utilizará para programar y ejecutar la verificación auxiliar Ejecute el siguiente comando:
crontab -u root -e
#Agregue la siguiente línea al crontab
0 5 * * * /usr/sbin/aide --check
O
#Si aidecheck.service y aidecheck.timer se usarán para programar y ejecutar la verificación de asistentes:
#Cree o edite el archivo /etc/systemd/system/aidecheck.service y agregue lo siguiente líneas: 
vi /etc/system/aidecheck.service 

[Unit]
Description=Aide Check
[Service]
Type=simple
ExecStart=/usr/sbin/aide --check
[Install]
WantedBy=multi-user.target

#Cree o edite el archivo /etc/systemd/system/aidecheck.timer y agregue las siguientes líneas:
vi  /etc/systemd/system/aidecheck.timer 

[Unit]
Description=Aide check every day at 5AM
[Timer]
OnCalendar=*-*-* 05:00:00
Unit=aidecheck.service
[Install]
WantedBy=multi-user.target

#Ejecute los siguientes comandos:
 chown root:root /etc/systemd/system/aidecheck.*
chmod 0644 /etc/systemd/system/aidecheck.*
 systemctl daemon-reload
 systemctl enable aidecheck.service
 systemctl --now enable aidecheck.timer

##########################################################################################################################
#1.5 Configuración de arranque seguro
# se centran en proteger el cargador de arranque y la configuración involucrado en el proceso de arranque directamente.
  #########################################################################################################################

#1.5.1 Asegúrese de que la contraseña del cargador de arranque esté configurada (automatizada)
#Configurar la contraseña del cargador de arranque requerirá que cualquier persona que reinicie el sistema debe ingresar
#una contraseña antes de poder establecer los parámetros de arranque de la línea de comandos
#Ejecute los siguientes comandos:
 grep "^\s*set superusers" /boot/grub2/grub.cfg
set superusers="<cintya >"
# grep "^\s*password" /boot/grub2/grub.cfg
password_pbkdf2 <username> <encrypted-password>

#Cree una contraseña cifrada con grub2-mkpasswd-pbkdf2:
 grub2-mkpasswd-pbkdf2
Enter password: <xxxxxxxx>
Reenter password: <xxxxxxx>
Your PBKDF2 is <xxxxxxxxxxxxx>

#agregue lo siguiente en /etc/grub.d/40_custom
 vi /etc/grub.d/40_custom
 set superusers="<cintya>"
password_pbkdf2 <username> <encrypted-password>

#Ejecute el siguiente comando para actualizar la configuración de grub2:
 grub2-mkconfig -o /boot/grub2/grub.cfg

#1.5.2 Ensure permissions on bootloader config are configured (Automated)

#Establecer los permisos de lectura y escritura para root solo evita que los usuarios no root ver los parámetros de arranque o cambiarlos. Usuarios no root que leen el arranque
#los parámetros pueden identificar debilidades en la seguridad al arrancar y ser capaces de explotar ellos.

#Ejecute el siguiente comando y verifique que Uid y Gid sean 0 / root y que Access no otorgue permisos para agrupar u otros:
 stat /boot/grub2/grub.cfg

#Ejecute los siguientes comandos para establecer la propiedad y los permisos en su grub configuración:
chown root:root /boot/grub2/grub.cfg
 chmod og-rwx /boot/grub2/grub.cfg
 
 #1.5.3 Asegurar la autenticación requerida para el modo de usuario único (automatizado)
 
#El modo de usuario único (modo de rescate) se utiliza para la recuperación cuando el sistema detecta un problema durante el arranque o por selección manual desde el gestor de arranque.

# Ejecute los siguientes comandos y verifique que se use / sbin / sulogin o / usr / sbin / sulogin
 grep /systemd-sulogin-shell /usr/lib/systemd/system/rescue.service
 grep /systemd-sulogin-shell /usr/lib/systemd/system/emergency.service

#Edite /usr/lib/systemd/system/rescue.service y agregue / modifique la siguiente línea:
 vi /urs/lib/systemd/system/rescue.service
 ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue
 
 #edite /usr/lib/systemd/system/emergency.service y agregue / modifique la siguiente línea:
 vi /usr/lib/systemd/system/emergency.service
 ExecStart=-/usr/lib/systemd/systemd-sulogin-shell emergency
 
