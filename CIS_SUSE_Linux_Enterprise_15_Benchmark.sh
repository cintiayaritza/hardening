
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

# 1.4 Comprobación de la integridad del sistema de archivos
#AIDE es una herramienta de verificación de integridad de archivos

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

#1.5 Configuración de arranque seguro
# se centran en proteger el cargador de arranque y la configuración involucrado en el proceso de arranque directamente.

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

#########################################################################################################
#1.6 proceso adicional de hardening  
 ########################################################################################################
 
 # 1.6.1 Asegúrese de que los volcados de memoria estén restringidos (automatizados)
 #Establecer un límite estricto en los volcados de núcleo evita que los usuarios anulen la variable flexible. Si el núcleo
#se requieren volcados, considere establecer límites para grupos de usuarios

#Ejecute los siguientes comandos y verifique las coincidencias de salida:
 grep -E "^\s*\*\s+hard\s+core" /etc/security/limits.conf/etc/security/limits.d/*
 sysctl fs.suid_dumpable
  grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*

#Ejecute el siguiente comando para verificar si systemd-coredump está instalado:
systemctl is-enabled coredump.service

#agregale la siguiente linea a archivo  /etc/security/limits.conf or a /etc/security/limits.d/*

vi /etc/security/limits.d/*
* hard core 0
#Establezca el siguiente parámetro en /etc/sysctl.conf o un archivo /etc/sysctl.d/*:
cat etc/sysct1.d/*
vi etc/sysctl.d/*
fs.suid_dumpable = 0

#Ejecute el siguiente comando para establecer el parámetro de kernel activo:
sysctl -w fs.suid_dumpable=0

#Si systemd-coredump está instalado:
#edite /etc/systemd/coredump.conf y agregue / modifique las siguientes líneas:

vi /etc/systemd/coredump.conf
Storage=none
ProcessSizeMax=0

#Ejecute el comando:
systemctl daemon-reload

#1.6.2 Asegúrese de que la compatibilidad con XD / NX esté habilitada (automatizada)
#Los procesadores recientes de la familia x86 admiten la capacidad de evitar la ejecución de código en un
#base de la página de memoria. Genéricamente y en procesadores AMD, esta capacidad se llama No Ejecutar
#(NX), mientras que en los procesadores Intel se denomina Execute Disable (XD)

#Ejecute el siguiente comando y verifique que su kernel haya identificado y activado NX / XD proteccion

 journalctl | grep 'protection: active'
 #sistemas sin journalctl:
  [[ -n $(grep noexec[0-9]*=off /proc/cmdline) || -z $(grep -E -i ' (pae|nx)
' /proc/cpuinfo) || -n $(grep '\sNX\s.*\sprotection:\s' /var/log/dmesg | grep
-v active) ]] && echo "NX Protection is not active"

#1.6.3 Asegúrese de que la aleatorización del diseño del espacio de direcciones (ASLR) esté habilitada (Automatizado)
#La colocación aleatoria de regiones de memoria virtual dificultará la escritura de la página de memoria.
#exploits ya que la ubicación de la memoria cambiará constantemente

#Ejecute los siguientes comandos y verifique las coincidencias de salida:
 sysctl kernel.randomize_va_space
grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*

#Establezca el siguiente parámetro en /etc/sysctl.conf o un archivo /etc/sysctl.d/*:
cat /etc/sysctl.conf


#Ejecute el siguiente comando para establecer el parámetro de kernel activo:
 sysctl -w kernel.randomize_va_space=2
 
 #1.6.4 Asegúrese de que el prevínculo esté deshabilitado (automatizado)
 
 #La función de preenlace puede interferir con el funcionamiento de AIDE, porque cambia binarios
 
 #Ejecute el siguiente comando para verificar que 1prelink` no esté instalado:
  rpm -q prelink
  
# Ejecute el siguiente comando para restaurar los binarios a la normalidad
 prelink -ua

############################################################################################
#1.7 Control de acceso obligatorio
#El control de acceso obligatorio (MAC) proporciona una capa adicional de restricciones de acceso para procesos en la parte superior de los controles de acceso discrecionales básicos.
###################################################################################################################

#1.7.1 Configurar AppArmor
#proporciona un sistema de control de acceso obligatorio (MAC) que aumenta enormemente la
#modelo predeterminado de control de acceso discrecional (DAC). En AppArmor se aplican las reglas de MAC
#por rutas de archivo en lugar de por contextos de seguridad como en otros sistemas MAC

#1.7.1.1 Asegúrese de que AppArmor esté instalado (automatizado)
#Sin un sistema de control de acceso obligatorio instalado, solo el acceso discrecional predeterminado El sistema de control estará disponible.

#Ejecute el siguiente comando para verificar que los paquetes de AppArmor estén instalados:
 rpm -q apparmor-docs apparmor-parser apparmor-profiles apparmor-utils libapparmor1
 
 #Ejecute el siguiente comando para instalar AppArmor:
  zypper install -t pattern apparmor
  
 # 1.7.1.2 Asegúrese de que AppArmor esté habilitado en la configuración del cargador de arranque (Automatizado)
#Configure AppArmor para que se habilite en el momento del arranque y verifique que no se haya sobrescrito por los parámetros de arranque del cargador de arranque.

#Ejecute los siguientes comandos para verificar que todas las líneas de Linux tengan apparmor = 1 y security = apparmor conjunto de parámetros:
grep "^\s*linux" /boot/grub2/grub.cfg | grep -v "apparmor=1"
 grep "^\s*linux" /boot/grub2/grub.cfg | grep -v "security=apparmor"

#Edite / etc / default / grub y agregue los parámetros apparmor = 1 y security = apparmor a la línea GRUB_CMDLINE_LINUX =
vi /etc/default/grub
GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"

#Ejecute el siguiente comando para actualizar la configuración de grub2:
 grub2-mkconfig -o /boot/grub2/grub.cfg
 
 #1.7.1.3 Asegúrese de que todos los perfiles de AppArmor estén en modo de cumplimiento o queja(Automatizado)
 #Los perfiles de AppArmor definen a qué recursos pueden acceder las aplicaciones
 
 #Ejecute el siguiente comando y verifique que los perfiles estén cargados, que los perfiles estén en vigor o modo de queja, y ningún proceso es ilimitado:
 apparmor_status | grep profiles
 
 #Ejecute el siguiente comando y verifique que ningún proceso esté sin confinar
 apparmor_status | grep processes
 
 #Ejecute uno de los siguientes comandos para configurar todos los perfiles para hacer cumplir O para quejarse
 #Ejecute el siguiente comando para configurar todos los perfiles en el modo de aplicación:
  aa-enforce /etc/apparmor.d/*
  #Run the following command to set all profiles to complain mode:
   aa-complain /etc/apparmor.d/*
   #Ejecute el siguiente comando para enumerar los procesos no confinados:
 aa-unconfined
#1.7.1.4 Ensure all AppArmor Profiles are enforcing (Automated)
#Los requisitos de configuración de seguridad varían de un sitio a otro. Algunos sitios pueden exigir una
#política que es más estricta que la política predeterminada, que es perfectamente aceptable

#Ejecute el siguiente comando y verifique que los perfiles estén cargados, no hay perfiles en la queja modo, y ningún proceso es ilimitado:
 apparmor_status | grep profiles
 #Ejecute el siguiente comando para verificar que ningún proceso esté sin confinar:
 apparmor_status | grep processes

#Ejecute el siguiente comando para configurar todos los perfiles en el modo de aplicación:
aa-enforce /etc/apparmor.d/*

#Ejecute el siguiente comando para enumerar los procesos no confinados:
aa-unconfined

##############################################################################################################
# 1.8 Banners de advertencia
#Presentar un mensaje de advertencia antes del inicio de sesión normal del usuario puede ayudar en el enjuiciamiento de intrusos en el sistema informático
############################################################################################################

#1.8.1 Banners de advertencia de línea de comando
#Los archivos / etc / motd, / etc / issue y /etc/issue.net gobiernan los banners de advertencia para
#inicios de sesión de línea de comando estándar para usuarios locales y remotos

#1.8.1.1 Asegúrese de que el mensaje del día esté configurado correctamente (automatizado)
#El contenido del archivo / etc / motd se muestra a los usuarios después de iniciar sesión y funciona como mensaje del día para usuarios autenticados.

#Ejecute el siguiente comando y verifique que el contenido coincida con la política del sitio
cat /etc/motd

#Ejecute el siguiente comando y verifique que no se devuelvan resultados:
grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/motd

#Edite el archivo / etc / motd con el contenido apropiado de acuerdo con la política de su sitio, elimine
#cualquier instancia de \ m, \ r, \ s, \ vo referencias a la plataforma del sistema operativo
#O Si no se utiliza motd, este archivo se puede eliminar.
#Ejecute el siguiente comando para eliminar el archivo motd:

vi /etc/modt

rm /etc/motd

#1.8.1.2 Asegúrese de que el banner de advertencia de inicio de sesión local esté configurado correctamente (Automatizado)
#Los sistemas basados ​​en Unix suelen mostrar información sobre la versión y el parche del sistema operativo
#nivel al iniciar sesión en el sistema.

#Ejecute el siguiente comando y verifique que el contenido coincida con la política del sitio
cat /etc/issue

#Ejecute el siguiente comando y verifique que no se devuelvan resultados:
 grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue
 
 #Edite el archivo / etc / issue con el contenido apropiado de acuerdo con la política de su sitio,
#eliminar cualquier instancia de \ m, \ r, \ s, \ vo referencias a la plataforma del sistema operativo
vi /ect/issue
echo "Solo para usos autorizados"
rm /etc/issue

#1.8.1.3 Asegúrese de que el banner de advertencia de inicio de sesión remoto esté configurado correctamente (Automatizado)
#El contenido del archivo /etc/issue.net se muestra a los usuarios antes de iniciar sesión para
#conexiones de servicios configurados.

#Ejecute el siguiente comando y verifique que el contenido coincida con la política del sitio:
cat /etc/issue.net

#Ejecute el siguiente comando y verifique que no se devuelvan resultados:
# grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net

#Edite el archivo /etc/issue.net con el contenido apropiado de acuerdo con la política de su sitio,
#eliminar cualquier instancia de \ m, \ r, \ s, \ vo referencias a la plataforma del sistema operativo
vi /ect/issue.net 
 echo "solo para autorizado"
 rm /etc/issue.net
 
 #1.8.1.4 Asegúrese de que los permisos en / etc / motd estén configurados (automatizado)
 #El contenido del archivo / etc / motd se muestra a los usuarios después de iniciar sesión y funciona como mensaje del día para usuarios autenticados
 
 #Ejecute el siguiente comando y verifique que Uid y Gid sean ambos 0 / root y Access sea 644:
 stat /etc/motd
 
 #Ejecute los siguientes comandos para establecer permisos en / etc / motd:
  chown root:root /etc/motd
  chmod u-x,go-wx /etc/motd
  
  #1.8.1.5 Asegúrese de que los permisos en / etc / issue estén configurados (automatizado)
  #El contenido del archivo / etc / issue se muestra a los usuarios antes de iniciar sesión en terminales locales.
  
  #Ejecute el siguiente comando y verifique que Uid y Gid sean ambos 0 / root y Access sea 644:
   stat /etc/issue
   
   #Ejecute los siguientes comandos para establecer permisos en / etc / issue:
   chown root:root /etc/issue
 chmod u-x,go-wx /etc/issue

#1.8.1.6 Asegúrese de que los permisos en /etc/issue.net estén configurados
#El contenido del archivo /etc/issue.net se muestra a los usuarios antes de iniciar sesión para
#conexiones de servicios configurados.

#Ejecute el siguiente comando y verifique que Uid y Gid sean ambos 0 / root y Access sea 644:
 stat /etc/issue.net

#Ejecute los siguientes comandos para establecer permisos en /etc/issue.net:
chown root:root /etc/issue.net
chmod u-x,go-wx /etc/issue.net

############################################################################################################
#1.9 Asegúrese de que las actualizaciones, los parches y el software de seguridad adicionalinstalado (manual)
#Periódicamente se lanzan parches para el software incluido debido a fallas de seguridad o
#incluir funcionalidad adicional.

#Ejecute el siguiente comando y verifique que no haya actualizaciones o parches para instalar:
 zypper list-updates
 
 #El siguiente comando instalará todas las actualizaciones disponibles:
 zypper update
 
 ###############################################################################################################
 #1.10 Asegúrese de que se elimine GDM o el inicio de sesión esté configurado (automatizado)
 #Descripción:
#GNOME Display Manager (GDM) maneja el inicio de sesión gráfico para sistemas basados ​​en GNOME.
#La configuración del escritorio GNOME se gestiona con dconf. Es un jerárquicamente
#base de datos estructurada o registro que permite a los usuarios modificar su configuración personal, y
#administradores del sistema para establecer valores predeterminados u obligatorios para todos los usuarios.

#Ejecute el siguiente comando para verificar que GDM no esté instalado en el sistema:
 rpm -q gdm
 
 #Verifique que / etc / dconf / profile / gdm exista e incluya lo siguiente:
 cat  /etc/dconf/profile/gdm
 
 user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults

#Verifique que exista vimun archivo en /etc/dconf/db/gdm.d/ e incluya lo siguiente: (Esto es normalmente /etc/dconf/db/gdm.d/01-banner-message)
cat /etc/dconf/db/gdm.d/
vi /etc/dconf/db/gdm.d/01-banner-message)
[org/gnome/login-screen]
banner-message-enable=true 
banner-message-text='<banner message>'

#Verifique que exista un archivo en /etc/dconf/db/gdm.d/ e incluya lo siguiente: (Esto es normalmente /etc/dconf/db/gdm.d/00-login-screen)
cat /etc/dconf/db/gdm.d
vi /etc/dconf/db/gdm.d/00-login-screen

#Ejecute el siguiente comando para eliminar GDM O Si se requiere GDM: Edite o cree el perfil de gdm que contiene las siguientes líneas: (Esto suele ser
#/ etc / dconf / profile / gdm)
 zypper remove gdm
 o
 vi /etc/dconf/profile/gdm
 user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults

#Ejecute el siguiente Ejecutar para mostrar un banner de inicio de sesión:
#Nota: es posible que deba crear el directorio /etc/dconf/db/gdm.d/
#Edite o cree un archivo de claves gdm para la configuración de toda la máquina: (esto suele ser/etc/dconf/db/gdm.d/01-banner-message)
 vi /etc/dconf/db/gdm.d/01-banner-message
 [org/gnome/login-screen]
banner-message-enable=true
banner-message-text='<banner message>'

#Ejemplo de texto de banner: 'Solo para usos autorizados. Toda la actividad puede ser monitoreada y reportada. '
#Ejecute lo siguiente para deshabilitar la lista de usuarios:
#Edite o cree un archivo de claves gdm para la configuración de toda la máquina en el directorio
#/etc/dconf/db/gdm.d/ y agregue lo siguiente: (Normalmente es /etc/dconf/db/gdm.d/00-login-screen)
 
cat etc/dconf/db/gdm.d/ 
vi /etc/dconf/db/gdm.d/00-login-screen
[org/gnome/login-screen]
Do not show the user list
disable-user-list=true

#Ejecute el siguiente comando para actualizar las bases de datos del sistema:
dconf update

################################################################################
# 2 Servicios
###############################################################################

#2.1 Servicios de inetd
#inetd es un dominio  de super-servidor que proporciona servicios de Internet y pasa conexiones aservicios configurados.

#2.1.1 Asegúrese de que xinetd no esté instalado (automatizado)
#El eXtended InterNET Daemon (xinetd) es un superdaemon de código abierto que reemplazó
#el daemon inetd original. El daemon  xinetd escucha servicios bien conocidos y
#envía el daemon apropiado para responder adecuadamente a las solicitudes de servicio.

#Ejecute el siguiente comando para verificar que xinetd no esté instalado:
 rpm -q xinetd
 
 #Ejecute el siguiente comando para eliminar xinetd:
zypper eliminar xinetd

#2.2 Servicios para fines especiales
#describe los servicios que están instalados en sistemas que necesitan ejecutarse específicamente estos servicios.

#2.2.1 Sincronización horaria
#Se recomienda que los sistemas físicos y los invitados virtuales que no tengan acceso directo al
#El reloj del host físico esté configurado para sincronizar su tiempo

#2.2.1.1 Asegúrese de que la sincronización de la hora esté en uso (manual)
#La hora del sistema debe estar sincronizada entre todos los sistemas de un entorno. Esto es
#normalmente se hace estableciendo un servidor de tiempo autorizado o un conjunto de servidores y teniendo todos
#los sistemas sincronizan sus relojes con ellos

#En sistemas donde la sincronización de hora basada en el host no está disponible, verifique que la sincronización sea
#instalado O systemd-timesyncd está habilitado:
rpm -q chrony

#Ejecute el siguiente comando para verificar que systemd-timesyncd esté habilitado
 systemctl is-enabled systemd-timesyncd
 
 #hora basada en el host no está disponible, instale chrony O habilitar systemd-timesyncd:
#Ejecute el siguiente comando para instalar Chrony:
 zypper install chrony
 
 # o Ejecute el siguiente comando para habilitar systemd-timesyncd
  systemctl enable systemd-timesyncd

#2.2.1.2 Asegúrese de que systemd-timesyncd esté configurado (Manual)
#systemd-timesyncd es un daemon que se ha agregado para sincronizar el reloj del sistema a través de la red

#La configuración adecuada es vital para garantizar que la sincronización horaria funcione correctamente.

#Asegúrese de que Timesyncd esté habilitado e iniciado
#Ejecute el siguiente comando para verificar que systemd-timesyncd esté habilitado:
 systemctl is-enabled systemd-timesyncd.service
 
 #Revise /etc/systemd/timesyncd.conf y asegúrese de que los servidores NTP, NTP FallbackNTP
#servidores, y RootDistanceMaxSec listados están de acuerdo con la política local
#Ejecute el siguiente comando
 timedatectl status

#Edite el archivo /etc/systemd/timesyncd.conf y agregue / modifique las siguientes líneas:
vi /ect/system/timesyncd.conf 

NTP=0.suse.pool.ntp.org 1.suse.pool.ntp.org #Servers listed should be In
Accordance With Local Policy
FallbackNTP=2.suse.pool.ntp.org 3.suse.pool.ntp.org #Servers listed should be
In Accordance With Local Policy
RootDistanceMax=1 #should be In Accordance With Local Policy

#Ejecute los siguientes comandos para habilitar e iniciar systemd-timesyncd:
systemctl --now enable systemd-timesyncd.service 
timedatectl set-ntp true 

#2.2.1.3 Asegúrese de que la cronología esté configurada (automatizada)
#chrony es un daemon que implementa el Protocolo de tiempo de red (NTP) y está diseñado para
#sincronizar los relojes del sistema en una variedad de sistemas y utilizar una fuente que sea altamente preciso.

#Ejecute el siguiente comando y verifique que el servidor remoto esté configurado correctamente:
 grep -E "^(server|pool)" /etc/chrony.conf
 
 #se pueden configurar varios servidores
#Ejecute el siguiente comando y verifique que OPTIONS incluya '-u chrony':
 grep ^OPTIONS /etc/sysconfig/chronyd
 
 #Agregue o edite las líneas de servidor o grupo en /etc/chrony.conf según corresponda:
 vi /etc/chrony.conf
 server <remote-server>

#Agregue o edite las líneas de servidor o grupo en /etc/chrony.conf según corresponda:
echo "OPTIONS="-u chrony""> /etc/chrony.conf

#2.2.2 Asegúrese de que los componentes del servidor X11 no estén instalados (automatizado)
#El sistema X Window proporciona una interfaz gráfica de usuario (GUI) donde los usuarios pueden tener
#múltiples ventanas en las que ejecutar programas y varios complementos

#Ejecute el siguiente comando para verificar que X Windows Server no esté instalado.
 rpm -qa xorg-x11-server*

#Ejecute el siguiente comando para eliminar los paquetes de X Windows Server:
zypper remove xorg-x11-server*

#2.2.3 Ensure Avahi Server is not installed (Automated)
#Avahi es una implementación gratuita de zeroconf, que incluye un sistema para multidifusión DNS / DNS-SD
#descubrimiento de servicios. Avahi permite que los programas publiquen y descubran servicios y hosts
#ejecutándose en una red local sin una configuración específica

#Ejecute uno de los siguientes comandos para verificar que avahi-autoipd y avahi no estén instalados:
 rpm -q avahi-autoipd avahi

#Ejecute los siguientes comandos para detener, enmascarar y eliminar avahi-autoipd y avahi:
 systemctl stop avahi-daemon.socket avahi-daemon.service
 zypper remove avahi-autoipd avahi
 
 #2.2.4 Asegúrese de que CUPS no esté instalado (automatizado)
 #El Common Unix Print System (CUPS) proporciona la capacidad de imprimir tanto en formato local como en
#impresoras de red. Un sistema que ejecuta CUPS también puede aceptar trabajos de impresión desde sistemas remotos
#e imprimirlos en impresoras locales.

#Ejecute el siguiente comando para verificar que las cups no estén instaladas:
 rpm -q cups
 
 #Ejecute el siguiente comando para eliminar cups:
 zypper remove cups
 
 #2.2.5 Asegúrese de que el servidor DHCP no esté instalado (automatizado)
 #El Protocolo de configuración dinámica de host (DHCP) es un servicio que permite que las máquinas
#direcciones IP asignadas dinámicamente.

#Ejecute el siguiente comando para verificar que dhcp no esté instalado:
rpm -q dhcp

#Ejecute el siguiente comando para eliminar dhcp:
 zypper remove dhcp
 
 #2.2.6 Asegúrese de que el servidor LDAP no esté instalado (automatizado)
 #El Protocolo ligero de acceso a directorios (LDAP) se introdujo como reemplazo de
#IS / YP. Es un servicio que proporciona un método para buscar información de una central
#base de datos.

#Ejecute el siguiente comando para verificar que los servidores openldap no estén instalados:
rpm -q openldap2

#Ejecute el siguiente comando para eliminar openldap-servers:
 zypper remove openldap2

#2.2.7 Asegúrese de que nfs-utils no esté instalado o que el servicio nfs-server esté enmascarado (Automatizado)
#Network File System (NFS)Proporciona la capacidad de que los sistemas monten sistemas de archivos de otros servidores a través de la red.

#Ejecute el siguiente comando para verificar que nfs-utils y nfs-kernel-server no estén instalados
 rpm -q nfs-utils nfs-kernel-server

#O Si los paquetes nfs-utils o nfs-kernel-server son necesarios como dependencia
#Ejecute el siguiente comando para verificar que el servicio nfs-server esté enmascarado
systemctl is-enabled nfs-server

#Ejecute los siguientes comandos para eliminar nfs-utils y nfs-kernel-server
 zypper remove nfs-utils
zypper remove nfs-kernel-server

#O Si los paquetes nfs-utils o nfs-kernel-server son necesarios como dependencia
#Ejecute el siguiente comando para detener y enmascarar el servicio del servidor nfs:
systemctl --now mask nfs-server

#2.2.8 Asegúrese de que rpcbind no esté instalado o los servicios rpcbind estén enmascarados (Automatizado)
#La utilidad rpcbind asigna los servicios RPC a los puertos en los que escuchan. Procesos RPC
#notificar a rpcbind cuando se inician, registrando los puertos en los que están escuchando y el RPC
#números de programa que esperan atender.

#Ejecute el siguiente comando para verificar que rpcbind no esté instalado:
rpm -q rpcbind

#Si el paquete rpcbind es necesario como dependencia
#Ejecute los siguientes comandos para verificar que rpcbind esté enmascarado:
 systemctl is-enabled rpcbind
 

#Ejecute el siguiente comando para verificar que rpcbind.socket esté enmascarado:
systemctl is-enabled rpcbind.socket

#Ejecute el siguiente comando para eliminar nfs-utils:
zypper remove rpcbind

#Si el paquete rpcbind es necesario como dependencia
#Ejecute los siguientes comandos para detener y enmascarar los servicios rpcbind y rpcbind.socket:
systemctl --now mask rpcbind
systemctl --now mask rpcbind.socket

#2.2.9 Ensure DNS Server is not installed (Automated)
#El sistema de nombres de dominio (DNS) es un sistema de nombres jerárquico que asigna nombres a IP
#direcciones para computadoras, servicios y otros recursos conectados a una red

#Ejecute uno de los siguientes comandos para verificar que el enlace no esté instalado:
rpm -q bind

#Ejecute el siguiente comando para eliminar el enlace:
 zypper remove bind

#2.2.10 Asegúrese de que el servidor FTP no esté instalado (automatizado)
#FTP (Protocolo de transferencia de archivos) es una herramienta estándar tradicional y ampliamente utilizada para transferir
# entre un servidor y clientes a través de una red, especialmente donde no se requiere autenticación
#necesario (permite que usuarios anónimos se conecten a un servidor).

#Ejecute el siguiente comando para verificar que vsftpd no esté instalado
 rpm -q vsftpd
 
 #Run the following command to remove vsftpd:
zypper remove vsftpd

#2.2.11 Asegúrese de que el servidor HTTP no esté instalado (automatizado)

#Los servidores HTTP o web ofrecen la posibilidad de alojar contenido de sitios web.

#Ejecute el siguiente comando para verificar que apache2 no esté instalado
 rpm -q apache2

#Ejecute el siguiente comando para eliminar apache2:
zypper remove apache2


#2.2.12 Asegúrese de que el servidor IMAP y POP3 no esté instalado (automatizado)
#dovecot es un servidor IMAP y POP3 de código abierto para sistemas basados en Linux

#Ejecute el siguiente comando para verificar que Dovecot no esté instalado:
 rpm -q dovecot

#Ejecute el siguiente comando para eliminar dovecot
 zypper remove dovecot
 
 #2.2.13 Asegúrese de que Samba no esté instalado (automatizado)
 #El daemon Samba permite a los administradores del sistema configurar sus sistemas Linux para compartir
#sistemas de archivos y directorios con escritorios Windows. Samba anunciará los sistemas de archivos

#Ejecute el siguiente comando para verificar que samba no esté instalado:
rpm -q samba

#el siguiente comando para eliminar samba:
 zypper remove samba
 
 #2.2.14 Asegúrese de que el servidor proxy HTTP no esté instalado (automatizado)
 #Squid es un servidor proxy estándar que se utiliza en muchas distribuciones y entornos.
 
 #Ejecute el siguiente comando para verificar que Squid no esté instalado:
  rpm -q squid
  
  #Ejecute el siguiente comando para eliminar el paquete squid
   zypper remove squid

#2.2.15 Ensure net-snmp is not installed (Automated)
#El Protocolo simple de administración de redes (SNMP) es un protocolo ampliamente utilizado para monitorear
#salud y bienestar de equipos de red, equipos informáticos y dispositivos como UPS

#Ejecute el siguiente comando para verificar que net-snmp no esté instalado:
rpm -q net-snmp

#Ejecute el siguiente comando para eliminar net-snmp:
 zypper remove net-snmp
 
 #2.2.16 Asegúrese de que el agente de transferencia de correo esté configurado para el modo solo local (Automatizado)
 #Los agentes de transferencia de correo (MTA), como sendmail y Postfix, se utilizan para escuchar
#enviar por correo y transferir los mensajes al usuario o servidor de correo correspondiente. Si el sistema no es
#destinado a ser un servidor de correo, se recomienda que el MTA esté configurado para procesar únicamente
#correo local.

#Ejecute el siguiente comando para verificar que el MTA no esté escuchando en ningún loopback.
#dirección (127.0.0.1 o :: 1)
 ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|\[?::1\]?):25\s'

#Edite /etc/postfix/main.cf y agregue la siguiente línea a la sección RECEIVING MAIL. Si
#la línea ya existe, cámbiela para que se parezca a la línea de abajo

echo "RECEIVING MAIL inet_interfaces = loopback-only" >> /etc/postfix/main.cf

#Run the folloing command to restart postfix:
 systemctl restart postfix

#2.2.17 Asegúrese de que rsync no esté instalado o que el servicio rsyncd esté enmascarado (Automatizado)
#El servicio rsyncd se puede utilizar para sincronizar archivos entre sistemas a través de enlaces de red.

#Run the following command to verify that rsync is not installed:
rpm -q rsync

#Run the following command to verify the rsyncd service is masked:
 systemctl is-enabled rsyncd
 
 #Ejecute el siguiente comando para eliminar el paquete rsync:
  zypper remove rsync

#Ejecute el siguiente comando para enmascarar el servicio rsyncd:
 systemctl --now mask rsyncd
 
 #2.2.18 Asegúrese de que el servidor NIS no esté instalado (automatizado)
 #es un protocolo de servicio de directorio cliente-servidor para distribuir el sistema
#Archivos de configuración. El servidor NIS es una colección de programas que permiten la distribución
#de archivos de configuración.

#Ejecute el siguiente comando para verificar que ypserv no esté instalado:
rpm -q ypserv

#Ejecute el siguiente comando para eliminar ypserv:
zypper remove ypserv

#2.2.19 Ensure telnet-server is not installed (Automated)
#El paquete telnet contiene el demonio telnet, que acepta conexiones de usuarios
#desde otros sistemas a través del protocolo telnet

#Ejecute el siguiente comando para verificar que el paquete telnet no esté instalado:
rpm -q telnet

#Ejecute el siguiente comando para eliminar el paquete telnet-server:
zypper remove telnet

#2.3 Servicio de cliente 
#Existen varios servicios inseguros. Mientras que deshabilitar los servidores previene un ataque local
#contra estos servicios, se recomienda eliminar a sus clientes a menos que sean necesarios.

#2.3.1 Asegúrese de que el cliente NIS no esté instalado (automatizado)
#El Servicio de Información de Red (NIS), anteriormente conocido como Páginas Amarillas, es un cliente-servidor
#Protocolo de servicio de directorio utilizado para distribuir archivos de configuración del sistema

#Ejecute el siguiente comando para verificar que el paquete ypbind no esté instalado:
 rpm -q ypbind
 
 #Ejecute el siguiente comando para eliminar el paquete ypbind:
 zypper remove ypbind

#2.3.2 Ensure rsh client is not installed (Automated)
#Estos clientes heredados contienen numerosas exposiciones de seguridad y han sido reemplazados por
#paquete SSH más seguro. Incluso si se elimina el servidor, es mejor asegurarse de que los clientes
#también eliminado para evitar que los usuarios intenten inadvertidamente utilizar estos comandos y
#exponiendo por tanto sus credenciales. Tenga en cuenta que al eliminar el paquete rsh se elimina el
#clientes para rsh, rcp y rlogin

#Ejecute el siguiente comando para verificar que el paquete rsh no esté instalado:
 rpm -q rsh
 
 #Ejecute el siguiente comando para eliminar el paquete rsh:
 zypper remove rsh
 
 #2.3.3 Asegúrese de que el cliente de talk no esté instalado (automatizado)
 #El software de talk permite a los usuarios enviar y recibir mensajes a través de los sistemas.
#a través de una sesión de terminal. El cliente de talk, que permite la inicialización de sesiones de talk, es
#instalado por defecto.

#Ejecute el siguiente comando para verificar que el paquete de talk no esté instalado:
rpm -q talk

#Ejecute el siguiente comando para eliminar el paquete talk:
 zypper remove talk

#2.3.4 Asegúrese de que el cliente telnet no esté instalado (automatizado)
#El paquete telnet contiene el cliente telnet, que permite a los usuarios iniciar conexiones a
#otros sistemas a través del protocolo telnet.

#Ejecute el siguiente comando para verificar que el paquete telnet no esté instalado:
 rpm -q telnet
 
 #Ejecute el siguiente comando para eliminar el paquete telnet:
  zypper remove telnet

#2.3.5 Asegúrese de que el cliente LDAP no esté instalado (automatizado)
#El Protocolo ligero de acceso a directorios (LDAP) se introdujo como reemplazo de
#NIS / YP. Es un servicio que proporciona un método para buscar información de una central
#base de datos.

#Ejecute el siguiente comando para verificar que el paquete openldap-clients no esté instalado:
rpm -q openldap2-clients

#Ejecute el siguiente comando para eliminar el paquete openldap-clients:
zypper remove openldap2-clients

#2.4 Asegurarse de que los servicios no esenciales se eliminen o enmascaren (manual)
#Un puerto de red se identifica por su número, la dirección IP asociada y el tipo de
#protocolo de comunicación como TCP o UDP.
#Un puerto de escucha es un puerto de red en el que escucha una aplicación o proceso, actuando como un
#punto final de comunicación.

#Ejecute el siguiente comando:
lsof -i -P -n | grep -v "(ESTABLISHED)"
#Revise la salida para asegurarse de que todos los servicios enumerados sean necesarios en el sistema.

#Ejecute el siguiente comando para eliminar el paquete que contiene el servicio:
 zypper remove <package_tcp>

#O si los paquetes necesarios tienen una dependencia:
#Ejecute el siguiente comando para detener y enmascarar el servicio:
 systemctl --now mask <service_tcp
 
#3 Configuración de red
#Esta sección proporciona orientación sobre cómo proteger la configuración de red del sistema.
#a través de los parámetros del kernel, el control de la lista de acceso y la configuración del firewall.

#Aunque IPv6 tiene muchas ventajas sobre IPv4, no todas las organizaciones tienen IPv6 o doble configuraciones stack implementadas

#Ejecute los siguientes comandos para verificar que se haya utilizado uno de los siguientes métodos para deshabilitar IPv6:
#SI IPv6 está deshabilitado a través de la configuración de GRUB2: Ejecute el siguiente comando y verifique que no se devuelvan líneas.
 grep "^\s*linux" /boot/grub2/grub.cfg | grep -v ipv6.disable=1
 
 #O SI IPv6 está deshabilitado a través de la configuración de sysctl: Ejecute los siguientes comandos:
 sysctl net.ipv6.conf.all.disable_ipv6
 sysctl net.ipv6.conf.default.disable_ipv6
 grep -E'^\s*net\.ipv6\.conf\.(all|default)\.disable_ipv6\s*=\s*1\b(\s+#.*)?$'/etc/sysctl.conf /etc/sysctl.d/*.conf | cut -d: -f2
 
 #Utilice uno de los dos métodos siguientes para deshabilitar IPv6 en el sistema:
#Para deshabilitar IPv6 a través de la configuración de GRUB2:
#Edite / etc / default / grub y agregue ipv6.disable = 1 a los parámetros de GRUB_CMDLINE_LINUX:
 echo "GRUB_CMDLINE_LINUX="ipv6.disable=1"" >> /etc/default/grub
 
 #Ejecute el siguiente comando para actualizar la configuración de grub2:
  grub2-mkconfig –o /boot/grub2/grub.cfg
#Para deshabilitar IPv6 a través de la configuración de sysctl:
#Configure los siguientes parámetros en /etc/sysctl.conf o en un archivo /etc/sysctl.d/*:
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysct1.d/*
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysct1.d/*

#Ejecute los siguientes comandos para configurar los parámetros activos del kernel:
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
 sysctl -w net.ipv6.route.flush=1
 
#SI IPv6 está deshabilitado a través de la configuración sysctl, es posible que el reenvío SSH X11 ya no funcione como se esperaba.
#pero si es necesario, lo siguiente permitirá el reenvío SSH X11 con IPv6 deshabilitado a través de la configuración sysctl: 

#Agregue la siguiente línea al archivo / etc / ssh / sshd_config:
echo "AddressFamily inet" /etc/ssh/sshd_config
#Ejecute el siguiente comando para reiniciar el servidor openSSH:
systemctl restart ssh

#3.1.2 Asegúrese de que las interfaces inalámbricas estén desactivadas (manual)
#Las redes inalámbricas se utilizan cuando las redes cableadas no están disponibles

#Ejecute el siguiente comando para determinar las interfaces inalámbricas en el sistema
iw list

#Ejecute el siguiente comando para deshabilitar cualquier interfaz inalámbrica:
ip link set <interface> down

#3.2 Parámetros de red (solo host)
#Un sistema se considera host solo si el sistema tiene una sola interfaz o tiene varias interfaces, pero no se configurará como un enrutador.

#Las banderas net.ipv4.ip_forwardand net.ipv6.conf.all.forwarding se utilizan para decirle al sistema si puede reenviar paquetes o no.

#Ejecute los siguientes comandos y verifique las coincidencias de salida:
sysctl net.ipv4.ip_forward
grep -E -s"^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf

#Si IPv6 está habilitado: Ejecute los siguientes comandos y verifique que la salida coincida:
sysctl net.ipv6.conf.all.forwarding
grep -E -s "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf

#O Verifique que IPv6 esté deshabilitado:
#Ejecute el siguiente script. La salida confirmará si IPv6 está deshabilitado en el sistema.
#!/bin/bash
[ -n "$passing" ] && passing=""
[ -z "$(grep "^\s*linux" /boot/grub2/grub.cfg | grep -v ipv6.disabled=1)" ] 
&& passing="true"
grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" 
/etc/sysctl.conf \
/etc/sysctl.d/*.conf && grep -Eq 
"^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" \
/etc/sysctl.conf /etc/sysctl.d/*.conf && sysctl
 net.ipv6.conf.all.disable_ipv6 | \
 grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" && \
 sysctl net.ipv6.conf.default.disable_ipv6 | \
 grep -Eq "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" && 
 passing="true"
 if [ "$passing" = true ] ; then
 	echo "IPv6 is disabled on the system"
 	else
 		echo "IPv6 is enabled on the system"
 	fi

#ejecute los siguientes comandos para resataurante los parametros prederterminador y establecer los parametros activos del kernel 
grep -Els "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf 
etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while 
read filename; do sed -ri "s/^\s*(net\.ipv4\.ip_forward\s*)(=)(\s*\S+\b).*$/# 
*REMOVED* \1/" $filename; done; sysctl -w net.ipv4.ip_forward=0; sysctl -w 
net.ipv4.route.flush=1

grep -Els "^\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
| while read filename; do sed -ri "s/^\s*(net\.ipv6\.conf\.all\.forwarding\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done; 
sysctl -w net.ipv6.conf.all.forwarding=0; sysctl -w net.ipv6.route.flush=1

#3.2.2 Asegúrese de que el envío de redireccionamiento de paquetes esté deshabilitado (automatizado)
#Los redireccionamientos CMP se utilizan para enviar información de enrutamiento a otros hosts.

#Ejecute los siguientes comandos y verifique las coincidencias de salida:
sysctl net.ipv4.conf.all.send_redirects
sysctl net.ipv4.conf.default.send_redirects
grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf /etc/sysctl.d/

#establezca los siguientes parámetros en /etc/sysctl.con para un archivo /etc/sysctl.d/*:
echo " sysctl -w net.ipv4.conf.all.send_redirects=0" >> /etc/sysctl.d/*
echo "sysctl -w net.ipv4.conf.default.send_redirects=0" >> /etc/sysctl.d/*
echo " sysctl -w net.ipv4.route.flush=1" >> /etc/sysctl.d/*

#3.3 Parámetros de red (host y enrutador)
#Los siguientes parámetros de red están pensados para su uso tanto en sistemas host como en enrutadores.

#3.3.1 Asegúrese de que los paquetes enrutados de origen no sean aceptados (Automatizado)
#En las redes, el enrutamiento de origen permite al remitente especificar parcial o totalmente la ruta que toman los paquetes a través de una red.
# Por el contrario, los paquetes enrutados que no son de origen viajan por una ruta determinada por los enrutadores de la red.

#Ejecute los siguientes comandos y verifique las coincidencias de salida
sysctl net.ipv4.conf.all.accept_source_route
sysctl net.ipv4.conf.default.accept_source_route
grep "net\.ipv4\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*

#Si IPv6 está habilitado: Ejecute los siguientes comandos y verifique que la salida coincida:
sysctl net.ipv6.conf.all.accept_source_route
sysctl net.ipv6.conf.default.accept_source_route
grep "net\.ipv6\.conf\.all\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*
grep "net\.ipv6\.conf\.default\.accept_source_route" /etc/sysctl.conf /etc/sysctl.d/*

#O Verifique que IPv6 esté deshabilitado:
#Ejecute el siguiente script. La salida confirmará si IPv6 está deshabilitado en el sistema.
#!/bin/bash
[ -n "$passing" ] && passing=""
[ -z "$(grep "^\s*linux" /boot/grub2/grub.cfg | grep -v ipv6.disabled=1)" ] 
&& passing="true"
grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" 
/etc/sysctl.conf \/etc/sysctl.d/*.conf && grep -Eq 
"^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" \
/etc/sysctl.conf /etc/sysctl.d/*.conf&& sysctl 
net.ipv6.conf.all.disable_ipv6 | \
grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" && \sysctl net.ipv6.conf.default.disable_ipv6 | \grep -Eq "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" && 
passing="true"if [ "$passing" = true ] ; then
	echo "IPv6 is disabled on the system"
	else
		echo "IPv6 is enabled on the system"
	fi

#Configure los siguientes parámetros en /etc/sysctl.con para un archivo /etc/sysctl.d/*:

echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl/.d/*
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl/.d/*

#Ejecute los siguientes comandos para configurar los parámetros activos del kernel:
sysctl -w net.ipv4.conf.all.accept_source_route=0
 sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1

#SI IPv6 no está deshabilitado:
#Configure los siguientes parámetros en /etc/sysctl.conf o en un archivo /etc/sysctl.d/*:
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/systect1.d/*
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/systect1.d/*

#Ejecute los siguientes comandos para configurar los parámetros activos del kernel:
 sysctl -w net.ipv6.conf.all.accept_source_route=0
 sysctl -w net.ipv6.conf.default.accept_source_route=0
 sysctl -w net.ipv6.route.flush=1
 
 #3.3.2 Asegúrese de que las redirecciones ICMP no sean aceptadas (automatizadas)
# Los mensajes de redireccionamiento ICMP son paquetes que transmiten información de enrutamiento y le dicen a su host
#(actuando como un enrutador) para enviar paquetes a través de una ruta alternativa.

#Ejecute los siguientes comandos y verifique las coincidencias de salida:
 sysctl net.ipv4.conf.all.accept_redirects
  sysctl net.ipv4.conf.default.accept_redirects
   grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf/etc/sysctl.d/*
   grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf/etc/sysctl.d/*
   
   #O verifique que IPv6 esté deshabilitado:
#Ejecute el siguiente script. La salida confirmará si IPv6 está deshabilitado en el sistema
!/bin/bash
[ -n "$passing" ] && passing=""
[ -z "$(grep "^\s*linux" /boot/grub2/grub.cfg | grep -v ipv6.disabled=1)" ]
&& passing="true"
&& passing="true"
grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b(\s+#.*)?$"
/etc/sysctl.conf \
/etc/sysctl.d/*.conf && grep -Eq
"^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" \
/etc/sysctl.conf /etc/sysctl.d/*.conf && sysctl
net.ipv6.conf.all.disable_ipv6 | \
grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" && \
sysctl net.ipv6.conf.default.disable_ipv6 | \
grep -Eq "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" &&
passing="true"
if [ "$passing" = true ] ; then
echo "IPv6 is disabled on the system"
else
echo "IPv6 is enabled on the system"
fi

#Configure los siguientes parámetros en /etc/sysctl.conf o en un archivo /etc/sysctl.d/*:
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.d/*
echo "net.ipv4.conf.default.accept_redirects = 0" >> /ect/sysct1.d/*

#Ejecute los siguientes comandos para configurar los parámetros activos del kernel:
sysctl -w net.ipv4.conf.all.accept_redirects=0
 sysctl -w net.ipv4.conf.default.accept_redirects=0
 sysctl -w net.ipv4.route.flush=1
 
 #SI IPv6 no está deshabilitado: Configure los siguientes parámetros en /etc/sysctl.conf o en un archivo /etc/sysctl.d/*:
 echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.d/*
 echo "net.ipv6.conf.default.accept_redirects = 0" >> /ect/sysct1.d/* 
 
 #Ejecute los siguientes comandos para configurar los parámetros activos del kernel:
 sysctl -w net.ipv6.conf.all.accept_redirects=0
 sysctl -w net.ipv6.conf.default.accept_redirects=0
 sysctl -w net.ipv6.route.flush=1
 
 #3.3.3 Asegúrese de que no se acepten redireccionamientos ICMP seguros (automatizados)
 #Los redireccionamientos ICMP seguros son los mismos que los redireccionamientos ICMP, 
 #excepto que provienen de las puertas de enlace que figuran en la lista de puertas de enlace predeterminadas.
 #Ejecute los siguientes comandos y verifique las coincidencias de salida:
 sysctl net.ipv4.conf.all.secure_redirects
sysctl net.ipv4.conf.default.secure_redirects
grep "net\.ipv4\.conf\.all\.secure_redirects" /etc/sysctl.conf/etc/sysctl.d/*
grep "net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf/etc/sysctl.d/*

#Configure los siguientes parámetros en /etc/sysctl.conf o en un archivo /etc/sysctl.d/*:
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysct1.d/*
echo "net.ipv4.conf.default.secure_redirects = 0 " >> /etc/sysct1.d/*

#Ejecute los siguientes comandos para configurar los parámetros activos del kernel:
 sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
 sysctl -w net.ipv4.route.flush=1
 
 #3.3.4 Asegúrese de que los paquetes sospechosos estén registrados (automatizado)
 #Cuando está habilitada, esta función registra los paquetes con direcciones de origen no enrutables en el kernel Iniciar sesión.

#Ejecute los siguientes comandos y verifique las coincidencias de salida:
sysctl net.ipv4.conf.all.log_martians net.ipv4.conf.all.log_martians = 1
 sysctl net.ipv4.conf.default.log_martians
 grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/*
 grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf/etc/sysctl.d/*
 
 #Configure los siguientes parámetros en /etc/sysctl.conf o en un archivo /etc/sysctl.d/*:
 
 echo "net.ipv4.conf.all.log_martians = 1" >> /ect/sysctl.d/*
 echo "net.ipv4.conf.default.log_martians = 1" >> /ect/sysctl.d/*
 
 #Ejecute los siguientes comandos para configurar los parámetros activos del kernel:
 sysctl -w net.ipv4.conf.all.log_martians=1
 sysctl -w net.ipv4.conf.default.log_martians=1
 sysctl -w net.ipv4.route.flush=1
 
 #3.3.5 Asegúrese de que se ignoren las solicitudes ICMP de difusión (automatizado)
 #Si configura net.ipv4.icmp_echo_ignore_broadcasts en 1, el sistema ignorará todas las solicitudes de eco y marca de tiempo ICMP para las direcciones de transmisión y multidifusión.

#Ejecute los siguientes comandos y verifique las coincidencias de salida:
 sysctl net.ipv4.icmp_echo_ignore_broadcasts
 grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf/etc/sysctl.d/*
 
 #Configure los siguientes parámetros en /etc/sysctl.conf o en un archivo /etc/sysctl.d/*:
 echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /ect/sysctl.d/*
 
 #Ejecute los siguientes comandos para configurar los parámetros activos del kernel
 sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
 sysctl -w net.ipv4.route.flush=1
 
 #3.3.6 Asegúrese de que se ignoren las respuestas ICMP falsas (automatizado)
# Establecer icmp_ignore_bogus_error_responses en 1 evita que el kernel registre datos falsos
#respuestas (no compatible con RFC-1122) de reencuadres de transmisión, lo que evita que los sistemas de archivos
#llenándose de mensajes de registro inútiles.

#Ejecute los siguientes comandos y verifique las coincidencias de salida:
sysctl net.ipv4.icmp_ignore_bogus_error_responses
grep "net.ipv4.icmp_ignore_bogus_error_responses" /etc/sysctl.conf/etc/sysctl.d/*

 #Configure el siguiente parámetro en /etc/sysctl.conf o en un archivo /etc/sysctl.d/*:
 echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /ect/sysctl.d/*
 
 #Ejecute los siguientes comandos para configurar los parámetros activos del kernel:
  sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
 sysctl -w net.ipv4.route.flush=1
 
 #3.3.7 Asegúrese de que el filtrado de ruta inversa esté habilitado (automatizado)
 #Establecer net.ipv4.conf.all.rp_filter y net.ipv4.conf.default.rp_filter en 1 fuerza
#el kernel de Linux para utilizar el filtrado de ruta inversa en un paquete recibido para determinar si el
#el paquete era válido

#Ejecute los siguientes comandos y verifique las coincidencias de salida:
 sysctl net.ipv4.conf.all.rp_filter
sysctl net.ipv4.conf.default.rp_filter
 grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*
 grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/*

#Configure los siguientes parámetros en /etc/sysctl.conf o en un archivo /etc/sysctl.d/*:

 echo "net.ipv4.conf.all.rp_filter = 1" >> /ect/sysctl.d/*
 echo "net.ipv4.conf.default.rp_filter = 1" >> /ect/sysctl.d/*
 
 #3.3.8 Ensure TCP SYN Cookies is enabled (Automated)
#Ejecute los siguientes comandos y verifique las coincidencias de salida:
sysctl net.ipv4.tcp_syncookies
 grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/*
 
 #Configure los siguientes parámetros en /etc/sysctl.conf o en un archivo /etc/sysctl.d/*:
 echo "net.ipv4.tcp_syncookies = 1" >> /ect/sysctl.d/*
 
 #Ejecute los siguientes comandos para configurar los parámetros activos del kernel:
 sysctl -w net.ipv4.tcp_syncookies=1
 sysctl -w net.ipv4.route.flush=1
 
#3.3.9 Asegúrese de que no se acepten los anuncios del enrutador IPv6 (automatizado)
#Ejecute los siguientes comandos y verifique las coincidencias de salida:
sysctl net.ipv6.conf.all.accept_ra
 sysctl net.ipv6.conf.default.accept_ra
 grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*
 grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/*

#Ejecute el siguiente script. La salida confirmará si IPv6 está deshabilitado en el sistema.
#!/bin/bash
[ -n "$passing" ] && passing=""
[ -z "$(grep "^\s*linux" /boot/grub2/grub.cfg | grep -v ipv6.disabled=1)" ]
&& passing="true"
grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b(\s+#.*)?$"
/etc/sysctl.conf \
/etc/sysctl.d/*.conf && grep -Eq
"^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" \
/etc/sysctl.conf /etc/sysctl.d/*.conf && sysctl
net.ipv6.conf.all.disable_ipv6 | \
grep -Eq "^\s*net\.ipv6\.conf\.all\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" && \
sysctl net.ipv6.conf.default.disable_ipv6 | \
grep -Eq "^\s*net\.ipv6\.conf\.default\.disable_ipv6\s*=\s*1\b(\s+#.*)?$" &&
passing="true"
if [ "$passing" = true ] ; then
echo "IPv6 is disabled on the system"
else
echo "IPv6 is enabled on the system"
fi

#SI IPv6 está habilitado: Configure los siguientes parámetros en /etc/sysctl.conf o en un archivo /etc/sysctl.d/*:
echo "net.ipv6.conf.all.accept_ra = 0" >> /ect/sysctl.d/*
echo "net.ipv6.conf.default.accept_ra = 0" >> /ect/sysctl.d/*

#Ejecute los siguientes comandos para configurar los parámetros activos del kernel:
 sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
 sysctl -w net.ipv6.route.flush=1
 
 #3.4 Protocolos de red poco comunes
#Los módulos del kernel de Linux admiten varios protocolos de red que no se utilizan comúnmente.
#Si estos protocolos no son necesarios, se recomienda desactivarlos en el kernel

#3.4.1 Asegúrese de que DCCP esté deshabilitado (automatizado)
#El Protocolo de control de congestión de datagramas (DCCP) es un protocolo de capa de transporte que admite transmisión de medios y telefonía

#Ejecute los siguientes comandos y verifique que la salida sea la indicada:
modprobe -n -v dccp
lsmod | grep dccp

#Edite o cree un archivo en el directorio /etc/modprobe.d/ que termine en in .conf
vim /etc/modprobe.d/dccp.conf
#agregar la siguiente linea 
install dccp /bin/true

#3.4.2 Asegúrese de que SCTP esté deshabilitado (automatizado)
#El Protocolo de transmisión de control de flujo (SCTP) es un protocolo de capa de transporte que se utiliza para admitir la comunicación orientada a mensajes, con varios flujos de mensajes en una conexión.
#Ejecute los siguientes comandos y verifique que la salida sea la indicada:
modprobe -n -v sctp
lsmod | grep sctp

#editar o crear un archivo en /etc/modprobe.d/directory que termina en .conf
vim /etc/modprobe.d/sctp.conf
#agregar la siguiente linea 
install sctp /bin/true

#3.5 configuracion firewall

#3.5.1 Configuracion  firewalld
#firewalld (Dynamic Firewall Manager) proporciona un firewall administrado dinámicamente con soporte para “zonas” de red / firewall para asignar un nivel de confianza a una red y sus conexiones, interfaces o fuentes asociadas. Tiene soporte para IPv4, IPv6, puentes Ethernet y también para configuraciones de firewall IPSet.

#3.5.1.1 Asegúrese de que FirewallD esté instalado (automatizado)
#firewalld es una herramienta de administración de firewall para sistemas operativos Linux. 

#Ejecute el siguiente comando para verificar que FirewallD e iptables estén instalados:
rpm -q firewalld iptables

#Ejecute el siguiente comando para instalar FirewallD e iptables:
zypper install firewalld iptables

#5.1.2 Asegúrese de que nftables no esté instalado o detenido y enmascarado (automatizado)
#nftables es un subsistema del kernel de Linux que proporciona filtrado y clasificación de paquetes de red / datagramas / marcos y es el sucesor de iptables.

#Ejecute el siguiente comando para verificar que iptables no esté instalado:
rpm -q nftables

#O Ejecute los siguientes comandos para verificar que nftables esté detenido y enmascarado:
systemctl status nftables | grep "Active: " | grep -v  "active (running) "
systemctl is-enabled nftables

#Ejecute el siguiente comando para eliminar nftables
zypper remove nftables

#O Ejecute el siguiente comando para detener y enmascarar nftables:
systemctl --now mask nftables

#.5.1.3 Asegúrese de que el servicio firewalld esté habilitado y en ejecución (automatizado)
#firewalld.service habilita la aplicación de las reglas de firewall configuradas a través de firewalld

#Ejecute el siguiente comando para verificar que firewalld esté habilitado:
systemctl is-enabled firewalld

#Ejecute el siguiente comando para verificar que firewalld se está ejecutando
firewall-cmd --state

#Ejecute el siguiente comando para desenmascarar firewalld
systemctl unmask firewalld

#Run the following command to enable and start firewalld
systemctl --now enable firewalld

#3.5.1.4 Asegúrese de que la zona predeterminada esté configurada (automatizada)
#Una zona de firewall define el nivel de confianza para una conexión, interfaz o enlace de dirección de origen.

#Ejecute el siguiente comando y verifique que la zona predeterminada se adhiera a la política de la empresa
firewall-cmd --get-default-zone

#Ejecute el siguiente comando para establecer la zona predeterminada:
firewall-cmd --set-default-zone=public

#3.5.1.5 Asegúrese de que las interfaces de red estén asignadas a la zona adecuada (manual)
#Las zonas de firewall definen el nivel de confianza de las conexiones o interfaces de red.

#Ejecute el siguiente comando y verifique que las interfaces siguen la política del sitio para la asignación de zonas
nmcli -t connection show | awk -F: '{if($4){print $4}}' | while read INT; do firewall-cmd --get-active-zones | grep -B1 $INT; done

#Ejecute el siguiente comando para asignar una interfaz a la zona apropiada.
firewall-cmd --zone=customezone --change-interface=eth1

#3.5.1.6 Asegúrese de que no se aceptan puertos y servicios innecesarios (manual)
#los servicios y los puertos pueden ser aceptados o explícitamente rechazados o descartados por una zona.

#Ejecute el siguiente comando y revise el resultado para asegurarse de que los servicios y puertos enumerados sigan la política del sitio.
firewall-cmd --get-active-zones | awk '!/:/ {print $1}' | while read ZN; do firewall-cmd --list-all --zone=$ZN; done

#Ejecute el siguiente comando para eliminar un servicio innecesario
firewall-cmd --remove-service=cockpit

#Ejecute el siguiente comando para eliminar un puerto innecesario:
firewall-cmd --remove-port=25/tcp

#Ejecute el siguiente comando para que la nueva configuración sea persistente:
firewall-cmd --runtime-to-permanent

#3.5.2 Configuración de nftables 
#Si se están utilizando firewalld o iptables en su entorno, siga las instrucciones en su sección respectiva y pase la guía en esta sección.

#debe actualizarse para permitir que solo los sistemas que requieran conectividad ssh se conecten, según la política del sitio. Guarde el siguiente script como /etc/nftables/nftables.rules

#Ejecute el siguiente comando para cargar el archivo en nftable
nft -f /etc/nftables/nftables.rules

#Ejecute el siguiente comando para crear el archivo iptables.rules
vi nft list ruleset > /etc/nftables/nftables.rules

#Agregue la siguiente línea a /etc/sysconfig/nftables.conf

sed -i 'include "/etc/nftables/nftables.rules"' >> /etc/sysconfig/nftables.conf

#3.5.2.1 Asegúrese de que nftables esté instalado (automatizado)
#Ejecute el siguiente comando para verificar que nftables esté instalado
rpm -q nftables

#Ejecute el siguiente comando para instalar nftables
zypper install nftables

#.5.2.2 Asegúrese de que firewalld no esté instalado o detenido y enmascarado (automatizado)
#Ejecute el siguiente comando para verificar que firewalld no esté instalado
rpm -q firewalld

#O Ejecute los siguientes comandos para verificar que firewalld esté detenido y enmascarado
ystemctl status firewalld | grep "Active: " | grep -v  "active (running) "
systemctl is-enabled firewalld

#Ejecute el siguiente comando para eliminar firewalld
zypper remove firewalld

# o  el siguiente comando para detener y enmascarar firewalld
systemctl --now mask firewalld

#3.5.2.3 Asegúrese de que las iptables se vacíen (manual)
#nftables es un reemplazo para iptables, ip6tables, ebtables y arptables

#Ejecute los siguientes comandos para asegurarse de que no existan reglas de iptables.

ptables -LNo 
#rule shoulb be returnedFor ip6tables:
 ip6tables -LNo 
 #rules should be returned

 #Ejecute los siguientes comandos para vaciar iptables: Para iptables:
 ptables -F
 #For ip6tables 
 ip6tables -F

 #3.5.2.4 Asegurarse de que existe una tabla (automatizado)
 #Las mesas sostienen cadenas. Cada tabla solo tiene una familia de direcciones y solo se aplica a los paquetes de esta familia. Las tablas pueden tener una de cinco familias

 #Ejecute el siguiente comando para verificar que existe una tabla nftables:
  nft list tables

  #Ejecute el siguiente comando para crear una tabla en nftables
  nft create table inet filter

  #.5.2.5 Asegúrese de que existan cadenas de base (automatizado)

  #Ejecute los siguientes comandos y verifique que existan cadenas base para INPUT, FORWARD y OUTPUT.

  nft list ruleset | grep 'hook input'
   nft list ruleset | grep 'hook forward'
   nft list ruleset | grep 'hook output'

   #Ejecute el siguiente comando para crear las cadenas base:
nft create chain inet filter input { type filter hook input priority 0 \; }
 nft create chain inet filter forward { type filter hook forward priority 0 \; }
  nft create chain inet filter output { type filter hook output priority 0 \; }

  #3.5.2.6 Asegúrese de que el tráfico de bucle invertido esté configurado (Automatizado)
  #Configure la interfaz de bucle invertido para aceptar tráfico. Configure todas las demás interfaces para denegar el tráfico a la red de bucle invertido

  #Ejecute los siguientes comandos para verificar que la interfaz de bucle invertido esté configurada:
  nft list ruleset | awk '/hook input/,/}/' | grep 'iif "lo" accept'iif "lo" accept
   nft list ruleset | awk '/hook input/,/}/' | grep 'ip saddr'
   
   #Ejecute el siguiente comando para verificar que la interfaz de loopback IPv6 esté configurada:
   nft list ruleset | awk '/hook input/,/}/' | grep 'ip6 saddr'

   #Ejecute los siguientes comandos para implementar las reglas de loopback:

   nft add rule inet filter input iif lo accept
  nft create rule inet filter input ipsaddr 127.0.0.0/8 counter drop

#IFIPv6 está habilitado: Ejecute el siguiente comando para implementar las reglas de bucle invertido de IPv6:
nft add rule inet filter input ip6 saddr ::1 counter drop

#5.2.7 Asegúrese de que las conexiones salientes y establecidas estén configuradas (Manual)
#Configure las reglas de firewall para nuevas conexiones salientes y establecidas

#Run the following commands and verify all rules for established incoming connections match site policy: site policy:
nft list ruleset | awk '/hook input/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'

#Ejecute el siguiente comando y verifique que todas las reglas para las conexiones salientes nuevas y establecidas coincidan con la política del sitio
nft list ruleset | awk '/hook output/,/}/' | grep -E 'ip protocol (tcp|udp|icmp) ct state'

#configurar iptables de acuerdo con la política del sitio. Los siguientes comandos implementarán una política para permitir todas las conexiones salientes y todas las conexiones establecidas:
nft add rule inet filter input ip protocol tcp ct state established accept
 nft add rule inet filter input ip protocol udp ct state established accept
 nft add rule inet filter input ip protocol icmp ct state established accept
 nft add rule inet filter output ip protocol tcp ct state new,related,established accept
 nft add rule inet filter output ip protocol udp ct state new,related,established accept
 nft add rule inet filter output ip protocol icmp ct statenew,related,established accept

 #3.5.2.8 Asegurar la política de denegación de firewall predeterminada (automatizada)
 #La política de la cadena base es el veredicto predeterminado que se aplicará a los paquetes que lleguen al final de la cadena.

 #Ejecute los siguientes comandos y verifique que las cadenas base contengan una política de DROP.
nft list ruleset | grep 'hook input'type filter hook input priority 0; policy drop; 
nft list ruleset | grep 'hook forward'type filter hook forward priority 0; policy drop;
 nft list ruleset | grep 'hook output'type filter hook output priority 0; policy drop;
 
#Ejecute el siguiente comando para las cadenas base con los ganchos de entrada, reenvío y salida para implementar una política DROP predeterminada
nft chain inetfilter input { policy drop \; }
nft chain inet filter forward { policy drop \; }
 nft chain inet filter output { policy drop \; }

#3.5.2.9 Asegúrese de que el servicio nftables esté habilitado (automatizado)
#El servicio nftables permite la carga de conjuntos de reglas nftables durante el arranque o el inicio del servicio nftables

#Ejecute el siguiente comando y verifique que el servicio nftables esté habilitado
systemctl is-enabled nftables

#Ejecute el siguiente comando para habilitar el servicio nftables:
systemctl enable nftables

#3.5.2.10 Asegúrese de que las reglas de nftables sean permanentes (automatizado)
#nftables es un subsistema del kernel de Linux que proporciona filtrado y clasificación de paquetes / datagramas / marcos de red.

#n the following commands to verify that input, forward, and output base chains are configured to be applied to a nftables ruleset on boot:
awk '/hook input/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/sysconfig/nftables.conf)

#Ejecute el siguiente comando para verificar la cadena base directa:
awk '/hook forward/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/sysconfig/nftables.conf)

#un el siguiente comando para verificar la cadena base hacia adelante:
 awk '/hook output/,/}/' $(awk '$1 ~ /^\s*include/ { gsub("\"","",$2);print $2 }' /etc/sysconfig/nftables.conf)

 #Edite /etc/sysconfig/nftables.conffile y elimine los comentarios o agregue una línea con include <Ruta absoluta al archivo de reglas nftables> para cada archivo nftables que desee incluir en el conjunto de reglas nftables en el arranque
vi /etc/sysconfig/nftables.conf

#agrega la siguiente linea
include "/etc/nftables/nftables.rules"

#3.5.3 Configure iptables
#3.5.3.1 Configure software
#3.5.3.1.1 Asegúrese de que el paquete iptables esté instalado (automatizado)

#Ejecute el siguiente comando para verificar que iptables esté instalado:
rpm -q iptables

#Ejecute el siguiente comando para instalar iptables
zypper install iptables

#3.5.3.1.2 Asegúrese de que nftables no esté instalado (automatizado)
#nftables es un subsistema del kernel de Linux que proporciona filtrado y clasificación de paquetes de red / datagramas / marcos y es el sucesor de iptables.

#Ejecute el siguiente comando para verificar que iptables no esté instalado:
rpm -q nftables

#Ejecute el siguiente comando para eliminar nftables:
zypper remove nftables

#3.5.3.1.3 Asegúrese de que el firewall no esté instalado o detenido y enmascarado (automatizado)

#Ejecute el siguiente comando para verificar que firewalld no esté instalado:
rpm -q firewalld

#O Ejecute los siguientes comandos para verificar que firewalld esté detenido y enmascarado
systemctl status firewalld | grep "Active: " | grep -v  "active (running) "
systemctl is-enabled firewalld

#Ejecute el siguiente comando para eliminar firewalld
zypper remove firewalld

#Ejecute el siguiente comando para detener y enmascarar firewalld
systemctl --now mask firewalld

#3.5.3.2 Configurar iptables IPv4

#3.5.3.2.1 Asegurar la política de denegación de firewall predeterminada (automatizada)
#Una política predeterminada denegar todas las conexiones garantiza que se rechazará cualquier uso de red no configurado.

#Ejecute el siguiente comando y verifique que la política para las cadenas INPUT, OUTPUT y FORWARD sea DROPor REJECT:
iptables -L

#Ejecute los siguientes comandos para implementar una política DROP predeterminada:
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

#3.5.3.2.2 Asegúrese de que el tráfico de bucle invertido esté configurado (automatizado)
#Configure la interfaz de bucle invertido para aceptar tráfico. Configure todas las demás interfaces para denegar el tráfico a la red loopback (127.0.0.0/8).

#Ejecute los siguientes comandos y verifique que la salida incluya las reglas enumeradas en orden (los recuentos de paquetes y bytes pueden diferir):
iptables -L INPUT -v -n
iptables -L OUTPUT -v -n

#Ejecute los siguientes comandos para implementar las reglas de bucle invertido:
iptables -A INPUT -i lo -j ACCEPT
 iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A INPUT -s 127.0.0.0/8 -j DROP

#3.5.3.2.3 Asegúrese de que las conexiones salientes y establecidas estén configuradas (Manual)
#Configure las reglas de firewall para nuevas conexiones salientes y establecidas.

#Run the following command and verify all rules for new outbound, and established connections match site policy:
iptables -L -v -n

#Configure iptables de acuerdo con la política del sitio. Los siguientes comandos implementarán una política para permitir todas las conexiones salientes y todas las conexiones establecidas:
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
 iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
  iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
   iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
    iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

#5.3.2.4 Asegúrese de que existan reglas de firewall para todos los puertos abiertos (Manual)
#Cualquier puerto que se haya abierto en direcciones sin bucle invertido necesita reglas de firewall para controlar el tráfico.

#Ejecute el siguiente comando para determinar los puertos abiertos:
ss -4tuln

#Ejecute el siguiente comando para determinar las reglas del firewall
iptables -L INPUT -v -n

#Para cada puerto identificado en la auditoría que no tenga una regla de firewall, establezca una regla adecuada para aceptar conexiones entrantes:
 iptables -A INPUT -p <protocol> --dport <port> -m state --state NEW -j ACCEPT

 #3.5.3.3 Configure IPv6 ip6tables

 #3.5.3.3.1 Asegúrese de que la política de firewall de denegación predeterminada de IPv6 (automatizada)
 #Ejecute el siguiente comando y verifique que la política para las cadenas INPUT, OUTPUT y FORWARD sea DROP o REJECT:
ip6tables -L

 #Ejecute los siguientes comandos para implementar una política DROP predeterminada:
 ip6tables -P INPUT DROP
  ip6tables -P OUTPUT DROP
   ip6tables -P FORWARD DROP

   #3.5.3.3.3 Asegúrese de que las conexiones IPv6 salientes y establecidas estén configuradas (Manual)

   #Configure las reglas del firewall para las nuevas conexiones IPv6 salientes y establecidas.

   #desactive el siguiente comando y verifique que todas las reglas para las nuevas conexiones salientes y establecidas coincidan con la política del sitio
   ip6tables -L -v -n

   #Configure iptables de acuerdo con la política del sitio. Los siguientes comandos implementarán una política para permitir todas las conexiones salientes y todas las conexiones establecidas
   ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
    ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
     ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
      ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT 
      ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
    ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

    #3.5.3.3.4 Asegúrese de que existan reglas de firewall IPv6 para todos los puertos abiertos (manual)
    #Cualquier puerto que se haya abierto en direcciones sin bucle invertido necesita reglas de firewall para controlar el tráfico.

    #Ejecute el siguiente comando para determinar los puertos abiertos:
    ss -6tuln

    #Ejecute el siguiente comando para determinar las reglas del firewall:
    ip6tables -L INPUT -v -n

    #o cada puerto identificado en la auditoría que no tiene una regla de firewall establece una regla adecuada para aceptar conexiones entrantes:
    ip6tables -A INPUT -p <protocol> --dport <port> -m state --state NEW -j ACCEPT

    ip6tables -A INPUT -p <protocol> --dport <port> -m state --state NEW -j ACCEPT

    #4 Logging and Auditing
#System auditing, through auditd, allows system administrators to monitor their systems such that they can detect unauthorized access or modification of data
#4.1.1 Ensure auditing is enabled
#The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring.
#4.1.1.1 Ensure auditd is installed (Automated)
#auditd is the userspace component to the Linux Auditing System. It's responsible for writing audit records to the disk
#Run the following command and verify auditd is installed:
 rpm -q audit
 
 #Run the following command to Install auditd
 zypper install audit
 
 #4.1.1.2 Ensure auditd service is enabled and running (Automated)
 #Turn on the auditd daemon to record system events
 
 #Run the following command to verify auditd is enabled:
systemctl is-enabled auditd
#Run the following command to verify that auditd is running:
 systemctl status auditd | grep 'Active: active (running) '
 
 #Run the following command to enable and start auditd:
  systemctl --now enable auditd

#4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled (Automated)
#Configure grub so that processes that are capable of being audited can be audited even if they start up prior to auditd startup.
#Run the following command and verify that each linux line has the audit=1 parameter set:
 grep "^\s*linux" /boot/grub2/grub.cfg | grep -v "audit=1"
 #Edit /etc/default/grub and add audit=1 to GRUB_CMDLINE_LINUX:
 echo "GRUB_CMDLINE_LINUX="audit=1"" >> /etc/default/grub
#Run the following command to update the grub2 configuration:
 grub2-mkconfig -o /boot/grub2/grub.cfg
 #4.1.2 Configure Data Retention
 #4.1.2.1 Ensure audit log storage size is configured (Automated)
 #Configure the maximum size of the audit log file. Once the log reaches the maximum size, it will be rotated and a new log file will be started.
 
 #Run the following command and ensure output is in compliance with site policy:
 grep max_log_file /etc/audit/auditd.conf
 #Set the following parameter in /etc/audit/auditd.conf in accordance with site policy:
echo "max_log_file = <MB>" >> /etc/audit/auditd.conf

#4.1.2.2 Ensure audit logs are not automatically deleted (Automated)
#The max_log_file_action setting determines how to handle the audit log file reaching the max file size. A value of keep_logs will rotate the logs but never delete old logs.
#Run the following command and verify output matches:
 grep max_log_file_action /etc/audit/auditd.conf
 #Set the following parameter in /etc/audit/auditd.conf:
echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf

#4.1.2.3 Ensure system is disabled when audit logs are full (Automated)
#The auditd daemon can be configured to halt the system when the audit logs are full.

#Run the following commands and verify output matches:
 grep space_left_action /etc/audit/auditd.conf
 grep action_mail_acct /etc/audit/auditd.conf
 grep admin_space_left_action /etc/audit/auditd.conf
 
 #Set the following parameters in /etc/audit/auditd.conf:
echo "space_left_action = email
action_mail_acct = root
admin_space_left_action = halt" >> /etc/audit/auditd.conf

#4.1.2.4 Ensure audit_backlog_limit is sufficient (Automated)
#Run the following commands and verify the audit_backlog_limit= parameter is set to an appropriate size for your organization
grep "^\s*linux" /boot/grub2/grub.cfg | grep -v "audit_backlog_limit="
 grep "audit_backlog_limit=" /boot/grub2/grub.cfg
 #Edit /etc/default/grub and add audit_backlog_limit=<BACKLOG SIZE> to GRUB_CMDLINE_LINUX: GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"
 vi /etc/default/grub
 # GRUB_CMDLINE_LINUX="audit_backlog_limit=8192"
 #Run the following command to update the grub2 configuration:
 grub2-mkconfig -o /boot/grub2/grub.cfg
 
 #4.1.3 Ensure events that modify date and time information are collected (Automated)

#On a 64 bit system run the following commands:
 grep time-change /etc/audit/rules.d/*.rules
 auditctl -l | grep time-change


#For 64 bit systems Edit or create a file in the /etc/audit/rules.d/ directory ending in .rules
 vi /etc/audit/rules.d/time_change.rules
#and add the following lines:
#-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
#-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k timechange
#-a always,exit -F arch=b64 -S clock_settime -k time-change
#-a always,exit -F arch=b32 -S clock_settime -k time-change
#-w /etc/localtime -p wa -k time-change
 
 #4.1.4 Ensure events that modify user/group information are collected  (Automated)
 #Record events affecting the group , passwd (user IDs), shadow and gshadow (passwords) or
#/etc/security/opasswd (old passwords, based on remember parameter in the PAM configuration) files

#Run the following command and verify rules are in a .rules file:
 grep identity /etc/audit/rules.d/*.rules
 #Run the following command and verify the rules are in the running auditd config:
 auditctl -l | grep identity
 
 #Edit or create a file in the /etc/audit/rules.d/ directory ending in .rules
 vi /etc/audit/rules.d/identity.rules
#and add the following lines:
#-w /etc/group -p wa -k identity
#-w /etc/passwd -p wa -k identity
#-w /etc/gshadow -p wa -k identity
#-w /etc/shadow -p wa -k identity
#-w /etc/security/opasswd -p wa -k identity

#4.1.5 Ensure events that modify the system's network environment are collected (Automated)
#On a 64 bit system run the following commands:
 grep system-locale /etc/audit/rules.d/*.rules
 auditctl -l | grep system-locale
#For 64 bit systems Edit or create a file in the /etc/audit/rules.d/ directory ending in .rules
 vi /etc/audit/rules.d/system_local.rules
#and add the following lines:
#-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
#-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
#-w /etc/issue -p wa -k system-locale
#-w /etc/issue.net -p wa -k system-locale
#-w /etc/hosts -p wa -k system-locale
#-w /etc/sysconfig/network -p wa -k system-locale

#4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected (Automated)
Run the following commands:
grep MAC-policy /etc/audit/rules.d/*.rules
 auditctl -l | grep MAC-policy
 
 #Edit or create a file in the /etc/audit/rules.d/ directory ending in .rules
 vi /etc/audit/rules.d/MAC_policy.rules
#and add the following lines:
#-w /etc/selinux/ -p wa -k MAC-policy
#-w /usr/share/selinux/ -p wa -k MAC-policy

#4.1.7 Ensure login and logout events are collected (Automated)
#Run the following commands:
 grep logins /etc/audit/rules.d/*.rules
 auditctl -l | grep logins
#Edit or create a file in the /etc/audit/rules.d/ directory ending in .rules
 vi /etc/audit/rules.d/logins.rules
#and add the following lines:
#-w /var/log/faillog -p wa -k logins
#-w /var/log/lastlog -p wa -k logins
#-w /var/log/tallylog -p wa -k logins

#4.1.8 Ensure session initiation information is collected (Automated)
#Run the following commands: Run the following command and verify rules are in a .rules file:
 grep -E '(session|logins)' /etc/audit/rules.d/*.rules

#Run the following command and verify the rules are in the running auditd config:
auditctl -l | grep -E '(session|logins)'

#Edit or create a file in the /etc/audit/rules.d/ directory ending in .rules
 vi /etc/audit/rules.d/session.rules
#and add the following lines:
#-w /var/run/utmp -p wa -k session
#-w /var/log/wtmp -p wa -k logins
#-w /var/log/btmp -p wa -k logins
#4.1.9 Ensure discretionary access control permission modification events are collected (Automated)
#On a 64 bit system run the following commands
#Run the following command and verify rules are in a .rules file:
 grep perm_mod /etc/audit/rules.d/*.rules
 #Run the following command and verify the rules are in the running auditd config:
 auditctl -l | grep auditctl -l | grep perm_mod

 #For 64 bit systems Edit or create a file in the /etc/audit/rules.d/ directory ending in .rules
 vi /etc/audit/rules.d/perm_mod.rules
#and add the following lines:
# -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F
auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F
auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F
auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F
auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S
removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295
-k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S
removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295
-k perm_mod #

#4.1.10 Ensure unsuccessful unauthorized file access attempts are collected (Automated)
#On a 64 bit system run the following commands:
Run the following command and verify rules are in a .rules file: #
 grep access /etc/audit/rules.d/*.rules
 
 #For 64 bit systems Edit or create a file in the /etc/audit/rules.d/ directory ending in.rules
 vi /etc/audit/rules.d/access.rules
#and add the following lines:
#-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S
ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access#

#4.1.11 Ensure use of privileged commands is collected (Automated)
#Monitor privileged programs (those that have the setuid and/or setgid bit set on execution) to determine if unprivileged users are running these commands.

#Run the following command replacing <partition> with a list of partitions where programs can be executed from on your system:
 find <partition> -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk
'{print "-a always,exit -F path=" $1 " -F perm=x -F auid>='"$(awk
'/^\s*UID_MIN/{print $2}' /etc/login.defs)"' -F auid!=4294967295 -k
privileged" }'

#Edit or create a file in the /etc/audit/rules.d/ directory ending in .rules and add all resulting lines to the file.
 vi /etc/audit/rules.d/privileged.rules
 #find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a
always,exit -F path=" $1 " -F perm=x -F auid>='"$(awk '/^\s*UID_MIN/{print
$2}' /etc/login.defs)"' -F auid!=4294967295 -k privileged" }' >>
/etc/audit/rules.d/privileged.rules#

#4.1.12 Ensure successful file system mounts are collected (Automated)



#
   
 


 







