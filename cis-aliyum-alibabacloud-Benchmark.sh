#pacheco Mex cintya yaritza 

#!/bin/sh
######################################################
###################################################
#cis_ aliyun_linux_2_benchmark_v1.0.0.0

# 1° configuracion inicial 
#######################################################

#En este scrip debes de tener en cuenta estos factores
#1° es que aliyum es un sistema operativo movil
#2° es que aliyum es mejor conocida como alibaba cloud lo 
#cual debes crear una cuenta para poder acceder a sus servicios  en la nube.
#3° tienes que usar una distrubucion de linux puede ser
#ubutun server, debian cloud o tambien centos los unico que cambia es 
#la configuracion ubutun usar sudo y centos yum
#uso ubuntu 20.04 para la alibaba cloud
#tienes que conectar a sus servido alibaba cloud ubuntu server
#Busque la dirección IP de Internet (dirección IP pública) asociada con su instancia de ECS en la nube de Alibaba. 
#para conectarse a servido tienes que tener la direccion ip, el nombre de usuario,
# y la contraseña que configuro instancia de alibaba cloud en el ssh
# es buscar en la ruta el archivo de la clave privada 
cat /home/cintya/.ssh/ecs.pem
#ejecuta chmod para modificar los permiso de la claves privada
chmod 400 /home/cintya/.ssh/ecs.pem
#configure el archivo de la clave privada mediante comandos 
ssh -i ~/home/cintya/.ssh/ecs.pem root@172.31.145.238
#usar el archivo de configuracion oara configurar los parametros
#requeridos desde un cliente que admita comandos SSH
cd ~/home/cintya/.ssh/ecs.pem 
#usar un editor de texto para configurar los parametros 
vim ecs.pem
host ecsaliyunserver #nombre de host
hostname 172.31.145.238 # la direccion ip de la instancia 
port 22 # numero de puerto 
user root #entra con la cuenta de inicion de seccion 
identityfile ~/home/cintya/ .ssh/ecs.pem #entrar con el archivo de la llave privada
 #guardar el archivo de la configuracion 
#reinicia el servicio ssh
#ejecute el siguiente comando puede entrar con la ip o nombre la instancia 
#ssh root@ecsaliyunserver 
ssh root@172.31.145.238
#le va pedir la contraseña que creando en alibaba cloud

# 1.1 configuracion de los archivos de sistema 

# 1.1.1 el montaje de los sistemas de archivos squashfs esté deshabilitado 

#1.1.1 

echo "install squashfs /bin/true
" > /etc/modprobe.d/squashfs.conf

#quitar modulo no necesario en kernel
modulo_direccion_fs "rmmod squashfs"  /etc/modprobe.d/squashfs.conf

#1.1.2 
echo "crear  tmpfs /fstab" 
> /tmp/etc/fstab

#comando para montarlo 
montar_direcccion_fs "mout tmps" /home/tmp/etc/fstab


# 1.1.3 Asegúrese de que la opción nodev esté configurada en la partición / tmp 
# 1.1.4 Asegúrese de que la opción nosuid esté configurada en la partición / tmp 
# 1.1.5 Asegúrese de que la opción noexec esté configurada en la partición / tmp 

vim  /tmp/etc/systemd/system/local-fs.target.wants/tmp.mount
mount -o remount,nosuid /tmp/etc/systemd/system/local-fs.target.wants/tmp.mount

# 1.1.6 Asegúrese de que exista una partición separada para / var 
echo "crear  var /fstab "
> /var/etc/fstab


# 1.1.7 Asegúrese de que exista una partición separada para / var / tmp 
echo "crear var/tmp"
> /var/tmp/etc/fstab
# 1.1.8 Asegúrese de que la opción nodev esté configurada en la partición / var / tmp 
# 1.1.9 Asegúrese de que la opción nosuid esté configurada en la partición / var / tmp
# 1.1.10 Asegúrese de que la opción noexec esté configurada en la partición / var / tmp 
vim /var/tmp/etc/fstab
mount -o remount,nodev /var/tmp/etc/fstab

# 1.1.11 Asegúrese de que exista una partición separada para / var / log 
echo "crear /var/log"
< /var/log/etc/fsbat

# 1.1.12 Asegúrese de que exista una partición separada para / var / log / audit 
echo "crear /var/log/audit"
< /var/log/audit/etc/fstab

# 1.1.13 Asegúrese de que exista una partición separada para / home 
echo "crear /home"
< /home/etc/fstab

# 1.1.14 Asegúrese de que la opción nodev esté configurada en la partición / home 
vim /home/etc/fstab

# 1.1.15 Asegúrese de que la opción nodev esté configurada en la partición / dev / shm 
# 1.1.16 Asegúrese de que la opción nosuid esté configurada en la partición / dev / shm 
# 1.1.17 Asegúrese de que la opción noexec esté configurada en la partición / dev / shm 
vim /dev/shm/etc/fstab
mount -o remount,nodev /dev/shm/etc/fstab



# 1.1.18 Asegúrese de que el bit world-writable esté configurado en todos los directorios de escritura 
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev
-type d -perm -0002 2>/dev/null | xargs chmod a+t

# 1.1.19 Deshabilitar el montaje automático
systemctl disable autofs
systemctl stop autofs


##########################################################################################################
#1.2 Configurar actualizaciones de software
######################################################################################################

#1.2.1 Asegúrese de que los repositorios del administrador de paquetes estén configurados 
yum repolist

#1.2.2 Asegúrese de que las claves GPG estén configuradas
rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'














