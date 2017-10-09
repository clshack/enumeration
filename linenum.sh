#!/bin/bash

echo -e "\n\e[00;31m#########################################################\e[00m"
echo -e "\e[00;31m#\e[00m" "\e[00;33mLocal Linux Enumeration & Privilege Escalation Script\e[00m" "\e[00;31m#\e[00m"
echo -e "\e[00;31m#########################################################\e[00m"

sleep 1

echo -e "\e[00;33mScan started at:"; date
echo -e "\n"

echo -e "\e[00;33m### SYSTEM ##############################################\e[00m"

#whoami
who=`whoami 2>/dev/null`
echo -e "\e[00;31mWhomai:\e[00m"
if [ "$who" ]; then
  echo -e "$who\n"
else 
  echo -e "None\n"
fi

#basic kernel info
unameinfo=`uname -a 2>/dev/null`
echo -e "\e[00;31mKernel information:\e[00m"
if [ "$unameinfo" ]; then
  echo -e "$unameinfo\n"
else 
  echo -e "None\n"
fi

procver=`cat /proc/version 2>/dev/null`
echo -e "\e[00;31mKernel information (continued):\e[00m"
if [ "$procver" ]; then
  echo -e "$procver\n"
else 
  echo -e "None\n"
fi

#search all *-release files for version info
release=`cat /etc/*-release 2>/dev/null`
echo -e "\e[00;31mSpecific release information:\e[00m"
if [ "$release" ]; then
  echo -e "$release\n"
else 
  echo -e "None\n"
fi

#target hostname info
hostnamed=`hostname 2>/dev/null`
echo -e "\e[00;31mHostname:\e[00m"
if [ "$hostnamed" ]; then
  echo -e "$hostnamed\n"
else 
  echo -e "None\n"
fi

echo -e "\e[00;33m### EXPLOITATION ########################################\e[00m"

#selinux
selinux=`sestatus 2>/dev/null`
echo -e "\e[00;31mSELinux:\e[00m"
if [ "$selinux" ]; then
  echo -e "$selinux\n"
else 
  echo -e "None\n"
fi

#NULL pointer dereference exploit prevention (mmap_min_addr)
mmap_min_addr=`cat /proc/sys/vm/mmap_min_addr 2>/dev/null`
echo -e "\e[00;31mNULL pointer dereference exploit prevention (mmap_min_addr):\e[00m"
if [ "$mmap_min_addr" ]; then
  echo -e "$mmap_min_addr\n"
else 
  echo -e "None\n"
fi

#symbol prepare_kernel_cred in /proc/kallsyms
kallsyms=`grep 'prepare_kernel_cred' /proc/kallsyms 2>/dev/null`
echo -e "\e[00;31mSymbol prepare_kernel_cred in /proc/kallsyms:\e[00m"
if [ "$kallsyms" ]; then
  echo -e "$kallsyms\n"
else 
  echo -e "None\n"
fi

#symbol prepare_kernel_cred in /proc/ksyms
ksyms=`grep 'prepare_kernel_cred' /proc/ksyms 2>/dev/null`
echo -e "\e[00;31mSymbol prepare_kernel_cred in /proc/ksyms:\e[00m"
if [ "$ksyms" ]; then
  echo -e "$ksyms\n"
else 
  echo -e "None\n"
fi

#symbol prepare_kernel_cred in /boot/System.map*
systemmap=`grep 'prepare_kernel_cred' /boot/System.map* 2>/dev/null`
echo -e "\e[00;31mSymbol prepare_kernel_cred in /boot/System.map*:\e[00m"
if [ "$systemmap" ]; then
  echo -e "$systemmap\n"
else 
  echo -e "None\n"
fi

#pulseaudio for bypassing NULL pointer dereference exploit prevention
pulseaudio=`which pulseaudio 2>/dev/null`
echo -e "\e[00;31mPulseaudio for bypassing NULL pointer dereference exploit prevention:\e[00m"
if [ "$pulseaudio" ]; then
  echo -e "$pulseaudio\n"
else 
  echo -e "None\n"
fi

#NULL pointer dereference exploit prevention (mmap_min_addr)
aslr=`cat /proc/sys/kernel/randomize_va_space 2>/dev/null`
echo -e "\e[00;31mASLR (off is 0, on is 2):\e[00m"
if [ "$aslr" ]; then
  echo -e "$aslr\n"
else 
  echo -e "None\n"
fi

#SMEP
smep=`grep smep /proc/cpuinfo 2>/dev/null`
echo -e "\e[00;31mSMEP (Supervisor Mode Execution Protection):\e[00m"
if [ "$smep" ]; then
  echo -e "Enabled\n"
else 
  echo -e "Disabled\n"
fi

#SMAP
smap=`grep smap /proc/cpuinfo 2>/dev/null`
echo -e "\e[00;31mSMAP (Supervisor Mode Access Protection):\e[00m"
if [ "$smap" ]; then
  echo -e "Enabled\n"
else 
  echo -e "Disabled\n"
fi

echo -e "\e[00;33m### USER/GROUP ##########################################\e[00m" |tee -a $report 2>/dev/null

#current user details
currusr=`id 2>/dev/null`
echo -e "\e[00;31mCurrent user/group info:\e[00m"
if [ "$currusr" ]; then
  echo -e "$currusr\n"
else 
  echo -e "None\n"
fi

#last logged on user information
lastlogedonusrs=`lastlog |grep -v "Never" 2>/dev/null`
echo -e "\e[00;31mUsers that have previously logged onto the system:\e[00m"
if [ "$lastlogedonusrs" ]; then
  echo -e "$lastlogedonusrs\n"
else 
  echo -e "None\n"
fi

#strips out username uid and gid values from /etc/passwd
usrsinfo=`cat /etc/passwd | cut -d ":" -f 1,2,3,4 2>/dev/null`
echo -e "\e[00;31mAll users and uid/gid info:\e[00m"
if [ "$usrsinfo" ]; then
  echo -e "$usrsinfo\n"
else 
  echo -e "None\n"
fi

#lists all id's and respective group(s)
grpinfo=`for i in $(cat /etc/passwd 2>/dev/null| cut -d":" -f1 2>/dev/null);do id $i;done 2>/dev/null`
echo -e "\e[00;31mGroup memberships:\e[00m"
if [ "$grpinfo" ]; then
  echo -e "$grpinfo\n"
else 
  echo -e "None\n"
fi

#checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)
hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
if [ "$hashesinpasswd" ]; then
  echo -e "\e[00;33m***It looks like we have password hashes in /etc/passwd!\e[00m\n$hashesinpasswd\n"
else 
  :
fi
 
#locate custom user accounts with some 'known default' uids
readpasswd=`grep -v "^#" /etc/passwd | awk -F: '$3 == 0 || $3 == 500 || $3 == 501 || $3 == 502 || $3 == 1000 || $3 == 1001 || $3 == 1002 || $3 == 2000 || $3 == 2001 || $3 == 2002 { print }'`
echo -e "\e[00;31mSample entires from /etc/passwd (searching for uid values 0, 500, 501, 502, 1000, 1001, 1002, 2000, 2001, 2002):\e[00m"
if [ "$readpasswd" ]; then
  echo -e "$readpasswd\n"
else 
  echo -e "None\n"
fi

#checks to see if the shadow file can be read
readshadow=`cat /etc/shadow 2>/dev/null`
if [ "$readshadow" ]; then
  echo -e "\e[00;33m***We can read the shadow file!\e[00m\n$readshadow\n"
else 
  :
fi

#checks to see if /etc/master.passwd can be read - BSD 'shadow' variant
readmasterpasswd=`cat /etc/master.passwd 2>/dev/null`
if [ "$readmasterpasswd" ]; then
  echo -e "\e[00;33m***We can read the master.passwd file!\e[00m\n$readmasterpasswd\n"
else 
  :
fi

#all root accounts (uid 0)
echo -e "\e[00;31mSuper user account(s):\e[00m"; grep -v -E "^#" /etc/passwd 2>/dev/null| awk -F: '$3 == 0 { print $1}' 2>/dev/null
echo -e ""

#pull out vital sudoers info
sudoers=`cat /etc/sudoers 2>/dev/null | grep -v -e '^$'|grep -v "#"`
echo -e "\e[00;31mSudoers configuration (condensed):\e[00m"
if [ "$sudoers" ]; then
  echo -e "$sudoers\n"
else 
  echo -e "None\n"
fi

#can we sudo without supplying a password
sudoperms=`echo '' | sudo -S -l 2>/dev/null`
if [ "$sudoperms" ]; then
  echo -e "\e[00;33m***We can sudo without supplying a password!\e[00m\n$sudoperms\n"
else 
  :
fi

#known 'good' breakout binaries
sudopwnage=`echo '' | sudo -S -l 2>/dev/null | grep -w 'nmap\|perl\|'awk'\|'find'\|'bash'\|'sh'\|'man'\|'more'\|'less'\|'vi'\|'vim'\|'nc'\|'netcat'\|python\|ruby\|lua\|irb' | xargs -r ls -la 2>/dev/null`
if [ "$sudopwnage" ]; then
  echo -e "\e[00;33m***Possible Sudo PWNAGE!\e[00m\n$sudopwnage\n"
else 
  :
fi

#checks to see if roots home directory is accessible
rthmdir=`ls -ahl /root/ 2>/dev/null`
if [ "$rthmdir" ]; then
  echo -e "\e[00;33m***We can read root's home directory!\e[00m\n$rthmdir\n"
else 
  :
fi

#displays /home directory permissions - check if any are lax
homedirperms=`ls -ahl /home/ 2>/dev/null`
echo -e "\e[00;31mAre permissions on /home directories lax:\e[00m\n$homedirperms\n"
if [ "$homedirperms" ]; then
  echo -e "$homedirperms\n"
else 
  echo -e "None\n"
fi

#looks for world-reabable files within /home - depending on number of /home dirs & files, this can take some time so is only 'activated' with thorough scanning switch
wrfileshm=`find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null`
echo -e "\e[00;31mWorld-readable files within /home:\e[00m"
if [ "$wrfileshm" ]; then
  echo -e "$wrfileshm\n"
else 
  echo -e "None\n"
fi

#lists current user's home directory contents
homedircontents=`ls -ahl ~ 2>/dev/null`
echo -e "\e[00;31mHome directory contents:\e[00m"
if [ "$homedircontents" ] ; then
  echo -e "$homedircontents\n"
else 
  echo -e "None\n"
fi

#checks for if various ssh files are accessible - this can take some time so is only 'activated' with thorough scanning switch
sshfiles=`find / -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" 2>/dev/null |xargs -r ls`
if [ "$sshfiles" ]; then
  echo -e "\e[00;31mSSH keys/host information found in the following locations:\e[00m\n$sshfiles\n"
else 
  :
fi

#is root permitted to login via ssh
sshrootlogin=`grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print  $2}'`
if [ "$sshrootlogin" = "yes" ]; then
  echo -e "\e[00;31mRoot is allowed to login via SSH:\e[00m"; grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#"
  echo -e "\n"
else 
  :
fi

echo -e "\e[00;33m### ENVIRONMENTAL #######################################\e[00m" |tee -a $report 2>/dev/null

#current path configuration
pathinfo=`echo $PATH 2>/dev/null`
echo -e "\e[00;31mPath information:\e[00m"
if [ "$pathinfo" ]; then
  echo -e "$pathinfo\n"
else 
  echo -e "None\n"
fi

#lists available shells
shellinfo=`cat /etc/shells 2>/dev/null`
echo -e "\e[00;31mAvailable shells:\e[00m"
if [ "$shellinfo" ]; then
  echo -e "$shellinfo\n"
else 
  echo -e "None\n"
fi

#current umask value with both octal and symbolic output
umask=`umask -S 2>/dev/null & umask 2>/dev/null`
echo -e "\e[00;31mCurrent umask value:\e[00m"
if [ "$umask" ]; then
  echo -e "$umask\n"
else 
  echo -e "None\n"
fi

#umask value as in /etc/login.defs
umaskdef=`cat /etc/login.defs 2>/dev/null |grep -i UMASK 2>/dev/null |grep -v "#" 2>/dev/null`
echo -e "\e[00;31mumask value as specified in /etc/login.defs:\e[00m"
if [ "$umaskdef" ]; then
  echo -e "$umaskdef\n"
else 
  echo -e "None\n"
fi

#password policy information as stored in /etc/login.defs
logindefs=`cat /etc/login.defs 2>/dev/null | grep "PASS_MAX_DAYS\|PASS_MIN_DAYS\|PASS_WARN_AGE\|ENCRYPT_METHOD" 2>/dev/null | grep -v "#" 2>/dev/null`
echo -e "\e[00;31mPassword and storage information:\e[00m"
if [ "$logindefs" ]; then
  echo -e "$logindefs\n"
else 
  echo -e "None\n"
fi

echo -e "\e[00;33m### JOBS/TASKS ##########################################\e[00m" |tee -a $report 2>/dev/null

#are there any cron jobs configured
cronjobs=`ls -la /etc/cron* 2>/dev/null`
echo -e "\e[00;31mCron jobs:\e[00m"
if [ "$cronjobs" ]; then
  echo -e "$cronjobs\n"
else 
  echo -e "None\n"
fi

#can we manipulate these jobs in any way
cronjobwwperms=`find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$cronjobwwperms" ]; then
  echo -e "\e[00;33m***World-writable cron jobs and file contents:\e[00m\n$cronjobwwperms\n"
else 
  :
fi

#contab contents
crontab=`cat /etc/crontab 2>/dev/null`
echo -e "\e[00;31mCrontab contents:\e[00m"
if [ "$crontab" ]; then
  echo -e "$crontab\n"
else 
  echo -e "None\n"
fi

crontabvar=`ls -la /var/spool/cron/crontabs 2>/dev/null`
echo -e "\e[00;31mAnything interesting in /var/spool/cron/crontabs:\e[00m"
if [ "$crontabvar" ]; then
  echo -e "$crontabvar\n"
else 
  echo -e "None\n"
fi

anacronjobs=`ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null`
echo -e "\e[00;31mAnacron jobs and associated file permissions:\e[00m"
if [ "$anacronjobs" ]; then
  echo -e "$anacronjobs\n"
else 
  echo -e "None\n"
fi

anacrontab=`ls -la /var/spool/anacron 2>/dev/null`
echo -e "\e[00;31mWhen were jobs last executed (/var/spool/anacron contents):\e[00m"
if [ "$anacrontab" ]; then
  echo -e "$anacrontab\n"
else 
  echo -e "None\n"
fi

#pull out account names from /etc/passwd and see if any users have associated cronjobs (priv command)
cronother=`cat /etc/passwd | cut -d ":" -f 1 | xargs -n1 crontab -l -u 2>/dev/null`
echo -e "\e[00;31mJobs held by all users:\e[00m"
if [ "$cronother" ]; then
  echo -e "$cronother\n"
else 
  echo -e "None\n"
fi

echo -e "\e[00;33m### NETWORKING  ##########################################\e[00m" |tee -a $report 2>/dev/null

#nic information
nicinfo=`/sbin/ifconfig -a 2>/dev/null`
echo -e "\e[00;31mNetwork & IP info:\e[00m"
if [ "$nicinfo" ]; then
  echo -e "$nicinfo\n"
else 
  echo -e "None\n"
fi

#dns settings
nsinfo=`cat /etc/resolv.conf 2>/dev/null | grep "nameserver"`
echo -e "\e[00;31mNameserver(s):\e[00m"
if [ "$nsinfo" ]; then
  echo -e "$nsinfo\n"
else 
  echo -e "None\n"
fi

#default route configuration
defroute=`route 2>/dev/null | grep default`
echo -e "\e[00;31mDefault route:\e[00m"
if [ "$defroute" ]; then
  echo -e "$defroute\n"
else 
  echo -e "None\n"
fi

#listening TCP
tcpservs=`netstat -antp 2>/dev/null`
echo -e "\e[00;31mListening TCP:\e[00m"
if [ "$tcpservs" ]; then
  echo -e "$tcpservs\n"
else 
  echo -e "None\n"
fi

#listening UDP
udpservs=`netstat -anup 2>/dev/null`
echo -e "\e[00;31mListening UDP:\e[00m"
if [ "$udpservs" ]; then
  echo -e "$udpservs\n"
else 
  echo -e "None\n"
fi

echo -e "\e[00;33m### SERVICES #############################################\e[00m" |tee -a $report 2>/dev/null

#running processes as root
psauxroot=`ps aux | grep root 2>/dev/null`
echo -e "\e[00;31mRunning processes as ROOT:\e[00m"
if [ "$psauxroot" ]; then
  echo -e "$psauxroot\n"
else 
  echo -e "None\n"
fi

#running processes
psaux=`ps aux 2>/dev/null`
echo -e "\e[00;31mRunning processes:\e[00m"
if [ "$psaux" ]; then
  echo -e "$psaux\n"
else 
  echo -e "None\n"
fi

#lookup process binary path and permissisons
procperm=`ps aux | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++'`
echo -e "\e[00;31mProcess binaries & associated permissions (from above list):\e[00m"
if [ "$procperm" ]; then
  echo -e "$procperm\n"
else 
  echo -e "None\n"
fi

#anything 'useful' in inetd.conf
inetdread=`cat /etc/inetd.conf 2>/dev/null`
echo -e "\e[00;31mContents of /etc/inetd.conf:\e[00m"
if [ "$inetdread" ]; then
  echo -e "$inetdread\n"
else 
  echo -e "None\n"
fi

#very 'rough' command to extract associated binaries from inetd.conf & show permisisons of each
inetdbinperms=`cat /etc/inetd.conf 2>/dev/null | awk '{print $7}' |xargs -r ls -la 2>/dev/null`
if [ "$inetdbinperms" ]; then
  echo -e "\e[00;31mThe related inetd binary permissions:\e[00m\n$inetdbinperms\n"
else 
  echo -e "None\n"
fi

xinetdread=`cat /etc/xinetd.conf 2>/dev/null`
echo -e "\e[00;31mContents of /etc/xinetd.conf:\e[00m"
if [ "$xinetdread" ]; then
  echo -e "$xinetdread\n"
else 
  echo -e "None\n"
fi

xinetdincd=`cat /etc/xinetd.conf 2>/dev/null |grep "/etc/xinetd.d" 2>/dev/null`
if [ "$xinetdincd" ]; then
  echo -e "\e[00;31m/etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below:\e[00m\n" ls -la /etc/xinetd.d 2>/dev/null
  echo -e "\n"
else 
  :
fi

#very 'rough' command to extract associated binaries from xinetd.conf & show permisisons of each
xinetdbinperms=`cat /etc/xinetd.conf 2>/dev/null | awk '{print $7}' |xargs -r ls -la 2>/dev/null`
if [ "$xinetdbinperms" ]; then
  echo -e "\e[00;31mThe related xinetd binary permissions:\e[00m\n$xinetdbinperms\n"
else 
  :
fi

initdread=`ls -la /etc/init.d 2>/dev/null`
echo -e "\e[00;31m/etc/init.d/ binary permissions:\e[00m"
if [ "$initdread" ]; then
  echo -e "$initdread\n"
else 
  echo -e "None\n"
fi  

#init.d files NOT belonging to root!
initdperms=`find /etc/init.d/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
echo -e "\e[00;31m/etc/init.d/ files not belonging to root (uid 0):\e[00m"
if [ "$initdperms" ]; then
  echo -e "$initdperms\n"
else 
  echo -e "None\n"
fi

rcdread=`ls -la /etc/rc.d/init.d 2>/dev/null`
echo -e "\e[00;31m/etc/rc.d/init.d binary permissions:\e[00m"
if [ "$rcdread" ]; then
  echo -e "$rcdread\n"
else 
  echo -e "None\n"
fi

#init.d files NOT belonging to root!
rcdperms=`find /etc/rc.d/init.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
echo -e "\e[00;31m/etc/rc.d/init.d files not belonging to root (uid 0):\e[00m"
if [ "$rcdperms" ]; then
  echo -e "$rcdperms\n"
else 
  echo -e "None\n"
fi

usrrcdread=`ls -la /usr/local/etc/rc.d 2>/dev/null`
echo -e "\e[00;31m/usr/local/etc/rc.d binary permissions:\e[00m"
if [ "$usrrcdread" ]; then
  echo -e "$usrrcdread\n"
else 
  echo -e "None\n"
fi

#rc.d files NOT belonging to root!
usrrcdperms=`find /usr/local/etc/rc.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
echo -e "\e[00;31m/usr/local/etc/rc.d files not belonging to root (uid 0):\e[00m"
if [ "$usrrcdperms" ]; then
  echo -e "$usrrcdperms\n"
else 
  echo -e "None\n"
fi

echo -e "\e[00;33m### SOFTWARE #############################################\e[00m" |tee -a $report 2>/dev/null

#sudo version - check to see if there are any known vulnerabilities with this
sudover=`sudo -V 2>/dev/null`
if [ "$sudover" ]; then
  echo -e "\e[00;31mSudo version:\e[00m\n$sudover\n"
else 
  :
fi

#mysql details - if installed
mysqlver=`mysql --version 2>/dev/null`
if [ "$mysqlver" ]; then
  echo -e "\e[00;31mMYSQL version:\e[00m\n$mysqlver\n"
else 
  :
fi

#checks to see if root/root will get us a connection
mysqlconnect=`mysqladmin -uroot -proot version 2>/dev/null`
if [ "$mysqlconnect" ]; then
  echo -e "\e[00;33m***We can connect to the local MYSQL service with default root/root credentials!\e[00m\n$mysqlconnect\n"
else 
  :
fi

#mysql version details
mysqlconnectnopass=`mysqladmin -uroot version 2>/dev/null`
if [ "$mysqlconnectnopass" ]; then
  echo -e "\e[00;33m***We can connect to the local MYSQL service as 'root' and without a password!\e[00m\n$mysqlconnectnopass\n"
else 
  :
fi

#postgres details - if installed
postgver=`psql -V 2>/dev/null`
if [ "$postgver" ]; then
  echo -e "\e[00;31mPostgres version:\e[00m\n$postgver\n"
else 
  :
fi

#checks to see if any postgres password exists and connects to DB 'template0' - following commands are a variant on this
postcon1=`psql -U postgres template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon1" ]; then
  echo -e "\e[00;33m***We can connect to Postgres DB 'template0' as user 'postgres' with no password!:\e[00m\n$postcon1\n"
else 
  :
fi

postcon11=`psql -U postgres template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon11" ]; then
  echo -e "\e[00;33m***We can connect to Postgres DB 'template1' as user 'postgres' with no password!:\e[00m\n$postcon11\n"
else 
  :
fi

postcon2=`psql -U pgsql template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon2" ]; then
  echo -e "\e[00;33m***We can connect to Postgres DB 'template0' as user 'psql' with no password!:\e[00m\n$postcon2\n"
else 
  :
fi

postcon22=`psql -U pgsql template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon22" ]; then
  echo -e "\e[00;33m***We can connect to Postgres DB 'template1' as user 'psql' with no password!:\e[00m\n$postcon22\n"
else 
  :
fi

#apache details - if installed
apachever=`apache2 -v 2>/dev/null; httpd -v 2>/dev/null`
if [ "$apachever" ]; then
  echo -e "\e[00;31mApache version:\e[00m\n$apachever\n"
else 
  :
fi

#what account is apache running under
apacheusr=`cat /etc/apache2/envvars 2>/dev/null |grep -i 'user\|group' |awk '{sub(/.*\export /,"")}1'`
if [ "$apacheusr" ]; then
  echo -e "\e[00;31mApache user configuration:\e[00m\n$apacheusr\n"
else 
  :
fi

#list of 'interesting' softwares
soft=`dpkg -l 2>/dev/null | cut -d ' ' -f 3 | grep -w 'realplayer\|eterm\|xorg\|postfix\|pam-krb5\|libvirt_proxy\|pulseaudio\|changetrack\|systemtap\|tmux\|polkit\|pkexec\|nvidia\|libdbus\|udev\|chitex\|pam_wheel\|sdfingerd\|wmapm\|mtools\|kloxo\|zsudo\|davfs2\|ispmanager\|zabbix\|ibstat\|systrace\|virtualbox\|tivoli\|ossec\|oprofile\|usb-creator\|fuse\|espfix64\|apport\|acpid\|wicd\|iteris\|sendfile\|kpopup\|samba\|qopoer\|cdrecord\|hztty\|terminatorx\|rsync\|traceroute\|dump\|vixie-cron\|glibc\|squirrel\|cdrdao\|bitchx\|atari800\|htget\|osh\|exim\|pax\|pileup\|iwconfig\|poppassd\|xmail\|mount-loop\|liblesstif\|cpanel\|openswan\|vccleaner\|calibre\|mount.cifs\|soapbox\|dbus-glib\|chkrootkit\|setroubleshootd\|aport\|overlayfs' | grep -v 'lib'`
echo -e "\e[00;31mList of interesting software for privilage escalation:\e[00m"
if [ "$soft" ]; then
  echo -e "$soft\n"
else 
  echo -e "None\n"
fi

echo -e "\e[00;33m### INTERESTING FILES ####################################\e[00m"

#checks to see if various files are installed
echo -e "\e[00;31mUseful file locations:\e[00m" 2>/dev/null; which nc 2>/dev/null 2>/dev/null; which netcat 2>/dev/null 2>/dev/null; which wget 2>/dev/null 2>/dev/null; which nmap 2>/dev/null 2>/dev/null; which gcc 2>/dev/null 2>/dev/null
echo -e "\n"

#limited search for installed compilers
compiler=`dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null || yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null`
echo -e "\e[00;31mInstalled compilers:\e[00m"
if [ "$compiler" ]; then
  echo -e "$compiler\n"
else 
  echo -e "None\n"
fi

#glibc
glibc=`dpkg --list 2>/dev/null | grep glibc 2>/dev/null || rpm -qa 2>/dev/null | grep glibc 2>/dev/null`
echo -e "\e[00;31mInstalled glibc:\e[00m"
if [ "$glibc" ]; then
  echo -e "$glibc\n"
else 
  echo -e "None\n"
fi

#manual check - lists out sensitive files, can we read/modify etc.
echo -e "\e[00;31mCan we read/write sensitive files:\e[00m" 2>/dev/null; ls -la /etc/passwd 2>/dev/null 2>/dev/null; ls -la /etc/group 2>/dev/null 2>/dev/null; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null 2>/dev/null; ls -la /etc/master.passwd 2>/dev/null 2>/dev/null
echo -e "\n"

#search for suid files - this can take some time so is only 'activated' with thorough scanning switch (as are all suid scans below)
findsuid=`find / -perm -4000 -type f 2>/dev/null`
echo -e "\e[00;31mSUID files:\e[00m"
if [ "$findsuid" ]; then
  echo -e "$findsuid\n"
else 
  echo -e "None\n"
fi

#list of 'interesting' suid files - feel free to make additions
intsuid=`find / -perm -4000 -type f 2>/dev/null | grep -w 'nmap\|perl\|awk\|find\|bash\|sh\|man\|more\|less\|vi\|vim\|nc\|netcat\|python\|ruby\|lua\|irb\|pl' | xargs -r ls -la` 2>/dev/null
if [ "$intsuid" ]; then
  echo -e "\e[00;33m***Possibly interesting SUID files:\e[00m\n$intsuid"
else 
  :
fi

#lists word-writable suid files
wwsuid=`find / -perm -4007 -type f 2>/dev/null`
if [ "$wwsuid" ]; then
  echo -e "\e[00;31mWorld-writable SUID files:\e[00m\n$wwsuid\n"
else 
  :
fi

#lists world-writable suid files owned by root
wwsuidrt=`find / -uid 0 -perm -4007 -type f 2>/dev/null`
if [ "$wwsuidrt" ]; then
  echo -e "\e[00;31mWorld-writable SUID files owned by root:\e[00m\n$wwsuidrt\n"
else 
  :
fi

#search for guid files - this can take some time so is only 'activated' with thorough scanning switch (as are all guid scans below)
findguid=`find / -perm -2000 -type f 2>/dev/null`
echo -e "\e[00;31mGUID files:\e[00m"
if [ "$findguid" ]; then
  echo -e "$findguid\n"
else 
  echo -e "None\n"
fi

#list of 'interesting' guid files - feel free to make additions
intguid=`find / -perm -2000 -type f 2>/dev/null | grep -w 'nmap\|perl\|awk\|find\|bash\|sh\|man\|more\|less\|vi\|vim\|nc\|netcat\|python\|ruby\|lua\|irb\|pl' | xargs -r ls -la`
if [ "$intguid" ]; then
  echo -e "\e[00;33m***Possibly interesting GUID files:\e[00m\n$intguid"
else 
  :
fi

#lists world-writable guid files owned by root
wwguidrt=`find / -uid 0 -perm -2007 -type f 2>/dev/null`
if [ "$wwguidrt" ]; then
  echo -e "\e[00;31mAWorld-writable GUID files owned by root:\e[00m\n$wwguidrt\n"
else 
  :
fi

#list all world-writable files excluding /proc
wwfiles=`find / ! -path "*/proc/*" -perm -2 -type f -print 2>/dev/null`
echo -e "\e[00;31mWorld-writable files (excluding /proc):\e[00m"
if [ "$wwfiles" ]; then
  echo -e "$wwfiles\n"
else 
  echo -e "None\n"
fi

#list all world-writable folders excluding /proc
wwfolders=`find / ! -path "*/proc/*" -perm -2 -type d -print 2>/dev/null`
echo -e "\e[00;31mWorld-writable folders (excluding /proc):\e[00m"
if [ "$wwfolders" ]; then
  echo -e "$wwfolders\n"
else 
  echo -e "None\n"
fi

#list all writable files by current user excluding /proc
wcfiles=`find / ! -path "*/proc/*" -writable -type f -print 2>/dev/null`
echo -e "\e[00;31mWritable files by current user (excluding /proc):\e[00m"
if [ "$wcfiles" ]; then
  echo -e "$wcfiles\n"
else 
  echo -e "None\n"
fi

#list all writable folders by current user excluding /proc
wcfolders=`find / ! -path "*/proc/*" -writable -type d -print 2>/dev/null`
echo -e "\e[00;31mWritable folders by current user (excluding /proc):\e[00m"
if [ "$wcfolders" ]; then
  echo -e "$wcfolders\n"
else 
  echo -e "None\n"
fi

#are any .plan files accessible in /home (could contain useful information)
usrplan=`find /home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$usrplan" ]; then
  echo -e "\e[00;31mPlan file permissions and contents:\e[00m\n$usrplan\n"
else 
  :
fi

bsdusrplan=`find /usr/home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$bsdusrplan" ]; then
  echo -e "\e[00;31mPlan file permissions and contents:\e[00m\n$bsdusrplan\n"
else 
  :
fi

#are there any .rhosts files accessible - these may allow us to login as another user etc.
rhostsusr=`find /home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostsusr" ]; then
  echo -e "\e[00;31mrhost config file(s) and file contents:\e[00m\n$rhostsusr\n"
else 
  :
fi

bsdrhostsusr=`find /usr/home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$bsdrhostsusr" ]; then
  echo -e "\e[00;31mrhost config file(s) and file contents:\e[00m\n$bsdrhostsusr\n"
else 
  :
fi

rhostssys=`find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostssys" ]; then
  echo -e "\e[00;31mHosts.equiv file details and file contents: \e[00m\n$rhostssys\n"
  else 
  :
fi

#list nfs shares/permisisons etc.
nfsexports=`ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null`
if [ "$nfsexports" ]; then
  echo -e "\e[00;31mNFS config details: \e[00m\n$nfsexports\n"
  else 
  :
fi

#show /etc/fstab content.
fstabshow=`cat /etc/fstab 2>/dev/null`
echo -e "\e[00;31mFstab config details: \e[00m"
if [ "$fstabshow" ]; then
  echo -e "$fstabshow\n"
else 
  echo -e "None\n"
fi

#looking for credentials in /etc/fstab
fstab=`cat /etc/fstab 2>/dev/null |grep username |awk '{sub(/.*\username=/,"");sub(/\,.*/,"")}1'| xargs -r echo username:; cat /etc/fstab 2>/dev/null |grep password |awk '{sub(/.*\password=/,"");sub(/\,.*/,"")}1'| xargs -r echo password:; cat /etc/fstab 2>/dev/null |grep domain |awk '{sub(/.*\domain=/,"");sub(/\,.*/,"")}1'| xargs -r echo domain:`
if [ "$fstab" ]; then
  echo -e "\e[00;33m***Looks like there are credentials in /etc/fstab!\e[00m\n$fstab\n"
else 
  :
fi

fstabcred=`cat /etc/fstab 2>/dev/null |grep cred |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1'| xargs -I{} sh -c 'ls -la {}; cat {}'`
if [ "$fstabcred" ]; then
    echo -e "\e[00;33m***/etc/fstab contains a credentials file!\e[00m\n$fstabcred"
else
    :
fi

#quick extract of .conf files from /etc - only 1 level
allconf=`find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} \; 2>/dev/null`
echo -e "\e[00;31mAll *.conf files in /etc (recursive 1 level):\e[00m"
if [ "$allconf" ]; then
  echo -e "$allconf\n"
else 
  echo -e "None\n"
fi

#extract any user history files that are accessible
usrhist=`ls -la ~/.*_history 2>/dev/null`
if [ "$usrhist" ]; then
  echo -e "\e[00;31mCurrent user's history files:\e[00m\n$usrhist\n"
else 
  :
fi

#can we read roots *_history files - could be passwords stored etc.
roothist=`ls -la /root/.*_history 2>/dev/null`
if [ "$roothist" ]; then
  echo -e "\e[00;33m***Root's history files are accessible!\e[00m\n$roothist\n"
else 
  :
fi

#is there any mail accessible
readmail=`ls -la /var/mail 2>/dev/null`
if [ "$readmail" ]; then
  echo -e "\e[00;31mAny interesting mail in /var/mail:\e[00m\n$readmail\n"
else 
  :
fi

#can we read roots mail
readmailroot=`head /var/mail/root 2>/dev/null`
if [ "$readmailroot" ]; then
  echo -e "\e[00;33m***We can read /var/mail/root! (snippet below)\e[00m\n$readmailroot"
else 
  :
fi

#tmp directory
tmp1=`ls -la /tmp 2>/dev/null`
if [ "$tmp1" ]; then
  echo -e "\e[00;31mAny interesting files in /tmp:\e[00m\n$tmp1\n"
else 
  :
fi

tmp2=`ls -la /var/tmp 2>/dev/null`
if [ "$tmp2" ]; then
  echo -e "\e[00;31mAny interesting files in /var/tmp:\e[00m\n$tmp2\n"
else 
  :
fi

tmp3=`ls -la /usr/local/tmp 2>/dev/null`
if [ "$tmp3" ]; then
  echo -e "\e[00;31mAny interesting files in /usr/local/tmp:\e[00m\n$tmp3\n"
else 
  :
fi

echo -e "\e[00;33m### SCAN COMPLETE ####################################\e[00m"

#EndOfScript
