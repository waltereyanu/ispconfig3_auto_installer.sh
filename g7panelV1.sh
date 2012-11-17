#!/bin/bash
#===============================================================================
#
#          FILE:  g7panelV1.sh
# 
#         USAGE:  ./g7panelV1.sh 
# 
#   DESCRIPTION:  
# 
#       OPTIONS:  ---
#  REQUIREMENTS:  ---
#          BUGS:  ---
#         NOTES:  ---
#        AUTHOR:  Walter Eyanu (), waltereyanu@gmail.com
#       COMPANY:  Jolis Intercom
#       VERSION:  1.0
#       CREATED:  11/13/2012 08:18:58 PM EAT
#      REVISION:  ---
#===============================================================================


#-------------------------------------------------------------------------------
#   User has to be root before running this script
#-------------------------------------------------------------------------------
if [[ $(id -u) -ne 0 ]]
then
	echo "Please run this script as root"
	exit 2
fi

#-------------------------------------------------------------------------------
#   This script only runs on debian
#-------------------------------------------------------------------------------

DEBIAN=`cat /etc/debian_version`

if [[ "$DEBIAN" = "" ]]
then
	echo "
	#-------------------------------------------------------------------------------
	#   Sorry This script was developed with debian in mind
	#   		   Exitting now .........
	#-------------------------------------------------------------------------------
	"
	sleep 2
	exit
fi


#-------------------------------------------------------------------------------
#   Functions
#-------------------------------------------------------------------------------


function basic_installations ()
{

	#-------------------------------------------------------------------------------
	#   We first configure the HOSTNAME
	#-------------------------------------------------------------------------------
	read -p "Please enter your HOSTNAME (e.g. puck384): " HOSTNAME
	check=`echo $HOSTNAME | grep -E "[^[:alnum:]\-]"`
	if [[ "$check" != "" ]]
	then
		echo "$HOSTNAME is not a valid HOSTNAME"
		exit 2
	fi

	read -p "Please enter the server domain name ($HOSTNAME.<domainname>): " FQDNNAME
	check=`echo $FQDNNAME | grep -E "[^[:alnum:]\-\.-]"`
	if [[ "$check" != "" ]]
	then
		echo "$FQDNNAME is not a valid domain name!"
		exit 2
	fi

	# We now combine the HOSTNAME to the domain name
	FQDNNAME="$HOSTNAME.$FQDNNAME"

	read -p "Please confirm the server name $FQDNNAME as being correct (y/n)" answer
	if [[ "$answer" != "j" && "$answer" != "y" ]]
	then
		echo "Please go back just to be sure"
		exit 0
	fi

	# This is the server IP
	SERVERIP=`ifconfig | grep -i 'inet addr:' | sed -r "s/.*inet\s+addr:\s*([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)\s+.*/\1.\2.\3.\4/" | grep -v 'addr:127.0.' | head -n 1`
	OK="no"
	while [[ "$OK" = "no" ]]
       	do
		read -p "Main-IP of the server (has to be set up in ifconfig already) [$SERVERIP]: " SETSERVERIP
		if [[ "$SETSERVERIP" = "" ]]
		then
			SETSERVERIP="$SERVERIP" 
		fi
		CHECK=`ifconfig | grep ":$SETSERVERIP "`
		if [[ "$CHECK" = "" ]]
		then
			echo "IP not found in ifconfig"
		else
			OK="yes"
		fi
	done
	SERVERIP="$SETSERVERIP"

	# now we set the HOSTNAME, we first back-up original files just in case
	cp /etc/hosts /etc/hosts.bk
	cp /etc/hostname /etc/hostname.bk
	if [[ -e /etc/mailname ]]
	then
		cp /etc/mailname /etc/mailname.bk
	fi

	CHECK=`grep "$SERVERIP" /etc/hosts`
	if [[" $CHECK" = "" ]]
	then
		echo "$SERVERIP $FQDNNAME $HOST_NAME" >> /etchosts
	fi

	echo "$HOSTNAME" > /etc/hostname
	echo "$FQDNNAME" > /etc/mailname
	hostname $HOSTNAME
	/etc/init.d/hostname.sh start

	apt-get -y update
	apt-get -y install ntp ntpdate
	apt-get -y install vim-nox screen
}    # ----------  end of function basic_installations  ----------


function web_server ()
{
    basic_installations
    
    ## create apt sources
    cp /etc/apt/sources.list /etc/apt/sources.list.bk
    echo "deb http://packages.dotdeb.org squeeze all
    deb http://ftp.de.debian.org/debian/ squeeze-updates main
    deb-src http://packages.dotdeb.org squeeze all" >> /etc/apt/sources.list
    
    wget http://www.dotdeb.org/dotdeb.gpg; cat dotdeb.gpg | apt-key add -
    
    read -p "We are going to install alot of packages, do you wish to continue (y/n)?" ANSWER
    if [[ "$ANSWER" != "j" && "$ANSWER" != "y" ]]
    then
	echo "You've decided to exit! Exiting now...."
	exit 0;
    fi
    
    apt-get update
    apt-get upgrade
    apt-get -y install nginx php5-fpm php5-mysql php5-curl php5-gd php5-intl php-pear php5-imagick php5-imap php5-mcrypt php5-memcache php5-ming php5-ps php5-pspell php5-recode php5-snmp php5-sqlite php5-tidy php5-xmlrpc php5-xsl php-apc fcgiwrap pure-ftpd-common pure-ftpd-mysql quota quotatool vlogger webalizer awstats geoip-database build-essential autoconf automake1.9 libtool flex bison debhelper
    /etc/init.d/nginx start
    /etc/init.d/php5-fpm restart
    apt-get install fail2ban
    cp /etc/default/pure-ftpd-common /etc/default/pure-ftpd-common.bk
    sed -i -r "s/VIRTUALCHROOT=.*VIRTUALCHROOT=true" /etc/default/pure-ftpd-common
    
    /etc/init.d/openbsd-inetd restart
    
    echo 1 > /etc/pure-ftpd/conf/TLS
    mkdir -p /etc/ssl/private/
    openssl req -x509 -nodes -days 7300 -newkey rsa:2048 -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem
    chmod 600 /etc/ssl/private/pure-ftpd.pem
    /etc/init.d/pure-ftpd-mysql restart
    
    cd /tmp
    wget http://olivier.sessink.nl/jailkit/jailkit-2.15.tar.gz
    tar xvfz jailkit-2.15.tar.gz
    cd jailkit-2.15
    ./debian/rules binary
    cd ..
    dpkg -i jailkit_2.15-1_*.deb
    rm -rf jailkit-2.15*
    
    echo "[pureftpd]
    enabled  = true
    port     = ftp
    filter   = pureftpd
    logpath  = /var/log/syslog
    maxretry = 3" >> /etc/fail2ban/jail.local
    
    echo "[Definition]
    failregex = .*pure-ftpd: \(.*@<HOST>\) \[WARNING\] Authentication failed for user.*
    ignoreregex =" >> /etc/fail2ban/filter.d/pureftpd.conf
    
    /etc/init.d/fail2ban restart
    
    cd /tmp
    svn export svn://svn.ispconfig.org/ispconfig3/trunk/
    cd trunk/install
    php -q install.php

}    # ----------  end of function web_server  ----------


function virtual_server ()
{
    #-------------------------------------------------------------------------------
    #   We first configure the HOSTNAME
    #-------------------------------------------------------------------------------
    read -p "Please enter your HOSTNAME (e.g. puck384): " HOSTNAME
    check=`echo $HOSTNAME | grep -E "[^[:alnum:]\-]"`
    if [[ "$check" != "" ]]
    then
	echo "$HOSTNAME is not a valid HOSTNAME"
    exit 2
    fi
    
    read -p "Please enter the server domain name ($HOSTNAME.<domainname>): " FQDNNAME
    check=`echo $FQDNNAME | grep -E "[^[:alnum:]\-\.-]"`
    if [[ "$check" != "" ]]
    then
	echo "$FQDNNAME is not a valid domain name!"
	exit 2
    fi
    # We now combine the HOSTNAME to the domain name
    FQDNNAME="$HOSTNAME.$FQDNNAME"
    
    read -p "Enter the First nameserver\'s IP address: " nameserver_one
    if [[ $nameserver_one =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
    then
	nameserver_one=$nameserver_one
    else
	echo "Sorry that is not a valid IP address"
    fi
    read -p "Enter the Second nameserver's IP address: " nameserver_two
    if [[ $nameserver_two =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
    then
	nameserver_two=$nameserver_two
    else
	echo "Sorry that is not a valid IP address"
    fi
    ## --here wait and first investigate how to do that
    read -p "Enter Diskpace in Gigabites starting with minimumn allowed space: " min
    read -p "Enter Diskpace in Gigabites the maximum allowed: " max
    
    ## -- VPS IP address
    read -p "Enter IP address for you new VPS:" IP
    if [[ $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
    then
	IP=$IP
    else
	echo "Sorry that is not a valid IP address"
    fi
    
    # now here we first find out if there are any VPSs running
    
    # This will list the number of VPSs+1(The HEADING) but then we subtract
    current_vps=`vzlist -a | awk 'END{ print NR-1 }'`
    
    # here we increment the result by 1, we don't want to overwrite already installed
    $current_vps=$[current_vps+1]
    
    vzctl create $current_vps --ostemplate $architecture
    vzctl set $current_vps --onboot yes --save
    vzctl set $current_vps --nameserver $nameserver_one --save
    vzctl set $current_vps --nameserver $nameserver_two --save
    vzctl set $current_vps --hostname $FQDNNAME --save
    vzctl set $current_vps --diskspace ${min}G:${max}G --save
    vzctl set $current_vps --ipadd $IP --save
    vzctl set $current_vps --ram 10.5G --swap 5G --save
    vzctl exec $current_vps passwd
    vzctl start $current_vps
}    # ----------  end of function virtual_server  ----------

function master_server ()
{
	basic_installations
	## create apt sources
	cp /etc/apt/sources.list /etc/apt/sources.list.bk ;
	echo "deb http://ftp.de.debian.org/debian $DISTRIB main contrib non-free" >> /etc/apt/sources.list ;
	echo "deb-src http://ftp.de.debian.org/debian $DISTRIB main contrib non-free" >> /etc/apt/sources.list ;
	echo "deb http://security.debian.org/ $DISTRIB/updates main contrib non-free" >> /etc/apt/sources.list ;
	echo "deb-src http://security.debian.org/ $DISTRIB/updates main contrib non-free" >> /etc/apt/sources.list ;
	echo "deb http://ftp.de.debian.org/debian/ squeeze-updates main" >> /etc/apt/sources.list ;

	apt-get -q -y --force-yes install bc

	# we shall do some update here
	DONE="no"
	STEP=1
	# here $STEP is what we are going to go through am assuming 5 will increase it later if need be
	while [[ "$DONE" = "no" && "$STEP" -lt "5" ]]
	do
		STEP=`echo "$STEP + 1" | bc`
		echo "STEP: $STEP"
		if [[ "$CHECK" != "" ]]
		then
			PUBKEY=`echo "$CHECK" | sed -r "s/.*(NO_PUBKEY)\s+([0-9a-zA-Z]+)(\s+|$).*/\2/" | head -n 1` ;
			echo "PUBKEY: $PUBKEY";
			CHECK=`echo "$PUBKEY" | grep -E "[^A-Za-z0-9]"`
			echo "CHECK2: $CHECK";
			if [[ "$CHECK" = "" ]]
			then
				echo "Importing Public key $PUBKEY."
				gpg --keyserver pgp.mit.edu --recv "$PUBKEY"
				gpg --export --armor "$PUBKEY" | apt-key add - ;
			fi
		else
			DONE="yes"
		fi
	done

	apt-get -q -y dist-upgrade

	## check for ssh option

	CHECK=`grep -e '^SSHD_OOM_ADJUST=-17' /etc/default/ssh`
	if [[ "$CHECK" != "" ]]
	then
		sed -i s/SSHD_OOM_ADJUST=-17/#SSHD_OOM_ADJUST=-17/ /etc/default/ssh
		echo "unset SSHD_OOM_ADJUST" >> /etc/default/ssh
	fi

	## Real installations begin
	
	echo "We are going to install postfix...."
	apt-get -y install postfix postfix-mysql postfix-doc mysql-client mysql-server openssl getmail4 rkhunter binutils dovecot-imapd dovecot-pop3d sudo

	## check for mysql bind option

	CHECK=`grep -e '^bind-address ' /etc/mysql/my.cnf`
	if [[ "$CHECK" != "" ]]
	then
		sed -i s/^bind-address /#bind-address / /etc/mysql/my.cnf
	fi

	/etc/init.d/mysql restart

	echo "Installing Amavisd-new, SpamAssassin, And Clamav"
	apt-get -y install amavisd-new spamassassin clamav clamav-daemon zoo unzip bzip2 arj nomarch lzop cabextract apt-listchanges libnet-ldap-perl libauthen-sasl-perl clamav-docs daemon libio-string-perl libio-socket-ssl-perl libnet-ident-perl zip libnet-dns-perl

	echo "The g7panel setup script uses amavisd which loads the SpamAssassin filter library internally,\n so we you stop SpamAssassin to free up some RAM:"

	/etc/init.d/spamassassin stop
	update-rc.d -f spamassassin remove

	echo "Install Nginx, PHP5 (PHP-FPM), And Fcgiwrap"
	apt-get -y install nginx

	/etc/init.d/nginx start

	echo "We now make sure apache is removed"
	apt-get -y purge apache2 apache2.2-common apache2-doc apache2-mpm-prefork apache2-utils
	apt-get autoremove

	echo "Installing PHP-FPM (FastCGI Process Manager)"
	apt-get -y install php5-fpm
	apt-get -y install php5-mysql php5-curl php5-gd php5-intl php-pear php5-imagick php5-imap php5-mcrypt php5-memcache php5-ming php5-ps php5-pspell php5-recode php5-snmp php5-sqlite php5-tidy php5-xmlrpc php5-xsl
	apt-get -y install php-apc

	echo "Restarting PHP-FPM"
	/etc/init.d/php5-fpm restart

	/etc/init.d/php5-fpm restart
	apt-get -y install pure-ftpd-common pure-ftpd-mysql quota quotatool

	## here i make sure that we've a back-up b4 we screw up, then replace accordingly
	cp /etc/default/pure-ftpd-common /etc/default/pure-ftpd-common.bk
	sed -i -r "s/STANDALONE_OR_INETD=.*STANDALONE_OR_INETD=standalone" /etc/default/pure-ftpd-common
	sed -i -r "s/VIRTUALCHROOT=.*VIRTUALCHROOT=true" /etc/default/pure-ftpd-common

	## here we also comment out ftp in /etc/inetd.conf
	#CHECK=`grep -e 'ftp'` /etc/inetd.conf
	#if [[ "$CHECK" != "" ]]
	#then
	#		sed -i s/^ftp /#ftp / /etc/inetd.conf
	#fi

	# seems not to work, so more to dig around for the repacations
	#/etc/init.d/openbsd-inetd restart
	
	# allow FTP and TLS sessions run
	echo 1 > /etc/pure-ftpd/conf/TLS
	mkdir -p /etc/ssl/private/ 
	openssl req -x509 -nodes -days 7300 -newkey rsa:2048 -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem
	chmod 600 /etc/ssl/private/pure-ftpd.pem
	/etc/init.d/pure-ftpd-mysql restart

	## enable quota
	cp /etc/fstab /etc/fstab.bk

	CHECK=`grep -E "^[^[:space:]]+[[:space:]]+\/[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+" /etc/fstab | grep 'usrquota'`
	if [[ "$CHECK" = "" ]]
	then
		sed -i -r "s/(\S+\s+\/\s+\S+\s+)(\S+)(\s+)/\1\2,usrquota\3/" /etc/fstab
	fi

	CHECK=`grep -E "^[^[:space:]]+[[:space:]]+\/[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+" /etc/fstab | grep 'grpquota'`

	if [[ "$CHECK" = "" ]]
	then
		sed -i -r "s/(\S+\s+\/\s+\S+\s+)(\S+)(\s+)/\1\2,grpquota\3/" /etc/fstab
	fi

	touch /quota.user /quota.group
	chmod 600 /quota.*
	mount -o remount /
	#quotacheck -avugm
	#quotaon -avug


	## Install Vlogger, Webalizer, And AWstats

	apt-get -y install vlogger webalizer awstats geoip-database

	## We comment out everything in /etc/cron.d/awstats
	### This on only comments out on line, will come back later to do multiple

	#CHECK=`grep -e '^10'` /etc/cron.d/awstats
	#if [[ "$CHECK" != "" ]]
	#then
	#	sed -i s/^10 /# / /etc/cron.d/awstats
	#fi

	# here we install jailkit

	apt-get -y install build-essential autoconf automake1.9 libtool flex bison debhelper

	cd /tmp
	wget http://olivier.sessink.nl/jailkit/jailkit-2.15.tar.gz
	tar xvfz jailkit-2.15.tar.gz
	cd jailkit-2.15
	./debian/rules binary
	cd ..
	dpkg -i jailkit_2.15-1_*.deb
	rm -rf jailkit-2.15*

	# Fail2ban

	apt-get -q -y install fail2ban

	echo '[pureftpd]

	enabled = true
	port = ftp
	filter = pureftpd
	logpath = /var/log/syslog
	maxretry = 3

	[sasl]

	enabled = true
	port = smtp
	filter = sasl
	logpath = /var/log/mail.log
	maxretry = 5

	[dovecot-pop3imap]

	enabled = true
	filter = dovecot-pop3imap
	action = iptables-multiport[name=dovecot-pop3imap, port="pop3,pop3s,imap,imaps", protocol=tcp]
	logpath = /var/log/mail.log
	maxretry = 5' > /etc/fail2ban/jail.local

	echo '[Definition]
	failregex = .*pure-ftpd: \(.*@<HOST>\) \[WARNING\] Authentication failed for user.*
	ignoreregex =' > /etc/fail2ban/filter.d/pureftpd.conf

	echo '[Definition]
	failregex = (?: pop3-login|imap-login): .*(?:Authentication failure|Aborted login \(auth failed|Aborted login \(tried to use disabled|Disconnected \(auth failed|Aborted login \(\d+ authentication attempts).*rip=(?P<host>\S*),.*
	ignoreregex =' > /etc/fail2ban/filter.d/dovecot-pop3imap.conf

	/etc/init.d/nginx restart

	apt-get -y install subversion

	cd /tmp
	svn export svn://svn.ispconfig.org/ispconfig3/branches/ispconfig-3.0.5
	cd /tmp/ispconfig-3.0.5/install
	php -q install.php
	
	# We change SSL certificates
	while :
	do
		clear
		echo "

		#-------------------------------------------------------------------------------
		#   Please remember to copy from wiki.ltd.ug the certificates
		#               ----------------------------
		#
		#   vim /etc/postfix/smtpd.cert
		#   vim /etc/postfix/smtpd.key
		#   /usr/lib/courier-imap/share/imapd.pem
		#   /etc/pki/tls/cert.pem
		#   /etc/pki/tls/certs/localhost.crt
		#   /etc/pki/tls/private/localhost.key
		#   /usr/local/ispconfig/interface/ssl/ispserver.crt
		#   /usr/local/ispconfig/interface/ssl/ispserver.key
		#
		#   /etc/init.d/nginx restart
		#   /etc/init.d/postfix restart
		#
		#-------------------------------------------------------------------------------
		"
	done
	
	clear
	echo"
	#-------------------------------------------------------------------------------
	#   HERE YOU CAN INSTALL OPEN VPSs PLEASE CHOOSE IF YOU WISH TO CONTINUE!!
	#-------------------------------------------------------------------------------
	"
	
	read -p "Do you wish to continue installing OPEN VPSs (y/n)" answer
	if [[ "$answer" != "j" && "$answer" != "y" ]]
	then
		echo "G7Panel installations finished, now exitting..."
		exit 2
	fi
	
	# openvz installations
	
	apt-get -y install linux-image-openvz-amd64 vzctl vzquota vzdump
	# we remove already installed templates
	
	arch=`uname -m`
	if [[ "$arch" == "x86_64" ]]
	then
	    apt-get -y install linux-image-openvz-amd64 vzctl vzquota vzdump
	else
	    apt-get -y install linux-image-openvz-686 vzctl vzquota vzdump
	fi
	
	ln -s /var/lib/vz /vz
	
	echo "
	net.ipv4.conf.all.rp_filter=1
	net.ipv4.icmp_echo_ignore_broadcasts=1
	net.ipv4.conf.default.forwarding=1
	net.ipv4.conf.default.proxy_arp = 0
	net.ipv4.ip_forward=1
	kernel.sysrq = 1
	net.ipv4.conf.default.send_redirects = 1
	net.ipv4.conf.all.send_redirects = 0
	net.ipv4.conf.eth0.proxy_arp=1
	" >> /etc/sysctl.conf
	
	sysctl -p
	
	# If the IP addresses of your virtual machines are from a different subnet than the host system's IP address. 
	# If you don't do this, networking will not work in the virtual machines!
	
	sed -i -r "s/NEIGHBOUR_DEVS=.*NEIGHBOUR_DEVS=all" /etc/vz/vz.conf
	
	clear
	
	echo "======================================================="
	echo "We're going to REBOOT for changes to take effect!"
	echo "======================================================="
	
	read -p "Do you wish to continue installing OPEN VPSs (y/n)" answer
	if [[ "$answer" != "j" && "$answer" != "y" ]]
	then
		echo "You decided to exit without rebooting, however remember that you won't be able to install VPSs minus a reboot"
		exit 2
	fi
	
	reboot
	
	
	rm /var/lib/vz/template/cache/*
	
	cd /var/lib/vz/template/cache
	
	arch=`uname -m`
	if [[ "$arch" == "x86_64" ]]
	then
	    wget http://download.openvz.org/template/precreated/contrib/debian-6.0-amd64-minimal.tar.gz
	    architecture=debian-6.0-amd64-minimal
	else
	    wget http://download.openvz.org/template/precreated/contrib/debian-6.0-i386-minimal.tar.gz
	    architecture=debian-6.0-i386-minimal
	fi
	
	

}    # ----------  end of function master_server  ----------




while :
do
    clear
    echo "
    =================================================================================
    =
    =		CHOOSE THE TYPE OF SERVER YOU WISH TO INSTALL...
    =
    =================================================================================
    
    [1] - MASTER SERVER
    [2] - WEB SERVER
    [3] - DATABASE SERVER
    [4] - MAIL SERVER
    [5] - OpenVZ
    [99] - EXIT
    
    =================================================================================

    ENTER YOUR OPTION: "

    read OPTION
    test "$OPTION" = "1" || test "$OPTION" = "2" || test "$OPTION" = "3" || test "$OPTION" = "4" || test "$OPTION" = "5" || test "$OPTION" = "99"
    if [ "$?" -eq 1 ]
    then
	    echo "This Option Doesn't exits"
	    sleep 2
    else
	    break
    fi
done
case "$OPTION" in
    1)
	echo "You choose to install Master Server"
	master_server
    ;;
    2)
	echo "You choose to install Web Server"
	web_server
    ;;
    3)
    ;;
    4)
    ;;
    5)
	echo "You've chosen to install a Virtual Private Server"
	virtual_server
    ;;
    99)
	echo "Exiting ...."
	sleep 1
	clear
	exit
esac
