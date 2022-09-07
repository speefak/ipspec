#!/bin/bash
#
# name          : ipspec
# desciption    : show IP and LAN Information
# autor         : Speefak ( itoss@gmx.de )
# licence       : (CC) BY-NC-SA
# version	: 1.0
#
#------------------------------------------------------------------------------------------------------------
############################################################################################################
#######################################   define global variables   ########################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------

 CODENAME=$(lsb_release -d | tr -d : | cut -f 2) 
 ARCHITECTURE=$(getconf LONG_BIT)
 LANIP=$(hostname -I | tr " " "\n" | uniq)
 GATEWAY_IP=$(ip route | sed -n 1p | cut -d " " -f3)

#------------------------------------------------------------------------------------------------------------
############################################################################################################
###########################################   define functions   ###########################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------
usage() {
	clear
	printf "\n"	
	printf " Usage: $(basename $0) <option>\n"
	printf "\n"
	printf "  default	show IP / LAN information\n"
	printf "  -sl		scan LAN\n"
	
	# output error message 
	printf  "\e[0;31m\n $1\e[0m\n"$(tput sgr0)
	printf "\n"
	exit
}
#------------------------------------------------------------------------------------------------------------
scan_lan () {

	printf " \n\n"
	printf " Your Linux Distibution is $CODENAME $ARCHITECTURE bit\n"
	printf " Your LAN ip is $LANIP\n"
	printf " \n\n"
	printf " Press any key to start scan\n"

	read

	for IP in $LANIP ;do
 		nmap $IP/24
	done

}
#------------------------------------------------------------------------------------------------------------
network_information () {

	WANIP=$(wget -q -O - https://check.torproject.org | grep "Your IP address appears to be:" | cut -d ">" -f3 | cut -d "<" -f1)		# HTTPS yes
 	#WANIP=$(wget -q -O - checkip.dyndns.org|sed -e 's/.*Current IP Address: //' -e 's/<.*$//')						# HTTPS no
 	#WANIP=$(wget -q -O - http://www.nwlab.net/cgi-bin/show-ip-js | cut -d'>' -f2 | cut -d '<' -f 1 | sed -ne '2p')

 	#TORCHECK=$(wget -q -O - https://check.torproject.org | grep "Tor" | sed -n 1p | cut -d " "  -f7 | cut -d "." -f1)
 	TORCHECK=$(lynx --dump https://check.torproject.org | sed -n 6p | cut -d . -f1)
 	TORCHECK=${TORCHECK//Sorry/$(tput setaf 1)"inactive" $(tput sgr0)}
 	TORCHECK=${TORCHECK//Congratulations/$(tput setaf 2)"active"$(tput sgr0)}

 	# get gateway http interface inforamtions
 	GATEWAY_HTTP_STRING=$(wget -q -O - $GATEWAY_IP) 
 
	# Fritzbox gateway
	if [[ -n $(echo $GATEWAY_HTTP_STRING | grep 'FRITZ!Box') ]] ;then 
		GATEWAY_DEVICE=$(echo $GATEWAY_HTTP_STRING | grep 'FRITZ!Box' | awk -F "bluBarTitle" '{print $2}' | cut -d '"' -f3)
	fi 

	# no gateway information available
	GATEWAY_DEVICE=${GATEWAY_DEVICE:-unknown}

	printf "WAN IP     => $WANIP\n"
	printf "LAN IP     => $LANIP\n"
	printf "GATEWAY IP => $GATEWAY_IP\n"
	printf "GW Device  => $GATEWAY_DEVICE\n"
	printf "TOR Net    => $TORCHECK\n"
}
#------------------------------------------------------------------------------------------------------------
############################################################################################################
#############################################   start script   #############################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------

 case $1 in
	
	-sl )	scan_lan;;
	-h  )	usage "help dialog";;
	*   )	network_information;;

 esac

exit 0
