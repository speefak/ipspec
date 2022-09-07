#!/bin/bash
#
# name          : ipspec.sh
# desciption    : show IP and LAN Information
# autor         : Speefak ( itoss@gmx.de )
# licence       : (CC) BY-NC-SA
# version	: 2.2
#
#------------------------------------------------------------------------------------------------------------
############################################################################################################
#######################################   define global variables   ########################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------

 RequiredPackets="lynx curl geoip-bin nmap"

 CODENAME=$(lsb_release -d | tr -d : | cut -f 2) 
 ARCHITECTURE=$(getconf LONG_BIT)
 LANIP=$(hostname -I | tr " " "\n" | uniq)
 LANMAC=$(ip addr | grep  -B1 $LANIP | head -n1 | cut -d " " -f6)
 GatewayIP=$(ip route | sed -n 1p | cut -d " " -f3) 

 FritzboxIP=$GatewayIP
 FritzboxPrintNewIPDelay=3

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
	printf "  -fbr		renew fritzbox WAN IP\n"
	printf "  -cfrp		check for required packets"
	
	# output error message 
	printf  "\e[0;31m\n $1\e[0m\n"$(tput sgr0)
	printf "\n"
	exit
}
#------------------------------------------------------------------------------------------------------------
check_for_required_packages () {

	InstalledPacketList=$(dpkg -l | grep ii)

	for Packet in $RequiredPackets ; do
		if [[ -z $(grep -w $Packet <<< $InstalledPacketList) ]]; then
			MissingPackets=$(echo $MissingPackets $Packet)
   		fi
	done
 
	# print status message / install dialog
	if [[ -n $MissingPackets ]]; then
		printf  "missing packets: \e[0;31m $MissingPackets\e[0m\n"$(tput sgr0)
		read -e -p "install required packets ? (Y/N) "		 	-i "Y" 		InstallMissingPackets
		if   [[ $InstallMissingPackets == [Yy] ]]; then

			# install software packets
			sudo apt update
			sudo apt install $MissingPackets
			if [[ ! $? == 0 ]]; then 
				exit
			fi
		else 
			printf  "programm error: \e[0;31m missing packets : $MissingPackets\e[0m\n\n"$(tput sgr0)
			exit 1
		fi

	else
		printf " all required packets detected\n"
	fi
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

	# get WAN IP and geo location
	IPDiscoverServices="	https://check.torproject.org;Your IP address appears to be:
				https://showip.net;.
				https://showmyip.gr;Your IP is: 
				https://meineipadresse.de;Meine IP-Adresse
				http://checkip.dyndns.org;Current IP Address:"

	SAVEIFS=$IFS
	IFS=$(echo -en "\n\b")
	for IPDiscoverService in $IPDiscoverServices ; do

		ServiceURL=$( cut -d ";" -f1 <<<  $IPDiscoverService | sed 's/^[ \t]*//')
		GrepExpression=$( cut -d ";" -f2 <<< $IPDiscoverService)

		WANIP=$(wget -q -O - $(eval echo $ServiceURL) | grep "$GrepExpression" | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
		if [[ -n $WANIP ]]; then break ; fi

	done
	IFS=$SAVEIFS

	GeoLocation=$(geoiplookup $WANIP | awk -F ": " '{print $2}')
	

 	#TorCheck=$(wget -q -O - https://check.torproject.org | grep "Tor" | sed -n 1p | cut -d " "  -f7 | cut -d "." -f1)
 	TorCheck=$(lynx --dump https://check.torproject.org | sed -n 6p | cut -d . -f1)
 	TorCheck=${TorCheck//Sorry/$(tput setaf 1)"inactive" $(tput sgr0)       }
 	TorCheck=${TorCheck//Congratulations/$(tput setaf 2)"active"$(tput sgr0)          }

 	# get gateway http interface inforamtions
 	GatewayHTTPString=$(wget -q -O - $GatewayIP) 
 
	# Fritzbox gateway
	if [[ -n $(echo $GatewayHTTPString | grep 'FRITZ!Box') ]] ;then 
		GatewayDevice=$(echo $GatewayHTTPString | grep 'FRITZ!Box' | awk -F "bluBarTitle" '{print $2}' | cut -d '"' -f3)
	fi 

	# no gateway information available
	GatewayDevice=${GatewayDevice:-unknown}

	print_parser SeperatorLine
	print_parser "WAN IP" "=>" "$WANIP" "($GeoLocation)"
	print_parser "LAN IP" "=>" "$LANIP" "($LANMAC)"
	print_parser "Gateway IP" "=>" "$GatewayIP" "($GatewayDevice)"
	print_parser "TOR status" "=>" "$TorCheck" "($ServiceURL)"
	print_parser SeperatorLine
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
print_parser () {

	if [[ $1 == SeperatorLine ]]; then
		printf "+-------------------------------------------------------------------+\n"
	else
		printf "| %-11s %-4s %-16s %-30s  | \n" "$1" "$2" "$3" "$4" 
	fi
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
fritzbox_reconnect () {
curl "http://$FritzboxIP:49000/igdupnp/control/WANIPConn1" -H "Content-Type: text/xml; charset="utf-8"" -H "SoapAction:urn:schemas-upnp-org:service:WANIPConnection:1#ForceTermination" -d "<?xml version='1.0' encoding='utf-8'?> <s:Envelope s:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/' xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'> <s:Body> <u:ForceTermination xmlns:u='urn:schemas-upnp-org:service:WANIPConnection:1' /> </s:Body> </s:Envelope>"
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
fritzbox_WAN_IP () {
wget -qO- "http://$FritzboxIP:49000/igdupnp/control/WANIPConn1" --header "Content-Type: text/xml; charset="utf-8"" --header "SoapAction:urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress" --post-data="<?xml version='1.0' encoding='utf-8'?> <s:Envelope s:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/' xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'> <s:Body> <u:GetExternalIPAddress xmlns:u='urn:schemas-upnp-org:service:WANIPConnection:1' /> </s:Body> </s:Envelope>" | grep -Eo '\<[[:digit:]]{1,3}(\.[[:digit:]]{1,3}){3}\>'
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
fritzbox_renew_ip () {
	printf " old FritzBox WAN IP: $(fritzbox_WAN_IP) \n" 
	printf " reconnecting ...\n"
	fritzbox_reconnect 2>&1> /dev/null 2>&1> /dev/null
	sleep $FritzboxPrintNewIPDelay
	printf " new FritzBox WAN IP: $(fritzbox_WAN_IP)\n" 
}
#------------------------------------------------------------------------------------------------------------
############################################################################################################
#############################################   start script   #############################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------

 case $1 in
	
	-sl )	scan_lan;;
	-h  )	usage "help dialog";;
	-fbr)	fritzbox_renew_ip ;;
	-cfrp)	check_for_required_packages;;
	*   )	network_information;;

 esac
