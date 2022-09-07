#!/bin/bash
#
# name          : ipspec.sh
# desciption    : show IP and LAN Information
# autor         : Speefak ( itoss@gmx.de )
# licence       : (CC) BY-NC-SA
# version	: 2.4
#
#------------------------------------------------------------------------------------------------------------
############################################################################################################
#######################################   define global variables   ########################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------

 RequiredPackets="lynx curl geoip-bin nmap speedtest-cli"
 SpeedtestTempFile=/tmp/spdt.tmp

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
	printf "  -bm		bandwidth measurement\n"
	printf "  -fbr		renew fritzbox WAN IP\n"
	printf "  -cfrp		check for required packets"
	
	# output error message 
	printf  "\e[0;31m\n $1\e[0m\n"$(tput sgr0)
	printf "\n"
	exit
}
#------------------------------------------------------------------------------------------------------------
command_check () {

	if [[ -z $(which $1) ]]; then
		usage "missing command (use option -cfrp): $1"
	fi
}
#------------------------------------------------------------------------------------------------------------
progressbar () {   						# usage : progressbar  "MESSAGE" 3 "."
	tput civis
	echo -ne "$1 "
	for i in `seq 1 $2`; do
		echo -en "\033[K$3"
		sleep 1
	done 
	echo -en "\015" 
	tput cvvis
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
print_parser () {

	if   [[ $(grep SeperatorLine <<< $@) ]]; then
		printf "+---------------------------------------------------------------------------+\n"
	elif [[ $PrintParser == "network_information" ]]; then		
		printf "| %-11s %-4s %-16s %-38s  | \n" "$1" "$2" "$3" "$4" 
	elif [[ $PrintParser == "bandwidth_measurement" ]]; then
#		Cut3=$(echo $3 | cut -c1-35)							# Error for colored output		
		printf "| %-11s %-4s %-35s %-20s | \n" "$1" "$2" "$3" "$4" 			# TODO => Format Error => Check printf config
	fi
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
#-------------------------------------------------------------------------------------------------------------------------------------------------------
scan_lan () {

	command_check "nmap"

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
				https://showmyip.gr;Your IP is: 
				https://meineipadresse.de;Meine IP-Adresse
				http://checkip.dyndns.org;Current IP Address:"

	SAVEIFS=$IFS
	IFS=$(echo -en "\n\b")
	for IPDiscoverService in $IPDiscoverServices ; do

		ServiceURL=$( cut -d ";" -f1 <<<  $IPDiscoverService | sed 's/^[ \t]*//')
		GrepExpression=$( cut -d ";" -f2 <<< $IPDiscoverService)

		WANIP=$(wget -q -O - $(eval echo $ServiceURL) | grep "$GrepExpression" | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
		if [[ -n $WANIP ]]; then 
			break
		else
			ErrorLog=$(echo "$ErrorLog" "Website unreachable: $ServiceURL\n") 
		fi
	done
	IFS=$SAVEIFS

	if [[ -n $ErrorLog ]]; then usage "\n $(echo $ErrorLog)" ; fi

	GeoLocation=$(geoiplookup $WANIP | awk -F ": " '{print $2}')
	GeoLocation=${GeoLocation/IP Address not found/XX}

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

	PrintParser="network_information"
	print_parser SeperatorLine
	print_parser "WAN IP" "=>" "$WANIP" "($GeoLocation)"
	print_parser "LAN IP" "=>" "$LANIP" "($LANMAC)"
	print_parser "Gateway IP" "=>" "$GatewayIP" "($GatewayDevice)"
	print_parser "TOR status" "=>" "$TorCheck" "($ServiceURL)"
	print_parser SeperatorLine
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
bandwidth_measurement () {

	command_check "speedtest"

	print_parser SeperatorLine

	# start measurement
	$(speedtest > $SpeedtestTempFile) &

	# wait for finish measurement
	while [[  $(pgrep speedtest)  ]]; do
		progressbar "| Bandwidth measurement in progress " 3 .
	done

	# set output vars
	SpeedtestOutput=$(cat $SpeedtestTempFile)
	ClientISPName=$(echo "$SpeedtestOutput" | grep "Testing from " | cut -d " " -f3-10 | sed 's/ (.*//g' | cut -c1-35)	# TODO write caractersund to parser
	ClientISPIP=$(echo "$SpeedtestOutput" | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
	TargetHost=$(echo "$SpeedtestOutput"  | grep "Hosted by " | cut -d " " -f3-20  | sed 's/ \[.*//g' | cut -c1-35)		# TODO write caractersund to parser
	TargetHostDistance=$(echo "$SpeedtestOutput"  | grep "Hosted by " | tr "[" "\n" | tr "]" "\n" | grep  " km")
	Ping=$(echo "$SpeedtestOutput"  | grep "Hosted by " | awk -F "km]: " '{print $2}')
	DownloadSpeed=$(echo "$SpeedtestOutput" | grep "Download:" | cut -d " " -f2-4)
	UploadSpeed=$(echo "$SpeedtestOutput" | grep "Upload:" | cut -d " " -f2-4)
	GeoLocation=$(geoiplookup $ClientISPIP 2> /dev/null| awk -F ": " '{print $2}' | cut -d "," -f1)
	GeoLocation=${GeoLocation/IP Address not found/XX}

	PrintParser="bandwidth_measurement"

#	print_parser "Local host" "=>" "123" "(123)"
#	print_parser "Remote host" "=>" "123" "(123)"
#	print_parser "Bandwidth" "=>" "down: $(tput setaf 2)123$(tput sgr0) up: $(tput setaf 1)123 $(tput sgr0)" "ping: 123"

	print_parser "Local host" "=>" "$ClientISPName" "($ClientISPIP|$GeoLocation)"
	print_parser "Remote host" "=>" "$TargetHost" "($TargetHostDistance)"
	print_parser "Bandwidth" "=>" "down: $(tput setaf 2)$DownloadSpeed$(tput sgr0) up: $(tput setaf 1)$UploadSpeed $(tput sgr0)" " ping: $Ping    "
	print_parser SeperatorLine

	#rm $SpeedtestTempFile

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

	-h  )	usage "help dialog";;
	-sl )	scan_lan;;
	-bm )	bandwidth_measurement;;
	-fbr)	fritzbox_renew_ip ;;
	-cfrp)	check_for_required_packages;;
	*   )	network_information;;

 esac
