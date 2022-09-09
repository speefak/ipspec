#!/bin/bash
#
# name          : ipspec.sh
# desciption    : show IP and LAN Information
# autor         : Speefak ( itoss@gmx.de )
# licence       : (CC) BY-NC-SA
# version	: 3.2
#
#------------------------------------------------------------------------------------------------------------
############################################################################################################
#######################################   define global variables   ########################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------

 RequiredPackets="lynx curl geoip-bin nmap speedtest-cli"
 SpeedtestTempFile=/tmp/spdt.tmp
 MaxScriptExecutionIntervalBandwidth=180

 WanIPLogfile=/tmp/wanip.log
 WanIPLogDelay=10
# RecordlinesCount=10 # TODO printf only specyfied lines

 Codename=$(lsb_release -d | tr -d : | cut -f 2)
 Architecture=$(getconf LONG_BIT)
 LANDevice=$(ip route | grep default | awk -F "dev " '{print $2}' | cut -d " " -f1 | sort -u)
 LANIP=$(ip -br addr show $LANDevice | awk '{print $3}' | cut -d "/" -f1)
 GatewayIP=$(ip route | grep default |  sed -n 1p | cut -d " " -f3)
 GatewayMAC=$(ip neigh | grep -w $GatewayIP 2> /dev/null | head -n1 | tr " " "\n" | grep "[[:alnum:]][[:alnum:]]:")
 DNSServerList=$(cat /etc/resolv.conf |grep -i '^nameserver'|cut -d ' ' -f2 | tr "\n" " " | sed 's/ $//'| sed 's/ /,/g' )
 DNSServerlistNmCLI="$(nmcli -t --fields NAME con show --active 2>/dev/null)"

 FritzboxIP=$GatewayIP
 FritzboxPrintNewIPWanIPLogDelay=3

 Version=$(cat $(readlink -f $(which $0)) | grep "# version" | head -n1 | awk -F ":" '{print $2}' | sed 's/ //g')
 ScriptFile=$(readlink -f $(which $0))
 ScriptName=$(basename $ScriptFile)

#------------------------------------------------------------------------------------------------------------
############################################################################################################
###########################################   define functions   ###########################################
############################################################################################################
#-------------------------------------------------------------------------------------------------------------------------------------------------------
usage() {
	clear

	printf "\n"
	printf " Usage: $(basename $0) <option>\n"
	printf "\n"
	printf " -h		help dialog \n"
	printf " -i		show script information\n"
	printf " -m		monocrome output\n"
	printf "\n"
	printf " default	show IP / LAN information ( used devices )\n"
	printf " -v		show IP / LAN information ( all devices )\n"
	printf " -sl		scan LAN (nmap) \n"
	printf " -bm		bandwidth measurement\n"
	printf " -lw		log wan ip\n"
	printf " -fbr		renew fritzbox WAN IP\n"
	printf " -cfrp		check for required packets\n"

	# output error message
	printf "\n"
	printf  "\e[0;31m\n $1\e[0m\n"$end
	printf "\n"
	exit
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
check_input_options () {

	# create available options list
	InputOptionList=$(cat $ScriptFile | sed -n '/usage()/,/exit/p' | grep " -[[:alpha:]]" | awk '{print $3}' | grep "^\-")

	# check for valid input options
	for Option in $@ ; do	
		if [[ -z $(grep -w -- "$Option" <<< "$InputOptionList") ]]; then
			InvalidOptionList=$(echo $InvalidOptionList $Option)
		fi
	done

	# print invalid options and exit script_information
	if [[ -n $InvalidOptionList ]]; then
		usage "invalid option: $InvalidOptionList"
	fi
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
load_colorcodes () {
	red=$'\e[0;31m'
	grn=$'\e[0;32m'
	yel=$'\e[0;33m'
	blu=$'\e[0;34m'
	mag=$'\e[0;35m'
	cyn=$'\e[0;36m'
	end=$'\e[0m'
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
script_information () {
	printf "\n"
	printf " Scriptname: $ScriptName\n"
	printf " Version:    $Version \n"
	printf " Location:   $(pwd)/$ScriptName\n"
	printf " Filesize:   $(ls -lh $0 | cut -d " " -f5)\n"
	printf "\n"
	exit 0
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
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
		printf "+---------------------------------------------------------------------------------------------------+\n"
	elif [[ $PrintParser == "info_line"  ]]; then
		printf "| %-97s | \n" "$1"
	elif [[ $PrintParser == "network_information" ]]; then
		printf "| %-11s %-4s %-38s %-41s | \n" "$1" "$2" "$3" "$4"
	elif [[ $PrintParser == "bandwidth_measurement" ]]; then
		printf "| %-11s %-4s %-38s %-41s | \n" "$1" "$2" "$3" "$4"
	fi
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
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
			sudo apt install -y $MissingPackets
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

	printf " \n\n"
	printf " Your Linux Distibution is $Codename $Architecture bit\n"
	printf " Your LAN ip is $LANIP\n"
	printf " \n\n"

	for IP in $LANIP ;do
 		nmap $IP/24
	done
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
check_LAN_connection () {

	# check LAN connection
	if [[ -z $(hostname -I) ]]; then
		usage " No LAN / WLAN connection"
	fi
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
check_WAN_connection () {
	# check WAN connection
	nc -zw1 8.8.8.8 443
	if [[ ! $? == 0 ]]; then
		WANConnection="offline"
	fi
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
get_wan_IP () {

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

		# check for valid WAN IP / break URL check loop if WANIP contains valid IP
		WANIP=$(wget -q -O - $(eval echo $ServiceURL) | grep "$GrepExpression" | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
		if [[ -n $WANIP ]]; then
			break
		else
			ErrorLog=$(echo "$ErrorLog" "Website unreachable: $ServiceURL\n")
		fi
	done
	IFS=$SAVEIFS

	if [[ -n $ErrorLog ]] && [[ -z $DisableErrorMessages ]]; then usage " $(echo $ErrorLog)" ; fi
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
check_ip_devices () {
	for IPDevice in $(ip a | grep ^[[:digit:]] | cut -d ":" -f2 | grep -v lo | tr -d " "); do

		# get device specs
		IPDeviceSpecs=$(ip a list $IPDevice)
		DeviceName=$(echo "$IPDeviceSpecs" | head -n1 | awk -F ": " '{printf $2}')
		DeviceIPv4=$(echo "$IPDeviceSpecs" | awk -F "inet " '{printf $2}' | cut -d "/" -f1)
		DeviceIPv6=$(echo "$IPDeviceSpecs" | awk -F "inet6 " '{printf $2}' | cut -d "/" -f1)
		DeviceMac=$(echo "$IPDeviceSpecs"  | awk -F "link/ether " '{printf $2}' | cut -d " " -f1)

		# parse values classes
		DeviceIPv4=${DeviceIPv4:-${red}none                                 ${end} }
		DeviceIPv6=${DeviceIPv6:-${red}none                                 ${end} }
		DeviceClass=$DeviceName
		if [[ -n $(grep ^en <<< $DeviceName) ]]; then DeviceClass=LAN  ; fi
		if [[ -n $(grep ^wl <<< $DeviceName) ]]; then DeviceClass=WLAN ; fi
		if [[ -n $(grep ^anbox <<< $DeviceName) ]]; then DeviceClass=AnBox ; fi

		PrintParser=network_information
			print_parser "$DeviceClass IPv4" "=>" "$DeviceIPv4" "($DeviceMac) (dev: $DeviceName)"
			print_parser "$DeviceClass IPv6" "=>" "$DeviceIPv6" "($DeviceMac) (dev: $DeviceName)"
	done
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
network_information () {


	# check for print output
	if [[ -n $1 ]]; then
		PrintNetworkSpecs=true
	fi

	# check WAN connection and set WAN value if offline
	if [[ $WANConnection == "offline" ]]; then
		WANIP="${red}none${end}                                  "
		GeoLocation="WAN offline"
		TorCheck="${red}none${end}               "
		ServiceURL="TOR offline"
	else
		# get WAN IP
		get_wan_IP

		# get geolocation
		GeoLocation=$(geoiplookup $WANIP | awk -F ": " '{print $2}')
		GeoLocation=${GeoLocation/IP Address not found/XX}

	 	#TorCheck=$(wget -q -O - https://check.torproject.org | grep "Tor" | sed -n 1p | cut -d " "  -f7 | cut -d "." -f1)
	 	TorCheck=$(lynx --dump https://check.torproject.org 2>/dev/null| sed -n 6p | cut -d . -f1)
	 	TorCheck=${TorCheck//Sorry/${red}"inactive"${end}           }
	 	TorCheck=${TorCheck//Congratulations/${grn}"active"${end}             }

	fi

 	# get gateway http interface inforamtions // timeout required for mobile wlan / tethering
	GatewayHTTPString=$(timeout 2 wget -q -O - $GatewayIP)

	# parse Fritzbox gateway information
	if [[ -n $(echo $GatewayHTTPString | grep 'FRITZ!Box') ]] ;then
		GatewayDevice=$(echo $GatewayHTTPString | tr "," "\n" | tr -d '"' | awk -F "pageTitleProduct:" '{printf $2}')
	fi


	# substitute empty vars
	GatewayDevice=${GatewayDevice:-unknown}
	GatewayIP=${GatewayIP:-${red}none${end}                }
	GatewayMAC=${GatewayMAC:-no connection    }

	if  [[ -z $DNSServerlistNmCLI ]] && [[ $GatewayIP == $DNSServerList  ]]; then
		DNSServerlistNmCLI="$GatewayMAC) (dev: $GatewayDevice"	
	fi

	# printf network specs
	if [[ -n $PrintNetworkSpecs ]]; then
		


	# print network specs
	PrintParser="network_information"
	print_parser SeperatorLine
	print_parser "WAN IP" "=>" "$WANIP" "($GeoLocation)"
	print_parser "Gateway IP" "=>" "$GatewayIP" "($GatewayMAC) (dev: $GatewayDevice)"
	print_parser "DNS Server" "=>" "$DNSServerList" "($DNSServerlistNmCLI)"

	check_ip_devices
	
	print_parser "TOR status" "=>" "$TorCheck                   " "($ServiceURL)"
	print_parser SeperatorLine

	fi
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
bandwidth_measurement () {

	# skip for offline WAN connections
	if [[ $WANConnection == "offline" ]]; then
		usage " No WAN connection. Bandwidth measurement skipped"
	fi

	if [[ $(stat -c %Y $SpeedtestTempFile 2> /dev/null) -ge $(( `date +%s` - $MaxScriptExecutionIntervalBandwidth )) ]]; then
		WaitingTime=$(( $(stat -c %Y $SpeedtestTempFile 2> /dev/null) - $(( `date +%s` - $MaxScriptExecutionIntervalBandwidth )) ))
		print_parser SeperatorLine
		PrintParser="info_line"
		print_parser " Bandwidth measurement in progress, waiting "$WaitingTime"s"
		print_parser SeperatorLine
		exit
	fi

	print_parser SeperatorLine

	# start measurement
	$(speedtest --secure > $SpeedtestTempFile) &

	# wait for finish measurement
	sleep 0.2
	while [[  $(pgrep speedtest)  ]]; do
		progressbar "| Bandwidth measurement in progress " 3 .
	done

	# parse speedtest output to output vars
	SpeedtestOutput=$(cat $SpeedtestTempFile)
	ClientISPName=$(echo "$SpeedtestOutput" | awk -F "Testing from " '{printf $2}' | sed 's/ (.*//g' | cut -c1-35)
	ClientISPIP=$(echo "$SpeedtestOutput" | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
	TargetHost=$(echo "$SpeedtestOutput"  | awk -F "Hosted by " '{printf $2}' | sed 's/\[.*$//' | cut -c1-35)
	TargetHostDistance=$(echo "$SpeedtestOutput"  | grep "Hosted by " | tr "[" "\n" | tr "]" "\n" | grep  " km")
	Ping=$(echo "$SpeedtestOutput"  | grep "Hosted by " | awk -F "km]: " '{printf  "%s ms" , substr($2, 1, 5) }')
	DownloadSpeed=$(echo "$SpeedtestOutput" | grep "Download:" | cut -d " " -f2-4)
	UploadSpeed=$(echo "$SpeedtestOutput" | grep "Upload:" | cut -d " " -f2-4)
	GeoLocation=$(geoiplookup $ClientISPIP 2> /dev/null | awk -F ": " '{print $2}' | cut -d "," -f1)
	GeoLocation=${GeoLocation/IP Address not found/XX}

	PrintParser="bandwidth_measurement"

	print_parser "Local host" "=>" "$ClientISPName" "($ClientISPIP|$GeoLocation)"
	print_parser "Remote host" "=>" "$TargetHost" "($TargetHostDistance)"

	# print parser spacing doesn`t work with colored tput prompt.
	# print_parser "Bandwidth" "=>" "down: $(tput setaf 2)$DownloadSpeed$(tput sgr0) up: $(tput setaf 1)$UploadSpeed $(tput sgr0)" " ping: $Ping    "

	print_parser "Bandwidth" "=>" "down: $(tput setaf 2)$DownloadSpeed$(tput sgr0) up: $(tput setaf 1)$UploadSpeed $(tput sgr0)" "$(printf '\033[59`%s\n' "(ping: $Ping)              ")           "  # '`'"
	print_parser SeperatorLine

	rm $SpeedtestTempFile
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
log_wan_ip () {

#TODO add option to clear log file


	# check for running wanip_log
	ActiveInstances=$(ps -aux | grep "ipspec -lw" | grep -v grep | wc -l)
	if [[ $ActiveInstances -gt 2 ]]; then
		usage " ipspec -lw already running"
	fi

	# disable errorlog and script exit
	DisableErrorMessages=true

	while true ; do

		# get $WAN IP, substitute empty var
		get_wan_IP
		WANIP=${WANIP:-${red}no connection${end}}

		# check for WANIP change / skip loop if no WAN change detected
		if [[ "$WANIP" == $(cat $WanIPLogfile 2>/dev/null | tail -n 1 | cut -d "(" -f2 | cut -d ")" -f1) ]]; then
			WANIPChange=false
			CountdownMSG=" ${grn}WANIP unchanged ${end}(${grn}$WANIP${end}) | ${yel}$(date +"%F|%H:%M:%S")${end}"
		else
			# create new logfile line 
			DateUnixtime=$(date +%s)
			DateHuman=$(date +"%F %H:%M:%S")
			LogFileNewLine=" WANIP changed ($WANIP) $DateHuman $DateUnixtime"
			CountdownMSG="   ${red}WANIP changed ${end}(${grn}$WANIP${end}) | ${yel}$(date +"%F|%H:%M:%S")${end}"

			# write new logfile line
			echo "$LogFileNewLine" >> $WanIPLogfile 
		fi

		# update vars for next loop 
		WANIPLast=$WANIPActual
		WANIPActual=$WANIP

		parse_logfile () {
			SAVEIFS=$IFS
			IFS=$(echo -en "\n\b")
			for LogFileLine in $(cat $WanIPLogfile) ; do
				UnixTimeStamp=$( awk '{print $NF}' <<<  "$LogFileLine")
				Runtime=$(date -d@$(( $(date +"%s") - $(echo "$UnixTimeStamp" | cut -d " " -f10) - 86400 )) -u +%d-%H:%M:%S |\
					sed 's/31-//' | sed 's/^00://' | sed 's/^0//' | sed 's/^0://' )  						# use 2022-09-09 19:08:29 instead 1662743309 
				printf "$LogFileLine ($Runtime ago) \n" | sed 's/'$UnixTimeStamp'//' 

			done
			IFS=$SAVEIFS	
		}	

		# print wan ip list 
		clear
		LogListOutput=$(parse_logfile) 
		printf "$LogListOutput\n\n"

		# countdown and quit request
		tput civis
		for i in `seq $WanIPLogDelay -1 0` ;do
			echo -en "\015\033[K$CountdownMSG (wait $i)"
			read -t 1 -N 1 Input
			if [[ -n $Input ]]; then
		   		printf "\n"
				tput cnorm
 				exit
		   	fi
		done
	done
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
fritzbox_reconnect () {
timeout 5 curl "http://$FritzboxIP:49000/igdupnp/control/WANIPConn1" -H "Content-Type: text/xml; charset="utf-8"" -H "SoapAction:urn:schemas-upnp-org:service:WANIPConnection:1#ForceTermination" -d "<?xml version='1.0' encoding='utf-8'?> <s:Envelope s:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/' xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'> <s:Body> <u:ForceTermination xmlns:u='urn:schemas-upnp-org:service:WANIPConnection:1' /> </s:Body> </s:Envelope>"
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
fritzbox_WAN_IP () {
timeout 5 wget -qO- "http://$FritzboxIP:49000/igdupnp/control/WANIPConn1" --header "Content-Type: text/xml; charset="utf-8"" --header "SoapAction:urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress" --post-data="<?xml version='1.0' encoding='utf-8'?> <s:Envelope s:encodingStyle='http://schemas.xmlsoap.org/soap/encoding/' xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'> <s:Body> <u:GetExternalIPAddress xmlns:u='urn:schemas-upnp-org:service:WANIPConnection:1' /> </s:Body> </s:Envelope>" | grep -Eo '\<[[:digit:]]{1,3}(\.[[:digit:]]{1,3}){3}\>'
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
fritzbox_renew_ip () {
	printf " old FritzBox WAN IP: $(fritzbox_WAN_IP) \n"
	printf " reconnecting ...\n"
	fritzbox_reconnect 2>&1> /dev/null 2>&1> /dev/null
	sleep $FritzboxPrintNewIPWanIPLogDelay
	printf " new FritzBox WAN IP: $(fritzbox_WAN_IP)\n"
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
############################################################################################################
#############################################   start script   #############################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------

 # check for valid input options
 check_input_options "$@"

#------------------------------------------------------------------------------------------------------------

 # check for monocrome output
 if [[ -z $(grep  "\-m" <<< $@) ]]; then
 	load_colorcodes
 fi

#------------------------------------------------------------------------------------------------------------

 # check connections
 # disable IP check for logging functions
 if [[ ! $1 == "-lw" ]]; then
 	 check_LAN_connection
	 check_WAN_connection
 fi

#------------------------------------------------------------------------------------------------------------

 case $1 in

	-h  )	usage " help dialog";;
	-i  )	script_information;;
	-v  )	network_information pspec;;
	-sl )	scan_lan;;
	-bm )	bandwidth_measurement;;
	-lw )	log_wan_ip;;
	-fbr)	fritzbox_renew_ip ;;
	-cfrp)	check_for_required_packages;;
	*   )	network_information pspec | grep -v none;;

 esac

#------------------------------------------------------------------------------------------------------------
############################################################################################################
##############################################   changelog   ###############################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------
# TODO add printf colorcodes instead of tput
# TODO check why space character error in print_parser occurs when using colorcodes
# TODO add new standalone option: list device status and MAC adresses even when LAN WAN is offline

# 3.2 
# avoid wan_ip_log interruption for missing WAN/LAN connections

# 3.1
# integrate wan ip log => logging wan ip
# TODO => optimize date calculation ( calculate date differece using human daten not unixtime to avoid creation of 2 seperate files 
# TODO => use printparser for log wan ip output

# 3.0
# add DNS servers output
# add DNS server infos using nmcli ( gnome )

# 2.9
# add input option check function

# 2.8
# format updated
# add ipv6 support
# add output for all and used devices
# add monocrome output

# 2.7
# LAN WAN check adde
