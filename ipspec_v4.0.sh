#!/bin/bash
#
# name        : ipspec.sh
# description : Zeigt umfassende IP-, LAN- und Netzwerkinformationen an
# author      : Speefak ( itoss@gmx.de )
# licence     : (CC) BY-NC-SA
# version     : 4.0
#
# Zweck
#   Stellt ein zentrales Werkzeug zur Prüfung des lokalen und WAN-Netzwerkzustands
#   auf Linux-Systemen bereit. Unterstützt Gerätestatus (online/offline), Multi-
#   Netzwerk-Scans mit CSV-Export, Bandbreitenmessung, Live-Traffic-Überwachung,
#   WAN-IP-Änderungsprotokollierung sowie FRITZ!Box-WAN-IP-Erneuerung.
#
# Anforderungen (Installation über -cfrp)
#   lynx curl geoip-bin netcat nmap speedtest-cli nload nethogs
#
# Hauptoptionen
#   (Standard)  Zeigt verwendete Netzwerkgeräte + WAN-Informationen
#   -v          Zeigt alle Netzwerkgeräte + WAN-Informationen
#   -d          Gerätestatus + MAC (funktioniert auch offline)
#   -sl         Einfacher LAN-Scan (lokales /24)
#   -ns         Erweiterter Multi-Netzwerk-Scan → CSV
#   -bm         Bandbreitenmessung (Speedtest)
#   -st         Live-Traffic (nload / nethogs)
#   -lw         Kontinuierliche WAN-IP-Protokollierung
#   -fbr        FRITZ!Box-WAN-IP erneuern
#   -cfrp       Benötigte Pakete prüfen / installieren
#   -m          Monochrome Ausgabe
#   -h / -i     Hilfe / Skriptinformationen
#

#------------------------------------------------------------------------------------------------------------
############################################################################################################
#######################################   define global variables   ########################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------

 RequiredPackets="lynx curl geoip-bin netcat nmap speedtest-cli nload nethogs"
 SpeedtestTempFile=/tmp/spdt.tmp
 MaxScriptExecutionIntervalBandwidth=180

 WanIPLogfile=/tmp/wanip.log
 WanIPLogDelay=10

 Codename=$(lsb_release -d | tr -d : | cut -f 2)
 Architecture=$(getconf LONG_BIT)
 LANDevice=$(ip route | grep default | awk -F "dev " '{print $2}' | cut -d " " -f1 | sort -u)
 LANIP=$(ip -br addr show $LANDevice | awk '{print $3}' | cut -d "/" -f1)
 GatewayIP=$(ip route | grep default |  sed -n 1p | cut -d " " -f3)
 GatewayMAC=$(ip neigh | grep -w $GatewayIP 2> /dev/null | head -n1 | tr " " "\n" | grep "[[:alnum:]][[:alnum:]]:")
 DNSServerList=$(cat /etc/resolv.conf |grep -i '^nameserver'|cut -d ' ' -f2 | tr "\n" " " | sed 's/ $//'| sed 's/ /,/g' )
 DNSServerlistNmCLI="$(nmcli -t --fields NAME con show --active 2>/dev/null | sed ':a;N;$!ba;s/\n/ \| /g')"

 FritzboxIP=$GatewayIP
 FritzboxPrintNewIPWanIPLogDelay=10

 Version=$(cat $(readlink -f $(which $0)) | grep "# version" | head -n1 | awk -F ":" '{print $2}' | sed 's/ //g')
 ScriptFile=$(readlink -f $(which $0))
 ScriptName=$(basename $ScriptFile)

# netscan defaults (can be overridden via -ns options)
 NETSCAN_NETWORKS_DEFAULT="192.168.1.0/24 192.168.2.0/24 192.168.5.0/24 192.168.10.0/24 192.168.20.0/24"
 NETSCAN_PORTS="1-10000"
 NETSCAN_FAST=0
 NETSCAN_OUTFILE="/tmp/netscan_$(date +%Y%m%d_%H%M%S).csv"

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
	printf " -d		list devices status + MAC (works offline)\n"
	printf " -sl		scan LAN (simple nmap of local /24)\n"
	printf " -ns		netscan (advanced multi-network scan -> CSV)\n"
	printf "		  options after -ns:\n"
	printf "		    -n \"net1 net2\"   network ranges (default: common private nets)\n"
	printf "		    -p 1-1000        port range (default: $NETSCAN_PORTS)\n"
	printf "		    -o /path/file.csv custom output file\n"
	printf "		    -f               fast mode (top 100 ports, no version detect)\n"
	printf " -bm		bandwidth measurement\n"
	printf " -st		show traffic (nload / nethogs)\n"
	printf " -lw		log wan ip\n"
	printf " -fbr		renew fritzbox WAN IP\n"
	printf " -cfrp		check for required packets\n"

	# output error message
	printf "\n"
	printf  "$red $1 \n"$end
	printf "\n"
	exit
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
check_input_options () {

	# create available options list
	InputOptionList=$(cat $ScriptFile | sed -n '/usage()/,/exit/p' | grep " -[[:alpha:]]" | awk '{print $3}' | grep "^\-")

	# check for valid input options
	# for -ns we accept additional sub-options (-n -p -o -f) so skip strict check on them
	for Option in $@ ; do
		if [[ -z $(grep -w -- "$Option" <<< "$InputOptionList") ]]; then
			# allow known netscan sub-options and their values (skip pure values)
			if [[ "$Option" =~ ^- ]]; then
				case "$Option" in
					-n|-p|-o|-f) continue ;;
					*) InvalidOptionList=$(echo $InvalidOptionList $Option) ;;
				esac
			fi
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
	printf " Location:   $(which $ScriptName)\n"
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
		printf "+-------------------------------------------------------------------------------------------------------------------+\n"
	elif [[ $PrintParser == "info_line"  ]]; then
		printf "| %-97s | \n" "$1"
	elif [[ $PrintParser == "network_information" ]]; then
		printf "| %-23s %-4s %-38s %-45s | \n" "$1" "$2" "$3" "$4"
	elif [[ $PrintParser == "bandwidth_measurement" ]]; then
		printf "| %-11s %-4s %-43s %-52s | \n" "$1" "$2" "$3" "$4"
	elif [[ $PrintParser == "wanip_log" ]]; then
		echo "| $1 |" | awk '{printf "%-1s %-5s %-9s %-16s %-3s %-10s %-21s %-4s %5s %13s %1s \n", $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13}'
	fi
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
check_for_required_packages () {

	InstalledPacketList=$(dpkg -l | grep ii | awk '{print $2}' | cut -d ":" -f1)

	for Packet in $RequiredPackets ; do
		if [[ -z $(grep -w "$Packet" <<< $InstalledPacketList) ]]; then
			MissingPackets=$(echo $MissingPackets $Packet)
		fi
	done

	# print status message / install dialog
	if [[ -n $MissingPackets ]]; then
		printf  "missing packets: $red $MissingPackets $end \n"
		read -e -p "install required packets ? (Y/N) "		 	-i "Y" 		InstallMissingPackets
		if   [[ $InstallMissingPackets == [Yy] ]]; then

			# install software packets
			sudo apt update
			sudo apt install -y $MissingPackets
			if [[ ! $? == 0 ]]; then
				exit
			fi
		else
			printf  "programm error: $red missing packets : $MissingPackets $end \n\n"
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
# netscan (integrated from netscan_v0.7)
# Scans one or more network ranges with nmap and produces a CSV
# (ip;mac;hostname;ports). Supports live status, MAC fallback via
# "ip neigh" and optional fast mode.
#-------------------------------------------------------------------------------------------------------------------------------------------------------
netscan () {
	# require nmap
	if ! command -v nmap >/dev/null 2>&1; then
		printf "${red}nmap fehlt. Installieren: apt install nmap${end}\n" >&2
		exit 1
	fi
	if ! command -v python3 >/dev/null 2>&1; then
		printf "${red}python3 fehlt (wird für XML->CSV Parsing benötigt).${end}\n" >&2
		exit 1
	fi

	# parse optional arguments that follow -ns
	# remaining args are already shifted by the caller or we use "$@"
	local NETWORKS_OPT=""
	local PORTS="$NETSCAN_PORTS"
	local FAST=$NETSCAN_FAST
	local OUTFILE="$NETSCAN_OUTFILE"

	# simple option parser for sub-options of -ns
	while [[ $# -gt 0 ]]; do
		case "$1" in
			-n)
				NETWORKS_OPT="$2"
				shift 2
				;;
			-p)
				PORTS="$2"
				shift 2
				;;
			-o)
				OUTFILE="$2"
				shift 2
				;;
			-f)
				FAST=1
				shift
				;;
			-h|--help)
				printf "\n"
				printf " netscan options (after -ns):\n"
				printf "   -n \"192.168.1.0/24 10.0.0.0/24\"   network ranges\n"
				printf "   -p 1-1000                          port range (default: $NETSCAN_PORTS)\n"
				printf "   -o /path/hosts.csv                 output file\n"
				printf "   -f                                 fast scan (top 100 ports, no -sV)\n"
				printf "\n"
				return 0
				;;
			*)
				# unknown → leave for outer check_input_options
				shift
				;;
		esac
	done

	# build network list
	IFS=' ' read -r -a NETWORKS <<< "${NETWORKS_OPT:-$NETSCAN_NETWORKS_DEFAULT}"

	if [[ $EUID -ne 0 ]]; then
		printf "${yel}Hinweis: Ohne root laufen -sS/OS-Detection nicht, nutze TCP-Connect-Scan.${end}\n" >&2
	fi

	# temporary workspace
	local TMPDIR
	TMPDIR="$(mktemp -d)"
	trap 'rm -rf "$TMPDIR"' RETURN

	# nmap base options
	local NMAP_BASE_OPTS=(--open)
	if [[ $EUID -eq 0 ]]; then
		NMAP_BASE_OPTS+=(-sS -O)
	else
		NMAP_BASE_OPTS+=(-sT)
	fi

	if [[ $FAST -eq 1 ]]; then
		NMAP_BASE_OPTS+=(--top-ports 100 -T4)
	else
		NMAP_BASE_OPTS+=(-p "$PORTS" -sV -T4)
	fi

	local XML_FILES=()
	local TOTAL_NETS=${#NETWORKS[@]}
	local i=0
	local net xml_file log_file NMAP_PID NMAP_EXIT

	# determine display string for the active port range
	if [[ $FAST -eq 1 ]]; then
		USED_PORTRANGE="top 100"
	else
		USED_PORTRANGE="$PORTS"
	fi

	for net in "${NETWORKS[@]}"; do
		i=$((i + 1))
		printf "Netzwerk $i/$TOTAL_NETS : $net | port $USED_PORTRANGE\n"

		xml_file="$TMPDIR/$(echo "$net" | tr '/.' '_').xml"
		log_file="$TMPDIR/$(echo "$net" | tr '/.' '_').log"
		XML_FILES+=("$xml_file")

		nmap "${NMAP_BASE_OPTS[@]}" -oX "$xml_file" --stats-every 1s "$net" > "$log_file" 2>&1 &
		NMAP_PID=$!

		printf '\n\n\n'   # Platz für 3 Statuszeilen reservieren
		while kill -0 "$NMAP_PID" 2>/dev/null; do
			local phase_line stats_line timing_line
			phase_line=$(grep -aE '^(Initiating|Completed|Discovered) ' "$log_file" | tail -n1 || true)
			stats_line=$(grep -a '^Stats:' "$log_file" | tail -n1 || true)
			timing_line=$(grep -a 'Timing:' "$log_file" | tail -n1 || true)
			printf '\033[3A\033[2K%s\n\033[2K%s\n\033[2K%s\n' \
				"${phase_line:-Starte Scan...}" "${stats_line:-warte auf Statistik...}" "${timing_line:-}"
			sleep 1
		done

		wait "$NMAP_PID"
		NMAP_EXIT=$?

		if [[ $NMAP_EXIT -ne 0 ]]; then
			printf "${red}nmap-Fehler bei $net (Exit $NMAP_EXIT):${end}\n" >&2
			cat "$log_file" >&2
			return "$NMAP_EXIT"
		fi
	done

	# MAC-Fallback über System-ARP/Neighbor-Tabelle
	local ARP_FILE="$TMPDIR/arp.txt"
	ip neigh show 2>/dev/null | awk '$1 ~ /^[0-9]+\./ {for(i=1;i<=NF;i++) if ($i=="lladdr") print $1, $(i+1)}' > "$ARP_FILE" || true

	# CSV-Header
	echo "ip;mac;hostname;ports" > "$OUTFILE"

	# Python XML → CSV Parser (eingebettet)
	python3 - "$OUTFILE" "$ARP_FILE" "${XML_FILES[@]}" <<'PYEOF'
import sys
import xml.etree.ElementTree as ET

out_file = sys.argv[1]
arp_file = sys.argv[2]
xml_files = sys.argv[3:]

arp_map = {}
with open(arp_file) as f:
    for line in f:
        parts = line.split()
        if len(parts) == 2:
            arp_map[parts[0]] = parts[1]

rows = []
for xml_file in xml_files:
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"XML-Parse-Fehler bei {xml_file}: {e}", file=sys.stderr)
        continue

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = mac = hostname = ""
        for addr in host.findall("address"):
            t = addr.get("addrtype")
            if t == "ipv4" or t == "ipv6":
                ip = addr.get("addr")
            elif t == "mac":
                mac = addr.get("addr")

        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")

        ports = []
        for p in host.findall("ports/port"):
            state = p.find("state")
            if state is not None and state.get("state") == "open":
                portid = p.get("portid")
                proto = p.get("protocol")
                svc = p.find("service")
                svcname = svc.get("name") if svc is not None else ""
                ports.append(f"{portid}/{proto}:{svcname}")

        if not mac:
            mac = arp_map.get(ip, "")

        rows.append((ip, mac, hostname, " ".join(ports)))

with open(out_file, "a") as f:
    for ip, mac, hostname, ports in rows:
        f.write(f"{ip};{mac};{hostname};{ports}\n")

print(f"{len(rows)} Hosts gefunden.")
PYEOF

	printf "Ergebnis: $OUTFILE\n"
	if command -v column >/dev/null 2>&1; then
		column -t -s';' "$OUTFILE"
	else
		cat "$OUTFILE"
	fi
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
show_traffic () {
	# show live traffic using nload (interface overview) and/or nethogs (per process)
	# packages are part of RequiredPackets → install via -cfrp if missing
	#
	# nethogs liegt oft unter /usr/sbin und ist damit für normale User
	# nicht in $PATH → command -v schlägt fehl. Deshalb zusätzlich feste Pfade prüfen.

	local NloadBin NethogsBin p

	NloadBin=$(command -v nload 2>/dev/null || true)
	if [[ -z $NloadBin ]]; then
		for p in /usr/bin/nload /usr/sbin/nload /bin/nload; do
			[[ -x $p ]] && NloadBin=$p && break
		done
	fi

	NethogsBin=$(command -v nethogs 2>/dev/null || true)
	if [[ -z $NethogsBin ]]; then
		for p in /usr/sbin/nethogs /usr/bin/nethogs /sbin/nethogs; do
			[[ -x $p ]] && NethogsBin=$p && break
		done
	fi

	if [[ -z $NloadBin || -z $NethogsBin ]]; then
		printf "${red}nload und/oder nethogs fehlen. Bitte zuerst installieren:${end}\n"
		printf "  $(basename $0) -cfrp\n"
		return 1
	fi

	printf "\n"
	printf " Interface : $LANDevice  ($LANIP)\n"
	printf " Gateway   : $GatewayIP\n"
	printf "\n"
	printf "  1) nload    – Traffic pro Interface (Übersicht)\n"
	printf "  2) nethogs  – Traffic pro Prozess\n"
	printf "  3) beide    – nload zuerst, danach nethogs\n"
	printf "\n"
	read -e -p "Auswahl [1]: " -i "1" TrafficChoice

	case "$TrafficChoice" in
		2)
			printf "\n${cyn}nethogs auf $LANDevice (Ctrl+C zum Beenden)${end}\n\n"
			if [[ $EUID -eq 0 ]]; then
				"$NethogsBin" "$LANDevice"
			else
				sudo "$NethogsBin" "$LANDevice"
			fi
			;;
		3)
			printf "\n${cyn}nload auf $LANDevice (Ctrl+C → weiter zu nethogs)${end}\n\n"
			"$NloadBin" -u m "$LANDevice"
			printf "\n${cyn}nethogs auf $LANDevice (Ctrl+C zum Beenden)${end}\n\n"
			if [[ $EUID -eq 0 ]]; then
				"$NethogsBin" "$LANDevice"
			else
				sudo "$NethogsBin" "$LANDevice"
			fi
			;;
		*)
			printf "\n${cyn}nload auf $LANDevice (Ctrl+C zum Beenden)${end}\n\n"
			"$NloadBin" -u m "$LANDevice"
			;;
	esac
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
check_LAN_connection () {

	# check LAN connection – if offline, show device status instead of aborting
	if [[ -z $(hostname -I) ]]; then
		device_status
		exit 0
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

	# get geolocation
	GeoLocation=$(geoiplookup $WANIP | awk -F ": " '{print $2}')
	GeoLocation=${GeoLocation/IP Address not found/XX}

	if [[ -n $ErrorLog ]] && [[ -z $DisableErrorMessages ]]; then usage " $(echo $ErrorLog)" ; fi
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
check_ip_devices () {

	for IPDevice in $(ip a | grep ^[[:digit:]] | cut -d ":" -f2 | grep -v lo | tr -d " "); do

		# get device specs
		IPDeviceSpecs=$(ip a list $IPDevice 2>/dev/null)
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
		if [[ -n $(grep ^vmbr <<< $DeviceName) ]]; then DeviceClass="Proxmox ($DeviceName)" ; fi

		PrintParser=network_information
			print_parser "$DeviceClass IPv4" "=>" "$DeviceIPv4" "($DeviceMac) (dev: $DeviceName)"
			print_parser "$DeviceClass IPv6" "=>" "$DeviceIPv6" "($DeviceMac) (dev: $DeviceName)"
	done
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
device_status () {
	# list all network devices with MAC + IPs in the same format as default/-v
	# works without LAN/WAN connectivity (uses only local iproute2 data)
	# when no address is present → "not connected"

	PrintParser="network_information"
	print_parser SeperatorLine

	for IPDevice in $(ip a | grep ^[[:digit:]] | cut -d ":" -f2 | grep -v lo | tr -d " "); do

		IPDeviceSpecs=$(ip a list "$IPDevice" 2>/dev/null)
		DeviceName=$(echo "$IPDeviceSpecs" | head -n1 | awk -F ": " '{printf $2}')
		DeviceIPv4=$(echo "$IPDeviceSpecs" | awk -F "inet " '{printf $2}' | cut -d "/" -f1)
		DeviceIPv6=$(echo "$IPDeviceSpecs" | awk -F "inet6 " '{printf $2}' | cut -d "/" -f1)
		DeviceMac=$(echo "$IPDeviceSpecs"  | awk -F "link/ether " '{printf $2}' | cut -d " " -f1)

		# no address → not connected (keep column width similar to "none" lines)
		DeviceIPv4=${DeviceIPv4:-${red}not connected                         ${end}}
		DeviceIPv6=${DeviceIPv6:-${red}not connected                         ${end}}
		DeviceMac=${DeviceMac:-n/a}

		DeviceClass=$DeviceName
		if [[ -n $(grep ^en <<< $DeviceName) ]]; then DeviceClass=LAN  ; fi
		if [[ -n $(grep ^wl <<< $DeviceName) ]]; then DeviceClass=WLAN ; fi
		if [[ -n $(grep ^vmbr <<< $DeviceName) ]]; then DeviceClass="Proxmox ($DeviceName)" ; fi
		if [[ -n $(grep ^br <<< $DeviceName) ]]; then DeviceClass="Bridge ($DeviceName)" ; fi
		if [[ -n $(grep ^docker <<< $DeviceName) ]]; then DeviceClass="Docker ($DeviceName)" ; fi
		if [[ -n $(grep ^veth <<< $DeviceName) ]]; then DeviceClass="veth ($DeviceName)" ; fi

		print_parser "$DeviceClass IPv4" "=>" "$DeviceIPv4" "($DeviceMac) (dev: $DeviceName)"
		print_parser "$DeviceClass IPv6" "=>" "$DeviceIPv6" "($DeviceMac) (dev: $DeviceName)"
	done

	print_parser SeperatorLine
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

		#TorCheck=$(wget -q -O - https://check.torproject.org | grep "Tor" | sed -n 1p | cut -d " "  -f7 | cut -d "." -f1)
	 	TorCheck=$(lynx --dump https://check.torproject.org 2>/dev/null| sed -n 6p | cut -d . -f1)
	 	TorCheck=${TorCheck//Sorry/${red}"inactive"${end}           }
	 	TorCheck=${TorCheck//Congratulations/${grn}"active"${end}             }

	fi

 	# get gateway http interface inforamtions // timeout required for mobile wlan / tethering
	GatewayHTTPString=$(timeout 2 wget -qO- $GatewayIP 2>/dev/null)

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

	# print speedtest results
	PrintParser="bandwidth_measurement"

	print_parser "Local host" "=>" "$ClientISPName" "($ClientISPIP|$GeoLocation)"
	print_parser "Remote host" "=>" "$TargetHost" "($TargetHostDistance)"

	# print_parser "Bandwidth" "=>" "down:$grn $DownloadSpeed $end up:$red $UploadSpeed $end" " (ping:$yel ${Ping} $end)" 	# printparser error
	print_parser "Bandwidth" "=>" "down:$grn $DownloadSpeed $end up:$red $UploadSpeed $end" "$(printf '\033[59`%s\n' "     (ping:$yel ${Ping}$end)             ")                       "  # '`'"
	print_parser SeperatorLine

	rm $SpeedtestTempFile
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
log_wan_ip () {

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
		GeoLocation=$( cut -d "," -f1 <<< $GeoLocation)

		# check for WANIP change / skip loop if no WAN change detected
		if [[ "$WANIP" == $(cat $WanIPLogfile 2>/dev/null | tail -n 1 | cut -d " " -f3) ]]; then
			WANIPChange=false
			CountdownMSG=" ${grn}WANIP unchanged ${end}(${grn}$WANIP${end}|${grn}$GeoLocation${end}) ${yel}$(date +"%F|%H:%M:%S")${end}"
		else
			# create new logfile line
			DateUnixtime=$(date +%s)
			DateHuman=$(date +"%F %H:%M:%S")
			LogFileNewLine="WANIP changed $WANIP $GeoLocation $DateHuman $DateUnixtime"
			CountdownMSG="   ${red}WANIP changed ${end}(${grn}$WANIP${end}|${grn}$GeoLocation${end}) ${yel}$(date +"%F|%H:%M:%S")${end}"

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
					sed 's/31-//' | sed 's/^00://' | sed 's/^0//' | sed 's/^0://' )  			# use 2022-09-09 19:08:29 instead 1662743309
				printf "$LogFileLine time elapsed: $Runtime \n" | sed 's/'$UnixTimeStamp'//'

			done
			IFS=$SAVEIFS
		}

		# print and format logfile
		clear
		PrintParser="wanip_log"
		print_parser SeperatorLine
		SAVEIFS=$IFS
		IFS=$(echo -en "\n\b")
		for i in $(parse_logfile) ; do
			IFS=$SAVEIFS
			print_parser "$i"
		done
		IFS=$SAVEIFS
		printf "\n"

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
	fritzbox_reconnect 2>&1> /dev/null 2>&1> /dev/null
	progressbar " reconnecting" "$FritzboxPrintNewIPWanIPLogDelay" "."
	printf " new FritzBox WAN IP: $(fritzbox_WAN_IP)\n"
}
#-------------------------------------------------------------------------------------------------------------------------------------------------------
############################################################################################################
#############################################   start script   #############################################
############################################################################################################
#------------------------------------------------------------------------------------------------------------

 # check for monocrome output (-m may appear in any position)
 if [[ -z $(grep -w "\-m" <<< $@) ]]; then
 	load_colorcodes
 fi

#------------------------------------------------------------------------------------------------------------

 # check for valid input options
 check_input_options "$@"

#------------------------------------------------------------------------------------------------------------

 # determine primary action (first non -m option, so -m can be anywhere)
 Action=""
 for arg in "$@"; do
 	case "$arg" in
 		-m) continue ;;
 		-h|-i|-v|-d|-sl|-ns|-bm|-st|-lw|-fbr|-cfrp)
 			Action="$arg"
 			break
 			;;
 	esac
 done

 # check connections
 # disable IP check for logging / offline device list
 if [[ "$Action" != "-lw" && "$Action" != "-d" ]]; then
 	 check_LAN_connection
	 check_WAN_connection
 fi

#------------------------------------------------------------------------------------------------------------

 case "$Action" in

	-h  )	usage " help dialog";;
	-i  )	script_information;;
	-v  )	network_information pspec;;
	-d  )	device_status;;
	-sl )	scan_lan;;
	-ns )
		# pass all args after -ns (and ignore a leading -m)
		shift_args=()
		seen_ns=0
		for arg in "$@"; do
			if [[ $seen_ns -eq 1 ]]; then
				shift_args+=("$arg")
			elif [[ "$arg" == "-ns" ]]; then
				seen_ns=1
			fi
		done
		netscan "${shift_args[@]}"
		;;
	-bm )	bandwidth_measurement;;
	-st )	show_traffic;;
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


# 3.9 => netscan (v0.7) as function integrated (-ns)
#        multi-network sequential nmap scan, live status, MAC fallback via ip neigh,
#        CSV output (ip;mac;hostname;ports), sub-options -n -p -o -f
#        option order independent (-m -v and -v -m both work), default ports 1-10000
#        scan status shows used port range
#        -st show traffic (nload / nethogs) implemented (was TODO in 3.8)
#        -d  device status + MAC (works offline), netscan CSV → /tmp/
# 3.8 => add (s)how (t)raffic option using nethogs and nload  → erledigt in 3.9
# 3.7 => printparser function updated / 30 DNSServerlistNmCLI syntax updated
# 3.6 => netcat packet added
# 3.5 => substitue tput to colorcodes
# 3.4 => change logfile syntax / waniplog printparser putput added
# 3.3 => geolocation for wan iplog added
# 3.2 => avoid wan_ip_log interruption for missing WAN/LAN connections
# 3.1 => integrate wan ip log => logging wan ip
# 3.0 => add DNS servers output / add DNS server infos using nmcli ( gnome )
# 2.9 => add input option check function
# 2.8 => format updated / add ipv6 support / add output for all and used devices / add monocrome output
# 2.7 => LAN WAN check added
