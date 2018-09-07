#!/bin/bash

#Written by Nick Higby

#Time data
function GetTime {
    current=$(date +%T)
    timezone=$(timedatectl | grep "zone" | cut -d":" -f2)
    uptime=$(uptime -p)

    echo "Time:"
    echo ""	
    echo "Current Time: $current"
    echo "Time Zone:   $timezone"
    echo "Uptime:       $uptime"
    echo ""
}

#OS data
function GetOS {
    numericalOS=$(cat /etc/lsb-release | grep RELEASE | cut -d"=" -f2)
    typicalOS=$(cat /etc/lsb-release | grep ID | cut -d"=" -f2)
    kernel=$(uname -r)

    echo "OS:"
    echo ""
    echo "Numerical OS:   $numericalOS"
    echo "Typical OS:     $typicalOS"
    echo "Kernel Version: $kernel"
    echo ""
}

#Hardware data
function GetHardware {
    brand=$(lscpu | grep "Model name:" | cut -d":" -f2 | sed 's/ //g')
    ram=$(free -h | grep Mem | cut -d"G" -f1 | cut -d":" -f2 | sed 's/ //g')
    hdd=$(sudo fdisk -l | grep "Disk /" | cut -d"," -f1 | cut -d":" -f2)
    hddnames=$(lsblk | grep disk | cut -d" " -f1)
    filemount=$(df -h)

    echo "Hardware:"
    echo ""
    echo "CPU Brand:           $brand"
    echo "Ram Amount:          $ram GB"
    echo "HDD Amount:         $hdd"
    echo "HDD Names:           $hddnames"
    echo ""
    echo "Mounted File Systems $filemount"
    echo ""
}

#Host and Domain data
function GetHostAndDomain {
    host=$(hostname)
    domain=$(domainname)

    echo "Hostname and Domain:"
    echo ""
    echo "Hostname: $host"
    echo "Domain:   $domain"
}

#User data
function GetUsers {
    echo ""
    echo "Users:"
    for i in $(cat /etc/passwd | cut -d":" -f1); 
    do
        echo ""
	userName=$i
        uid=`awk -F: -v u=$userName '$1 == u {print $3}' /etc/passwd`
        gid=`awk -F: -v u=$userName '$1 == u {print $4}' /etc/passwd`
	
        echo "Name: $userName"
	echo "UID:  $uid"
        echo "GID:  $gid"
    done

    history=$(last)
    echo ""
    echo "Login History:"
    echo "$history"
    echo ""
}

#Boot data
function GetBoot {
    services=$(service --status-all)

    echo "Boot:"
    echo ""
    echo "Services: $services"
    echo ""
}

#Task data
function GetTask {
    tasks=$(grep -F "*" /etc/crontab)

    echo "Scheduled Tasks:"
    echo "$tasks"
    echo ""
}

#Network data
function GetNetwork {
    arp=$(arp -a)
    netconfig=$(ifconfig)
    route=$(route)
    dhcpserver=$(sudo grep -R "DHCPOFFER" /var/log/* | grep /var/log/syslog.1)
    dnsserver=$(cat /etc/resolv.conf | grep "nameserver" | awk '{print $2}')
    listen=$(netstat -lutn)
    established=$(netstat -lutna | grep ESTABLISHED)

    echo "Network:"
    echo ""
    echo "Arp Table:"
    echo "$arp"
    echo ""
    echo "Network Config:"
    echo "$netconfig"
    echo ""
    echo "Routing Table:"
    echo "$route"
    echo ""
    echo "DHCP Server: $dhcpserver"
    echo "DNS Server:  $dnsserver"
    echo ""
    echo "Listening Services:"
    echo "$listen"
    echo ""
    echo "Established Connections:"
    echo "$established"
    echo ""
}

#Network object data
function GetNetworkObjects {
    netshares=$(nmblookup -S __SAMBA__)
    printers=$(lpstat -a)

    echo "Network Objects:"
    echo ""
    echo "Network Share:"
    echo "$netshares"
    echo ""
    echo "Printers:"
    echo "$printers"
    echo ""
}

#Software data
function GetSoftware {
    soft=$(dpkg --get-selections)

    echo "Installed Software:"
    echo "$soft"
    echo ""
}

#Process data
function GetProcess {
    process=$(ps -aux)

    echo "Process List:"
    echo "$process"
    echo ""
}

#Driver data
function GetDriver {
    drivers=$(lsmod)

    echo "Driver List:"
    echo "$drivers"
    echo ""
}

#File data
function GetFiles {
    documents=$(find /home/*/Documents)
    downloads=$(find /home/*/Downloads)

    echo "Files:"
    echo ""
    echo "Documents:"
    echo "$documents"
    echo ""
    echo "Downloads:"
    echo "$downloads:"
    echo ""
}

#Additional data
function GetAdditional {
    desktop=$(find /home/*/Desktop)
    stickybit=$(sudo find / -type d -perm -1000 -exec ls -ld {} \;)
    bashHistory=$(cat ~/.bash_history)

    echo "Desktop:"
    echo "$desktop"
    echo ""
    echo "Stickybit Set:"
    echo "$stickybit"
    echo ""
    echo "History:"
    echo "$bashHistory"
    echo ""
}

#To CSV
function ToCSV {
  GetTime >> output.csv
  GetOS >> output.csv
  GetHardware >> output.csv
  GetHostAndDomain >> output.csv
  GetUsers >> output.csv
  GetBoot >> output.csv
  GetTask >> output.csv
  GetNetwork >> output.csv
  GetNetworkObjects >> output.csv
  GetSoftware >> output.csv
  GetProcess >> output.csv
  GetDriver >> output.csv
  GetFiles >> output.csv 
  GetAdditional >> output.csv

}

function Main {
  GetTime
  GetOS
  GetHardware
  GetHostAndDomain
  GetUsers
  GetBoot
  GetTask
  GetNetwork
  GetNetworkObjects
  GetSoftware
  GetProcess
  GetDriver
  GetFiles
  GetAdditional
  ToCSV
}

Main

