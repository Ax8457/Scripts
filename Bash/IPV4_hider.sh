#!/bin/bash
echo "=========================================="
echo "=============== IPV4 HIDER ==============="
echo "=========================================="

if [ $# -eq 0 ]; then
	echo "Usage : ./IPV4_Hider.ps1 <file_to_parse>."
	exit 1
fi

if [ ! -f "$1" ]; then 
	echo "File doesn't exist."
	exit 1
fi 

file=$1
start=$(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$file" | awk 'NR==1')

if [ -z "$start" ]; then
	echo "No IPV4 address in this file."
	exit 1
fi

cp "$1" "$1.bak"
incr=0
while true 
do
	ipAddress=$(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$file" | awk 'NR==1')
	if [ -n "$ipAddress" ]; then 
		echo "IP address found : $ipAddress"
		read -p "IP address will be replace by: " motif
		sed -i "s/$ipAddress/$motif/" "$file"
		echo "IP address $ipAddress replaced by $motif"
		echo "-----------------------------------------------"
		((incr++))
		sleep 0.5

	else
		echo "All IPV4 Addresses had been replaced. [$incr]"
		echo "Backup file had been saved at $file.bak ."
		exit 1 
	fi

done
