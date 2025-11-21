#!/bin/bash
touch log.txt
c=$(pip list | awk '{print $1}' | wc -l)
c1=$((c - 2))
echo "[+] $c1 python packages found"
c2=0
while [ $c2 -le 50 ]
do
  echo -ne "-"
  c2=$((c2 + 1))
done 
echo  ""
##set List to found packet
List=$(pip list | awk -F' ' '{print $1}') 
set -- $List

counter=3
while [ $counter -le $# ]
do
  echo "Candidate: ${!counter}" # indexing packets in list
  
  ## print dash line
  c2=0
  while [ $c2 -le 50 ]
  do
   echo -ne "-"
   c2=$((c2 + 1))
  done 	
  echo "" ## add carriage return
  
  ## pip packet informations
  pip show "${!counter}"
  
  ## print dash line
  c2=0
  while [ $c2 -le 50 ]
  do
   echo -ne "-"
   c2=$((c2 + 1))
  done 
  echo ""
  
  ## Ask for delete packet
  read -p "Delete packet ? [yes/No]: " answer
  if [[ "$answer" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo "[X] Uninstalling ${!counter}..."
    sudo pip uninstall -y "${!counter}" >> ./log.txt 2>&1
    sudo pip3 uninstall -y "${!counter}" >> ./log.txt 2>&1
    sleep 0.1
  else
  ## Skipp if no answer 
    echo "[SKIP] Skipping ${!counter}"
    sleep 0.1
  fi
  
  ## skip to next and overwrite stdout by erasing lines used 
  read -p "[ENTER] To Next"
  counter=$((counter + 1))
  printf '\033[17A\033[J' 2>/dev/null || clear
  
  ## print dash lane  
  c2=0
  while [ $c2 -le 50 ]
  do
   echo -ne "-"
   c2=$((c2 + 1))
  done 
  echo ""
done

echo "[OK] Done"

