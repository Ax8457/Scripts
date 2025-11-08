# Powershell / Microsoft
My Powershell Scripts Microsoft-Oriented

**- EntraDefenderAlerts :**
This script gathers alerts from _Defender portal_ and prints its in your shell. Requires _PSWriteColor_ module & to create API in _ENTRA ID_ with relevant permissions granted to work.

**- ServiceSecurePathChecker :**
This script is built to find services on host and check wether there are in a secure location according _Defender_ (the secure path list is based on a _Defender portal_ security recommendation).  /!\ In order to enumerate services, administrative rights are required. An option has been added to interpret environment variables (_$env:<Name>_).

