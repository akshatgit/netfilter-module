A kernel module that detects four different kinds of TCP scan done by nmap.
It does not filter the packet, merely logs them to kernel logs.

Four scans detected by the module:

  SYN scan
  FIN scan
  Xmas scan
  Null scan

Detection is done by reading the incoming packet's tcp header by using netfilter kernel module.
There are four scenarios that the module is interested. They represent different scans. They are:

  If only syn flag is up: Syn scan
  If only fin is up: Fin scan
  If urg, psh and fin is up: Xmas scan
  If no flag is up: Null scan

A big assumption we have taken for syn and fin scan is that we are not maintaining the state of the connection. Because of which even genuine syn and fin packets are labelled as scan packets.

Inputs to test the module:

  nmap -sS <IP>: Syn scan
  nmap -sF <IP>: Fin scan
  nmap -sX <IP>: Xmas scan
  nmap -sN <IP>: Null scan
