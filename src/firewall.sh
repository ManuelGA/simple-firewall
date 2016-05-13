#!/bin/bash

# File : firewall.sh
# Author : Manuel Gonzales
# Functions : error_exit
# Date : Jan 25, 2016
# Script to add a job to crontab for sending emails at the desired time(s)

#echo error and exit the script
function error_exit
{
	echo "$1" 1>&2
	exit 1
}

#set rules for that port
#arg1: protocol, arg2: port number, arg3: action
function default_traffic
{
	iptables -A INPUT -p $1 --dport $2 -j $3
	iptables -A INPUT -p $1 --sport $2 -j $3
	iptables -A OUTPUT -p $1 --sport $2 -j $3
	iptables -A OUTPUT -p $1 --dport $2 -j $3
	#iptables -A FORWARD -p $1 --dport $2 -j $3
	#iptables -A FORWARD -p $1 --sport $2 -j $3
}

#set rules for specific chain
#arg1: chain, arg2: protocol, arg3: port number, arg4: action
function defined_traffic
{
	iptables -A $1 -p $2 --dport $3 -j $4
	iptables -A $1 -p $2 --sport $3 -j $4
}

#set policy for all chains
#arg1: policy
function set_policy
{
	iptables -P INPUT $1
	iptables -P OUTPUT $1
	iptables -P FORWARD $1
}

#forward traffic to a new chain
#arg1; new chain
function forward_chain
{
	iptables -A OUTPUT -j $1
	iptables -A INPUT -j $1
	iptables -A FORWARD -j $1
}

#clear tables
function flush_tables
{
	iptables -F
	iptables -X
}

#variables for flagging
tcp=true
udp=false

if [[ $1 != "set" && $1 != "reset" ]] ; then
	error_exit " Correct Usage: firewall [set|reset]"
fi

#SET UP VARIABLES
policy="DROP"

reserved_port=0
maximum_port=1024
highest_port=65535

ssh_port="ssh"
ssh_rule="ACCEPT"

www_port="http,https"
www_rule="ACCEPT"

#http_rule="ACCEPT"
#reserved_rule="DROP"

dns_rule="ACCEPT"
#dhcp_rule="ACCEPT"
#syn_rules="DROP"

ssh_chain="ssh_traffic"
www_chain="www_traffic"
all_chain="all_traffic"


if [[ $1 == "reset" ]] ; then
	flush_tables
	set_policy "ACCEPT"
	iptables -Z
else

	iptables -N $ssh_chain
	iptables -N $www_chain
	iptables -N $all_chain

	set_policy $policy

	iptables -A INPUT -p udp --sport domain -j $dns_rule
	iptables -A OUTPUT -p udp --dport domain -j $dns_rule
	iptables  -A INPUT -p udp --dport 67:68 --sport 67:68 -j ACCEPT
	iptables  -A OUTPUT -p udp --dport 67:68 --sport 67:68 -j ACCEPT

	if $tcp ; then		

		default_traffic "tcp" $ssh_port $ssh_chain
		defined_traffic $ssh_chain "tcp" $ssh_port $ssh_rule
	#	default_traffic "tcp" $reserved_port $reserved_rule

		iptables -A INPUT -p tcp -m multiport --dport $www_port -m multiport --sport $maximum_port:$highest_port -j $www_chain
		iptables -A INPUT -p tcp -m multiport --sport $www_port -j $www_chain
		iptables -A OUTPUT -p tcp -m multiport --dport $www_port -j $www_chain
		iptables -A OUTPUT -p tcp -m multiport --sport $www_port -j $www_chain
		
		iptables -A $www_chain -p tcp -m multiport --dport $www_port -j $www_rule
		iptables -A $www_chain -p tcp -m multiport --sport $www_port -j $www_rule

	#	iptables -A $all_chain -p "tcp" --tcp-flags ALL SYN -j $syn_rules
	#	iptables -A $all_chain -p "tcp" --tcp-flags ALL NONE -j $syn_rules
	#	iptables -A $all_chain -p "tcp" --tcp-flags ALL ALL -j $syn_rules

	fi

	if $udp ; then

		default_traffic "udp" $ssh_port $ssh_chain
		defined_traffic $ssh_chain "udp" $ssh_port $ssh_rule
	#	default_traffic "udp" $reserved_port $reserved_rule

		iptables -A INPUT -p udp -m multiport --dport $www_port -m multiport --sport $maximum_port:$highest_port -j $www_chain
		iptables -A INPUT -p udp -m multiport --sport $www_port -j $www_chain
		iptables -A OUTPUT -p udp -m multiport --dport $www_port -j $www_chain
		iptables -A OUTPUT -p udp -m multiport --sport $www_port -j $www_chain
		
		iptables -A $www_chain -p udp -m multiport --dport $www_port -j $www_rule
		iptables -A $www_chain -p udp -m multiport --sport $www_port -j $www_rule

	fi

	forward_chain $all_chain
	iptables -A $all_chain -j $policy

fi
