#!/bin/bash
#
# Wrapper for common ipset commands on the sipban set. It does not check the
# whitelist. The set only blocks traffic while this iptables rule exists
# (sipban.pl inserts it at startup):
#
# /sbin/iptables -t filter -I INPUT -i eno1 -m set --match-set sipban src -j DROP

# Name of the ipset set
IPSET_NAME="sipban"
SAVE_FILE="/etc/sipban.dump"
TIMEOUT=604800
IPv4="^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(\/(3[0-2]|[1-2][0-9]|[0-9]))?$"

case $1 in
    # Create the set
    -c)
        /usr/sbin/ipset create $IPSET_NAME hash:net hashsize 4096 timeout $TIMEOUT > /dev/null
    ;;
    # Flush (empty) the set
    -f)
        /usr/sbin/ipset flush $IPSET_NAME
    ;;
    # Destroy the set
    -k)
        /usr/sbin/ipset destroy $IPSET_NAME
    ;;
    # Show the header of the set
    -i)
        /usr/sbin/ipset list $IPSET_NAME -t
    ;;
    # Add an IP address or class to the set
    -a)
        if [[ $2  =~ $IPv4 ]]; then
            /usr/sbin/ipset -q add $IPSET_NAME $2 > /dev/null
        else
            echo 'Invalid IP address'
        fi
    ;;
    # Delete an IP address from the set
    -d)
        if [[ $2  =~ $IPv4 ]]; then
            /usr/sbin/ipset del $IPSET_NAME $2
        else
            echo 'Invalid IP address'
        fi
    ;;
    # List the members, or test whether an IP address is in the set
    -l)
        if  [[ $2  =~ $IPv4 ]]; then
            /usr/sbin/ipset test $IPSET_NAME $2
        else
            /usr/sbin/ipset list $IPSET_NAME
        fi
    ;;
    # Save the set to the dump file
    -s)
        /usr/sbin/ipset save $IPSET_NAME > $SAVE_FILE
    ;;
    # Restore the set from the dump file
    -r)
        /usr/sbin/ipset restore -! < $SAVE_FILE
    ;;
    # Add the IP addresses listed in a file
    -u)
        if test -f $2; then
            while IFS= read -r line;
                do
                    if [[ $line  =~ $IPv4 ]]; then
                        /usr/sbin/ipset -q add $IPSET_NAME $line > /dev/null
                    else
                        echo 'Invalid IP address'
                    fi
                done < $2
        fi
    ;;
    # Without a valid option, show the usage
    *)
        echo "Usage: $0 [options]"
        echo 'options:'
        echo '    -c (create the sipban set)'
        echo '    -f (delete all the members of the set)'
        echo '    -k (destroy the sipban set)'
        echo '    -i (show information about the set)'
        echo
        echo '    -a [ip] or [ip/class] (add an IP address or class to the set)'
        echo '    -d [ip] (delete an IP address from the set)'
        echo '    -l {ip} (list the members, or test an IP address)'
        echo
        echo '    -s (save the set to the dump file)'
        echo '    -r (restore the set from the dump file)'
        echo '    -u [file] (add the IP addresses listed in a file)'
        exit 1
    ;;
esac
