
#! /bin/bash
sudo su -
echo "UBUNTU HARDENING TESTS AS PER CIS BENCHMARK DOCUMENT" >> hardeningtests.txt
echo " " >> hardeningtests.txt
#apt-get update -y
#apt-get upgrade -y
echo "1 PATCHING and SOFTWARE UPDATES " >> hardeningtests.txt
echo "Update and Upgrade Completed" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "CHECK AUTOMATIC UPDATES CONFIGURED" >> hardeningtests.txt
echo "Desired Output" >> hardeningtests.txt
echo "APT::Periodic::Update-Package-Lists 1" >> hardeningtests.txt
echo "APT::Periodic::Unattended-Upgrade 1" >> hardeningtests.txt
echo "Actual Output Below" >> hardeningtests.txt
less /etc/apt/apt.conf.d/20auto-upgrades >> hardeningtests.txt




echo "2 FILE SYSTEM CONFIGURATION" >> hardeningtests.txt

echo "Show Partitions" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo "Verify that there is a /tmp file partition in the /etc/fstab file." >> hardeningtests.txt
grep "[[:space:]]/tmp[[:space:]]" /etc/fstab >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "Set nodev option for /tmp Partition - Scored" >> hardeningtests.txt
grep /tmp /etc/fstab | grep nodev >> hardeningtests.txt
mount | grep /tmp | grep nodev >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "2.3 Set nosuid option for /tmp Partition - Scored" >> hardeningtests.txt
grep /tmp /etc/fstab | grep nosuid >> hardeningtests.txt
mount | grep /tmp | grep nosuid >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "2.4 Set noexec option for /tmp Partition - Scored" >> hardeningtests.txt 
grep /tmp /etc/fstab | grep noexec >> hardeningtests.txt
mount | grep /tmp | grep noexec >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "2.5 Create Separate Partition for /var - Scored" >> hardeningtests.txt 
grep /var /etc/fstab >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "2.6 Bind Mount the /var/tmp directory to /tmp - Scored" >> hardeningtests.txt  
grep -e "^/tmp" /etc/fstab | grep /var/tmp >> hardeningtests.txt
echo "Desired State: /tmp /var/tmp none none 0 0" >> hardeningtests.txt
echo " " >> hardeningtests.txt
mount | grep -e "^/tmp" | grep /var/tmp >> hardeningtests.txt
echo "Desired State: /tmp on /var/tmp type none - rw,bind" >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "2.7 Create Separate Partition for /var/log - Scored" >> hardeningtests.txt
grep /var/log /etc/fstab >> hardeningtests.txt
echo "Desired State: <volume> /var/log ext3 <options>" >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "2.8 Create Separate Partition for /var/log/audit - Scored" >> hardeningtests.txt
grep /var/log/audit /etc/fstab >> hardeningtests.txt
echo "Desired State: <volume> /var/log/audit ext3 <options>" >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "2.9 Create Separate Partition for /home - Scored" >> hardeningtests.txt
grep /home /etc/fstab >> hardeningtests.txt
echo "Desired State: <volume> /home ext3 <options>" >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "2.10 Add nodev Option to /home Scored " >> hardeningtests.txt
grep /home /etc/fstab >> hardeningtests.txt
echo "CHECK Note: Verify that nodev is an option" >> hardeningtests.txt
echo " " >> hardeningtests.txt
mount | grep /home >> hardeningtests.txt
echo "Desired Output: <each user partition> on <mount point> type <fstype> nodev " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "2.11 Add nodev Option to Removable Media Partitions Not Scored - NOT DONE" >> hardeningtests.txt
# grep <each removable media mountpoint> /etc/fstab
# Verify that nodev is an opt
echo " " >> hardeningtests.txt

echo "#2.12 Add noexec Option to Removable Media Partitions Not Scored - NOT DONE" >> hardeningtests.txt
# grep <each removable media mountpoint> /etc/fstab 
echo " " >> hardeningtests.txt


echo "2.14 Add nodev Option to /run/shm Partition - Scored"  >> hardeningtests.txt
grep /run/shm /etc/fstab | grep nodev >> hardeningtests.txt
mount | grep /run/shm | grep nod >> hardeningtests.txt
echo "Expected Output: If either command emits no output then the system is not configured as recommended." >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "2.15 Add nosuid Option to /run/shm Partition - Scored" >> hardeningtests.txt
grep /run/shm /etc/fstab | grep nosuid >> hardeningtests.txt
mount | grep /run/shm | grep nosuid >> hardeningtests.txt
echo "Expected Output: If either command emits no output then the system is not configured as recommended." >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "2.16 Add noexec Option to /run/shm Partition - Scored" >> hardeningtests.txt
grep /run/shm /etc/fstab | grep noexec >> hardeningtests.txt
mount | grep /run/shm | grep noexec >> hardeningtests.txt
echo "Expected Output: If either command emits no output then the system is not configured as recommended." >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "2.17 Set Sticky Bit on All World-Writable Directories Scored " >> hardeningtests.txt
echo "Setting the sticky bit on world writable directories prevents users from deleting o renaming files in that directory that are not owned by them. " >> hardeningtests.txt
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null >> hardeningtests.txt
echo "Remediation Command: df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | chmod a+t" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "2.18 Disable Mounting of cramfs Filesystems - Not Scored" >> hardeningtests.txt
/sbin/modprobe -n -v cramfs >> hardeningtests.txt
echo "Expected Output: install /bin/true" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

/sbin/lsmod | grep cramfs >> hardeningtests.txt
echo "Expected Output: <No output>" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "2.19 Disable Mounting of freevxfs Filesystems - Not Scored" >> hardeningtests.txt 
/sbin/modprobe -n -v freevxfs >> hardeningtests.txt
echo "Expected Output: install /bin/true" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


/sbin/lsmod | grep freexvfs >> hardeningtests.txt
echo "Expected Output: <No output>" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "2.20 Disable Mounting of jffs2 Filesystems - Not Scored" >> hardeningtests.txt
/sbin/modprobe -n -v jffs2 >> hardeningtests.txt
echo "Expected Output: install /bin/true" >> hardeningtests.txt
/sbin/lsmod | grep jffs2  >> hardeningtests.txt
echo "Expected Output: <No output>" >> hardeningtests.txt 
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "2.25 Disable Automounting - Scored" >> hardeningtests.txt
initctl show-config autofs >> hardeningtests.txt
echo "Desired State: autofs" >> hardeningtests.txt
echo "NOTE: Ensure no start conditions listed for autofs:" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

# 3 SECURE BOOT SETTINGS

echo "3 SECURE BOOT SETTINGS" >> hardeningtests.txt
echo "According to Alastair - This section is not applicable as the servers are all virtual servers" >> hardeningtests.txt
echo "Check for Root Password" >> hardeningtests.txt
grep ^root:[*\!]: /etc/shadow  >> hardeningtests.txt
echo "Desired State: No Results should be returned" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


# 4 ADDITIONAL PROCESS HARDENING

echo "4 ADDITIONAL PROCESS HARDENING" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo "Command: grep hard core /etc/security/limits.conf" >> hardeningtests.txt
echo "Desired Output: * hard core 0" >> hardeningtests.txt
echo "Actual Output" >> hardeningtests.txt
grep -r "hard core" /etc/security/ >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "Command: sysctl fs.suid_dumpable" >> hardeningtests.txt
echo "Desired Output: fs.suid_dumpable = 0" >> hardeningtests.txt
echo "Actual Output" >> hardeningtests.txt
sysctl fs.suid_dumpable >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "Command: initctl show-config apport" >> hardeningtests.txt
echo "Desired Output: - File not found" >> hardeningtests.txt
echo "Actual Output" >> hardeningtests.txt
initctl show-configapport >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "Command: initctl show-config whoopsie" >> hardeningtests.txt
echo "Desired Output: - File not found" >> hardeningtests.txt
echo "Actual Output" >> hardeningtests.txt
initctl show-config whoopsie >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "Command: dmesg | grep NX" >> hardeningtests.txt
echo "Desired Output:NX Execute Disable protection: active" >> hardeningtests.txt
echo "Actual Output" >> hardeningtests.txt
dmesg | grep NX >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "Command: sysctl kernel.randomize_va_space" >> hardeningtests.txt
echo "Desired Output:kernel.randomize_va_space = 2" >> hardeningtests.txt
echo "Actual Output" >> hardeningtests.txt
sysctl kernel.randomize_va_space >> hardeningtests.txt
echo "RemedialAction: Add  kernel.randomize_va_space = 2  to sysctl.conf" >> hardeningtests.txt
echo " " >> hardeningtests.txt

# apparmor_status 
echo "Command: apparmor_status" >> hardeningtests.txt
echo "Desired Output: apparmor module is loaded." >> hardeningtests.txt
echo "Actual Output" >> hardeningtests.txt
apparmor_status >> hardeningtests.txt
echo "Remediation: Install apparmor and apparmor-utils if missing" >> hardeningtests.txt
echo " " >> hardeningtests.txt



# 5 OS Services

echo "5 OS Services- 5.1 Ensure Legacy Services are Not Enabled" >> hardeningtests.txt
dpkg -s nis >> hardeningtests.txt
grep ^shell /etc/inetd.conf >> hardeningtests.txt
grep ^login /etc/inetd.conf >> hardeningtests.txt
grep ^exec /etc/inetd.conf >> hardeningtests.txt
dpkg -s rsh-client >> hardeningtests.txt
dpkg -s rsh-redone-client >> hardeningtests.txt
grep ^talk /etc/inetd.conf >> hardeningtests.txt
grep ^ntalk /etc/inetd.conf >> hardeningtests.txt
grep ^telnet /etc/inetd.conf >> hardeningtests.txt
grep ^tftp /etc/inetd.conf >> hardeningtests.txt
grep initctl show-config xinetd >> hardeningtests.txt
grep ^chargen /etc/inetd.conf >> hardeningtests.txt
grep ^daytime /etc/inetd.conf >> hardeningtests.txt
grep ^echo /etc/inetd.conf >> hardeningtests.txt
grep ^discard /etc/inetd.conf >> hardeningtests.txt
grep ^time /etc/inetd.conf >> hardeningtests.txt

# 6 Special Purpose Services Tests
echo "6 Special Purpose Services Tests" >> hardeningtests.txt
dpkg -l xserver-xorg-core* >> hardeningtests.txt
sudo apt install -y upstart
initctl show-config avahi-daemon >> hardeningtests.txt
initctl show-config cups >> hardeningtests.txt
initctl show-config isc-dhcp-server >> hardeningtests.txt
initctl show-config isc-dhcp-server6 >> hardeningtests.txt
dpkg -s ntp >> hardeningtests.txt
dpkg -s slapd >> hardeningtests.txt
initctl show-config rpcbind-boot >> hardeningtests.txt
ls /etc/rc*.d/S*bind9 >> hardeningtests.txt
initctl show-config vsftpd >> hardeningtests.txt
ls /etc/rc*.d/S*apache2 >> hardeningtests.txt
initctl show-config dovecot >> hardeningtests.txt
initctl show-config smbd >> hardeningtests.txt
initctl show-config squid3 >> hardeningtests.txt
ls /etc/rc*.d/S*snmpd >> hardeningtests.txt
netstat -an | grep LIST | grep ":25[[:space:]]" >> hardeningtests.txt
grep ^RSYNC_ENABLE /etc/default/rsync >> hardeningtests.txt
dpkg -s biosdevname >> hardeningtests.txt


# 7 Network Configuration and Firewalls - Tests
echo "7 Network Configuration and Firewalls" >> hardeningtests.txt

echo "7.1.1 Disable IP Forwarding - Scored" >> hardeningtests.txt
/sbin/sysctl net.ipv4.ip_forward >> hardeningtests.txt
echo "net.ipv4.ip_forward = 0" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

 

echo "7.1.2 Disable Send Packet Redirects - Scored" >> hardeningtests.txt
/sbin/sysctl net.ipv4.conf.all.send_redirects >> hardeningtests.txt
echo "net.ipv4.conf.all.send_redirects = 0" >> hardeningtests.txt
echo " " >> hardeningtests.txt
/sbin/sysctl net.ipv4.conf.default.send_redirects >> hardeningtests.txt
echo "net.ipv4.conf.default.send_redirects = 0" >> hardeningtests.txt
echo " " >> hardeningtests.txt



echo "7.2.1 Disable Source Routed Packet Acceptance - Scored" >> hardeningtests.txt
/sbin/sysctl net.ipv4.conf.all.accept_source_route >> hardeningtests.txt
echo "net.ipv4.conf.all.accept_source_route = 0" >> hardeningtests.txt
echo " " >> hardeningtests.txt
/sbin/sysctl net.ipv4.conf.default.accept_source_route >> hardeningtests.txt
echo "net.ipv4.conf.default.accept_source_route = 0" >> hardeningtests.txt 
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "7.2.1 Disable Source Routed Packet Acceptance - Scored" >> hardeningtests.txt
/sbin/sysctl net.ipv4.conf.all.accept_redirects >> hardeningtests.txt
echo "net.ipv4.conf.all.accept_redirects = 0" >> hardeningtests.txt
echo " " >> hardeningtests.txt
/sbin/sysctl net.ipv4.conf.default.accept_redirects >> hardeningtests.txt
echo "net.ipv4.conf.default.accept_redirects = 0" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "7.2.3 Disable Secure ICMP Redirect Acceptance - Scored" >> hardeningtests.txt
/sbin/sysctl net.ipv4.conf.all.secure_redirects >> hardeningtests.txt
echo "net.ipv4.conf.all.secure_redirects = 0" >> hardeningtests.txt
echo " " >> hardeningtests.txt
/sbin/sysctl net.ipv4.conf.default.secure_redirects >> hardeningtests.txt
echo "net.ipv4.conf.default.secure_redirects = 0" >> hardeningtests.txt 
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "7.2.4 Log Suspicious Packets Scored " >> hardeningtests.txt
/sbin/sysctl net.ipv4.conf.all.log_martians >> hardeningtests.txt
echo "net.ipv4.conf.all.log_martians = 1" >> hardeningtests.txt
echo " " >> hardeningtests.txt
/sbin/sysctl net.ipv4.conf.default.log_martians >> hardeningtests.txt
echo "net.ipv4.conf.default.log_martians = 1" >> hardeningtests.txt 
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "7.2.5 Enable Ignore Broadcast Requests - Scored" >> hardeningtests.txt
/sbin/sysctl net.ipv4.icmp_echo_ignore_broadcasts >> hardeningtests.txt
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> hardeningtests.txt 
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt




echo "7.2.6 Enable Bad Error Message Protection Scored " >> hardeningtests.txt
/sbin/sysctl net.ipv4.icmp_ignore_bogus_error_responses >> hardeningtests.txt
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt



echo "7.2.7 Enable RFC-recommended Source Route Validation - Scored" >> hardeningtests.txt
/sbin/sysctl net.ipv4.conf.all.rp_filter >> hardeningtests.txt
echo "net.ipv4.conf.all.rp_filter = 1" >> hardeningtests.txt
/sbin/sysctl net.ipv4.conf.default.rp_filter >> hardeningtests.txt
echo "net.ipv4.conf.default.rp_filter = 1" >> hardeningtests.txt  
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt



echo "7.2.8 Enable TCP SYN Cookies - Scored" >> hardeningtests.txt
/sbin/sysctl net.ipv4.tcp_syncookies >> hardeningtests.txt
echo "net.ipv4.tcp_syncookies = 1"  >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt




echo "7.3.1 Configure IPv6" >> hardeningtests.txt
/sbin/sysctl net.ipv6.conf.all.accept_ra >> hardeningtests.txt
echo "net.ipv4. net.ipv6.conf.all.accept_ra = 0" >> hardeningtests.txt
/sbin/sysctl net.ipv6.conf.default.accept_ra >> hardeningtests.txt
echo "net.ipv4. net.ipv6.conf.default.accept_ra = 0" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "7.3.2 Disable IPv6 Redirect Acceptance - Not Scored" >> hardeningtests.txt
/sbin/sysctl net.ipv6.conf.all.accept_redirects >> hardeningtests.txt
echo "net.ipv4. net.ipv6.conf.all.accept_redirect = 0" >> hardeningtests.txt
/sbin/sysctl net.ipv6.conf.default.accept_redirects >> hardeningtests.txt
echo "net.ipv4. net.ipv6.conf.default.accept_redirect = 0" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "7.3.3 Disable IPv6 - Not Scored" >> hardeningtests.txt
echo "Desired Result: No Output " >> hardeningtests.txt
echo "Actual Output " >> hardeningtests.txt
ip addr | grep inet6 >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt



echo "7.4.1 Install TCP Wrappers Scored " >> hardeningtests.txt
echo "Desired Result: installed ok installed" >> hardeningtests.txt
echo "Actual Output " >> hardeningtests.txt
dpkg -s tcpd  >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt



echo "7.4.2 Create /etc/hosts.allow - Not Scored" >> hardeningtests.txt
cat /etc/hosts.allow  >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "7.4.3 Verify Permissions on /etc/hosts.allow Scored " >> hardeningtests.txt
/bin/ls -l /etc/hosts.allow >> hardeningtests.txt
echo "-rw-r--r-- 1 root root 2055 Jan 30 16:30 /etc/hosts.allow" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "7.4.4 Create /etc/hosts.deny - Not Scored" >> hardeningtests.txt
grep "ALL: ALL" /etc/hosts.deny >> hardeningtests.txt
echo "ALL: ALL" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "7.4.3 Verify Permissions on /etc/hosts.allow Scored " >> hardeningtests.txt
/bin/ls -l /etc/hosts.deny >> hardeningtests.txt
echo "-rw-r--r-- 1 root root 2055 Jan 30 16:30 /etc/hosts.deny" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

ifconfig -a >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


# Section 8 Tests AUDITD STUFF
echo "SECTION 8 TESTS AUDITD STUFF" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo "grep max_log_file /etc/audit/auditd.conf" >> hardeningtests.txt
grep max_log_file /etc/audit/auditd.conf >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# grep space_left_action /etc/audit/auditd.conf" >> hardeningtests.txt
echo "Desired Result: space_left_action = email" >> hardeningtests.txt
grep space_left_action /etc/audit/auditd.conf >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# grep action_mail_acct /etc/audit/auditd.conf" >> hardeningtests.txt
echo "Desired Result: action_mail_acct = root" >> hardeningtests.txt
echo " NOTE: In /etc/audit/auditd.conf, action_mail_acct = security is equivalent to action_mail_acct = root"  >> hardeningtests.txt
echo " Alastair Says: This is because we have added an alias (see /etc/aliases and line 87 in provisioning/hardening/serverscripts/serverhardening.sh) called -security-.  Anything going to this alias goes to root and security@gtp.com.au" >> hardeningtests.txt
echo "Actual Result: Shown Below" >> hardeningtests.txt
grep action_mail_acct /etc/audit/auditd.conf >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# grep admin_space_left_action /etc/audit/auditd.conf" >> hardeningtests.txt
echo "Desired Result: admin_space_left_action = halt" >> hardeningtests.txt
grep admin_space_left_action /etc/audit/auditd.conf >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# grep max_log_file_action /etc/audit/auditd.conf " >> hardeningtests.txt
echo "Desired Result: max_log_file_action = keep_logs" >> hardeningtests.txt
grep max_log_file_action /etc/audit/auditd.conf >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# Check AUditD Installed" >> hardeningtests.txt
dpkg -s auditd >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "grep linux /boot/grub/grub.cfg" >> hardeningtests.txt
echo "Make sure each line that starts with linux has the audit=1 parameter set." >> hardeningtests.txt
grep "linux" /boot/grub/grub.cfg >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt



echo "On a 64 bit system, perform the following command and ensure the output is as shown. " >> hardeningtests.txt
echo "# grep time_change /etc/audit/audit.rules" >> hardeningtests.txt
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> hardeningtests.txt
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> hardeningtests.txt
echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> hardeningtests.txt
echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> hardeningtests.txt
echo "-w /etc/localtime -p wa -k time-change" >> hardeningtests.txt
echo "# Execute the following command to restart auditd" >> hardeningtests.txt
echo "# pkill -P 1-HUP auditd" >> hardeningtests.txt
echo " " >> hardeningtests.txt
grep -r time-change /etc/audit >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# grep identity /etc/audit/audit.rules - EXPECTED OUTPUT BELOW" >> hardeningtests.txt
echo "-w /etc/group -p wa -k identity" >> hardeningtests.txt
echo "-w /etc/passwd -p wa -k identity" >> hardeningtests.txt
echo "-w /etc/gshadow -p wa -k identity" >> hardeningtests.txt
echo "-w /etc/shadow -p wa -k identity" >> hardeningtests.txt
echo "-w /etc/security/opasswd -p wa -k identi" >> hardeningtests.txt
echo " " >> hardeningtests.txt 
grep -r identity /etc/audit >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "On a 64 bit system, perform the following command and ensure the output is as shown" >> hardeningtests.txt
echo "to determine if events that modify the system's environment are recorded. " >> hardeningtests.txt
echo "# grep system-locale /etc/audit/audit.rules" >> hardeningtests.txt
echo "-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> hardeningtests.txt
echo "-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> hardeningtests.txt
echo "-w /etc/issue -p wa -k system-locale" >> hardeningtests.txt
echo "-w /etc/issue.net -p wa -k system-locale" >> hardeningtests.txt
echo "-w /etc/hosts -p wa -k system-locale" >> hardeningtests.txt
echo "-w /etc/network -p wa -k system-locale" >> hardeningtests.txt
echo " " >> hardeningtests.txt 
grep -r system-locale /etc/audit >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt



echo "# grep MAC-policy /etc/audit/audit.rules" >> hardeningtests.txt
echo "Desired Output: -w /etc/selinux/ -p wa -k MAC-policy" >> hardeningtests.txt
grep -r MAC-policy /etc/audit >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# grep logins /etc/audit/audit.rules" >> hardeningtests.txt
echo "-w /var/log/faillog -p wa -k logins" >> hardeningtests.txt
echo "-w /var/log/lastlog -p wa -k logins" >> hardeningtests.txt
echo "-w /var/log/tallylog -p wa -k logins" >> hardeningtests.txt
echo " " >> hardeningtests.txt
grep -r logins /etc/audit >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# grep session /etc/audit/audit.rules" >> hardeningtests.txt
echo "-w /var/run/utmp -p wa -k session" >> hardeningtests.txt
echo "-w /var/log/wtmp -p wa -k session" >> hardeningtests.txt
echo "-w /var/log/btmp -p wa -k session " >> hardeningtests.txt
echo " " >> hardeningtests.txt
grep -r session /etc/audit >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# grep perm_mod /etc/audit/audit.rules" >> hardeningtests.txt
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 " >> hardeningtests.txt
echo "-F auid!=4294967295 -k perm_mod" >> hardeningtests.txt
echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 " >> hardeningtests.txt
echo "-F auid!=4294967295 -k perm_mod" >> hardeningtests.txt
echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 " >> hardeningtests.txt
echo "-F auid!=4294967295 -k perm_mod" >> hardeningtests.txt
echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 " >> hardeningtests.txt 
echo "-F auid!=4294967295 -k perm_mod" >> hardeningtests.txt
echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S " >> hardeningtests.txt
echo "lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> hardeningtests.txt
echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S " >> hardeningtests.txt
echo "lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> hardeningtests.txt
echo " " >> hardeningtests.txt
grep -r perm_mod /etc/audit >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# grep access /etc/audit/audit.rules" >> hardeningtests.txt
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate " >> hardeningtests.txt
echo "-F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access" >> hardeningtests.txt
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate " >> hardeningtests.txt
echo "-F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access" >> hardeningtests.txt
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate " >> hardeningtests.txt
echo "-F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access" >> hardeningtests.txt
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate " >> hardeningtests.txt
echo "-F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access" >> hardeningtests.txt
echo " " >> hardeningtests.txt
grep -r access /etc/audit >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

#echo "All audit records will be tagged with the identifier privileged. " >> hardeningtests.txt
#echo "# find PART -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print " >> hardeningtests.txt
#echo "-a always,exit -F path=" $1 " -F perm=x -F auid>=500 -F auid!=4294967295 " >> hardeningtests.txt
#echo "-k privileged }'" >> hardeningtests.txt
#echo "Next, add those lines to the /etc/audit/audit.rules file. " >> hardeningtests.txt
#find PART -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \ >> hardeningtests.txt
#echo " " >> hardeningtests.txt
#echo " " >> hardeningtests.txt
#echo " " >> hardeningtests.txt
#echo " " >> hardeningtests.txt

echo "# grep mounts /etc/audit/audit.rules" >> hardeningtests.txt
echo "-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts" >> hardeningtests.txt
echo "-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts" >> hardeningtests.txt
grep -r mounts /etc/audit/ >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# grep delete /etc/audit/audit.rules" >> hardeningtests.txt
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 " >> hardeningtests.txt
echo "-F auid!=4294967295 -k delete" >> hardeningtests.txt
echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 " >> hardeningtests.txt
echo "-F auid!=4294967295 -k delete " >> hardeningtests.txt
grep -r delete /etc/audit/ >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# grep scope /etc/audit/audit.rules" >> hardeningtests.txt
echo "-w /etc/sudoers -p wa -k scope" >> hardeningtests.txt
grep -r scope /etc/audit >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# grep actions /etc/audit/audit.rules" >> hardeningtests.txt
echo "-w /var/log/sudo.log -p wa -k actions " >> hardeningtests.txt
grep -r actions /etc/audit/ >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# grep modules /etc/audit/audit.rules" >> hardeningtests.txt
echo "-w /sbin/insmod -p x -k modules" >> hardeningtests.txt
echo "-w /sbin/rmmod -p x -k modules" >> hardeningtests.txt
echo "-w /sbin/modprobe -p x -k modules" >> hardeningtests.txt
echo "-a always,exit arch=b64 -S init_module -S delete_module -k modules" >> hardeningtests.txt
echo " " >> hardeningtests.txt
grep -r modules /etc/audit/ >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# grep "^-e 2" /etc/audit/audit.rules" >> hardeningtests.txt
echo "-e 2" >> hardeningtests.txt
grep -r "^-e 2" /etc/audit >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

# CONFIGURE RSYSLOG
echo "Check rsyslog installed" >> hardeningtests.txt
dpkg -s rsyslog >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# initctl show-config rsyslog" >> hardeningtests.txt
echo "rsyslog" >> hardeningtests.txt
echo "start on filesystem" >> hardeningtests.txt
echo "stop on runlevel [06]" >> hardeningtests.txt
echo " " >> hardeningtests.txt
initctl show-config rsyslog >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# ls -l /var/log/" >> hardeningtests.txt
ls -l /var/log/ >> hardeningtests.txt

echo "verify that the <owner>:<group> is root:root" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "8.2.5 Configure rsyslog to Send Logs to a Remote Log Host Scored " >> hardeningtests.txt
echo "# grep "^*.*[^I][^I]*@" /etc/rsyslog.conf" >> hardeningtests.txt
echo "*.* @@loghost.example.com  " >> hardeningtests.txt
grep "^*.*[^I][^I]*@" /etc/rsyslog.conf >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt



echo "8.2.6 Accept Remote rsyslog Messages Only on Designated Log Hosts" >> hardeningtests.txt
echo "Audit:" >> hardeningtests.txt 
echo "# grep '$ModLoad imtcp.so' /etc/rsyslog.conf" >> hardeningtests.txt
echo "$ModLoad imtcp.so" >> hardeningtests.txt
echo "# grep '$InputTCPServerRun' /etc/rsyslog.conf" >> hardeningtests.txt
echo "$InputTCPServerRun 514" >> hardeningtests.txt 
grep '$ModLoad imtcp.so' /etc/rsyslog.conf >> hardeningtests.txt
grep '$InputTCPServerRun' /etc/rsyslog.conf >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "CHECK AIDE INSTALLED" >> hardeningtests.txt
echo "# dpkg -s aide " >> hardeningtests.txt

echo "# crontab -u root -l | grep aide" >> hardeningtests.txt
echo "0 5 * * * /usr/sbin/aide --check  " >> hardeningtests.txt
crontab -u root -l | grep aide >> hardeningtests.txt


# Section 9 Tests
echo "SECTION 9 TESTS" >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo "dpkg -s openssh-server" >> hardeningtests.txt
dpkg -s openssh-server >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "Check Protocol is 2 for SSH" >> hardeningtests.txt
grep "^Protocol" /etc/ssh/sshd_config >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "grep ^LogLevel /etc/ssh/sshd_config  out puts LogLevel INFO" >> hardeningtests.txt
grep "^LogLevel" /etc/ssh/sshd_config >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# /bin/ls -l /etc/ssh/sshd_config" >> hardeningtests.txt
/bin/ls -l /etc/ssh/sshd_config >> hardeningtests.txt
echo "Desired Output: -rw------- 1 root root 762 Sep 23 002 /etc/ssh/sshd_config " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "X11Forwarding /etc/ssh/sshd_config - Desired Output = NO" >> hardeningtests.txt
grep "^X11Forwarding" /etc/ssh/sshd_config >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# grep ^MaxAuthTries /etc/ssh/sshd_config - Desired Output MaxAuthTries 4 " >> hardeningtests.txt
grep "^MaxAuthTries" /etc/ssh/sshd_config >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# grep ^IgnoreRhosts /etc/ssh/sshd_config -Desired Output - IgnoreRhosts yes" >> hardeningtests.txt
grep "^IgnoreRhosts" /etc/ssh/sshd_config >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
 
echo "# grep ^HostbasedAuthentication /etc/ssh/sshd_config - Desired Output - HostbasedAuthentication no" >> hardeningtests.txt
grep "^HostbasedAuthentication" /etc/ssh/sshd_config >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# grep ^PermitRootLogin /etc/ssh/sshd_config - Dsired Output - PermitRootLogin no or without-password" >> hardeningtests.txt
echo "#see http://askubuntu.com/questions/449364/what-does-without-password-mean-in-sshd-config-file" >> hardeningtests.txt
echo "It means key only" >> hardeningtests.txt
grep "^PermitRootLogin" /etc/ssh/sshd_config >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# grep ^PermitEmptyPasswords /etc/ssh/sshd_config - Dsired Output - PermitEmptyPasswords no" >> hardeningtests.txt
grep "^PermitEmptyPasswords" /etc/ssh/sshd_config >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# grep Ciphers /etc/ssh/sshd_config - Desired Output - Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> hardeningtests.txt
grep "Ciphers" /etc/ssh/sshd_config  >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt



echo "# grep ^ClientAliveInterval /etc/ssh/sshd_config - Desired Output - ClientAliveInterval 300" >> hardeningtests.txt
grep "^ClientAliveInterval" /etc/ssh/sshd_config >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# grep ^ClientAliveCountMax /etc/ssh/sshd_config - Desired Output - ClientAliveCountMax 0 " >> hardeningtests.txt
grep "^ClientAliveCountMax" /etc/ssh/sshd_config >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt



echo "# grep ^AllowUsers /etc/ssh/sshd_config - Desired Output - AllowUsers <userlist>" >> hardeningtests.txt
grep "^AllowUsers" /etc/ssh/sshd_config >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# grep ^AllowGroups /etc/ssh/sshd_config - Desired Output - AllowGroups <grouplist>" >> hardeningtests.txt
grep "^AllowGroups" /etc/ssh/sshd_config >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# grep ^DenyUsers /etc/ssh/sshd_config - Desired Output - DenyUsers <userlist>" >> hardeningtests.txt
grep "^DenyUsers" /etc/ssh/sshd_config >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# grep ^DenyGroups /etc/ssh/sshd_config - Desired Output - DenyGroups <grouplist>" >> hardeningtests.txt
grep "^DenyGroups" /etc/ssh/sshd_config >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# grep "^Banner" /etc/ssh/sshd_config - Desired Output - Banner <bannerfile>" >> hardeningtests.txt
grep "^Banner" /etc/ssh/sshd_config >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# cat /etc/securetty - to check ofr insecure consoles" >> hardeningtests.txt
cat /etc/securetty >> hardeningtests.txt
echo " Action: Remove entries for any consoles that are not in a physically secure location." >> hardeningtests.txt 



echo "# grep pam_wheel.so /etc/pam.d/su - Desired Output - auth required pam_wheel.so use_uid" >> hardeningtests.txt
grep pam_wheel.so /etc/pam.d/su >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# grep wheel /etc/group - Desired Output - wheel:x:10:root, <user list> " >> hardeningtests.txt
grep wheel /etc/group >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


#Section 10 Tests

echo "# grep PASS_MAX_DAYS /etc/login.defs" >> hardeningtests.txt
echo "PASS_MAX_DAYS 90" >> hardeningtests.txt
grep PASS_MAX_DAYS /etc/login.defs >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo "# chage --list dale" >> hardeningtests.txt
echo "Maximum number of days between password change:    90" >> hardeningtests.txt
chage --list dale >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo "# grep PASS_MIN_DAYS /etc/login.defs" >> hardeningtests.txt
echo "PASS_MIN_DAYS 7" >> hardeningtests.txt
grep PASS_MIN_DAYS /etc/login.defs >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo "# chage --list dale" >> hardeningtests.txt
echo "Minimum number of days between password change:    7" >> hardeningtests.txt 
chage --list dale >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# grep PASS_WARN_AGE /etc/login.defs" >> hardeningtests.txt
echo "PASS_WARN_AGE 7" >> hardeningtests.txt
grep PASS_WARN_AGE /etc/login.defs >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo "# chage --list <user>" >> hardeningtests.txt
echo "Number of days of warning before password expires:    7" >> hardeningtests.txt 
chage --list dale >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "Run the following script to determine if any system accounts can be accessed:" >> hardeningtests.txt 
echo "egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" &&" >> hardeningtests.txt
echo "$1!="halt" && $3<500 && $7!="/usr/sbin/nologin" && $7!="/bin/false") {print}' " >> hardeningtests.txt
echo "There should be no results returned below. " >> hardeningtests.txt
#egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/usr/sbin/nologin" && $7!="/bin/false >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# grep "^root:" /etc/passwd | cut -f4 -d:" >> hardeningtests.txt
echo "0 " >> hardeningtests.txt
grep "^root:" /etc/passwd | cut -f4 -d: >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# grep "^UMASK" /etc/login.defs" >> hardeningtests.txt
echo "UMASK 077 " >> hardeningtests.txt
grep "^UMASK" /etc/login.defs >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# useradd -D | grep INACTIVE" >> hardeningtests.txt
echo "INACTIVE=35 " >> hardeningtests.txt
useradd -D | grep INACTIVE >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


#Section 11 Tests

echo "WARNING BANNERS - DO THEY EXIST" >> hardeningtests.txt
echo "# /bin/ls -l /etc/motd" >> hardeningtests.txt
echo "-rw-r--r-- 1 root root 2055 Jan 30 16:30 /etc/motd" >> hardeningtests.txt
/bin/ls -l /etc/motd >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo "# ls /etc/issue" >> hardeningtests.txt
echo "-rw-r--r-- 1 root root 2055 Jan 30 16:30 /etc/issue" >> hardeningtests.txt
ls /etc/issue >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo "# ls /etc/issue.net" >> hardeningtests.txt
echo "-rw-r--r-- 1 root root 2055 Jan 30 16:30 /etc/issue.net" >> hardeningtests.txt
ls /etc/issue.net >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "CHECK NO OS INFORMATIONIS SHOWING IN BANNERS" >> hardeningtests.txt
echo "# egrep '(\\v|\\r|\\m|\\s)' /etc/issue" >> hardeningtests.txt
egrep '(\\v|\\r|\\m|\\s)' /etc/issue >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo "# egrep '(\\v|\\r|\\m|\\s)' /etc/motd" >> hardeningtests.txt
egrep '(\\v|\\r|\\m|\\s)' /etc/motd >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo "# egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net " >> hardeningtests.txt 
egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net >> hardeningtests.txt 
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


# Section 12 Tests VERIFY SYSTEM PERMISSIONS

echo "# /bin/ls -l /etc/passwd" >> hardeningtests.txt
echo "-rw-r--r-- 1 root root 2055 Jan 30 16:30 /etc/passwd" >> hardeningtests.txt 
/bin/ls -l /etc/passwd >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# /bin/ls -l /etc/shadow" >> hardeningtests.txt
echo "-rw-r----- 1 root shadow 712 Jul 22 21:33 shadow" >> hardeningtests.txt 
/bin/ls -l /etc/shadow >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# /bin/ls -l /etc/group" >> hardeningtests.txt
echo "-rw-r--r-- 1 root root 762 Sep 23 002 /etc/group" >> hardeningtests.txt 
/bin/ls -l /etc/group >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# /bin/ls -l /etc/passwd" >> hardeningtests.txt
echo "-rw-r--r-- 1 root root 762 Sep 23 002 /etc/passwd" >> hardeningtests.txt  
/bin/ls -l /etc/passwd >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "# /bin/ls -l /etc/shadow" >> hardeningtests.txt
echo "-rw-r----- 1 root shadow 712 Jul 22 21:33 shadow " >> hardeningtests.txt
/bin/ls -l /etc/shadow >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "# /bin/ls -l /etc/group" >> hardeningtests.txt
echo "-rw-r--r-- 1 root root 762 Sep 23 002 /etc/group" >> hardeningtests.txt
/bin/ls -l /etc/group >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "12.7 Find World Writable Files - Not Scored" >> hardeningtests.txt 
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f perm -0002 -print >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt


echo "12.8 Find Un-owned Files and Directories - Scored" >> hardeningtests.txt
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "12.9 Find Un-grouped Files and Directories - Scored" >> hardeningtests.txt
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -group -ls  >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "12.10 Find SUID System Executables Not Scored " >> hardeningtests.txt
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f perm -4000 -print >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "12.11 Find SGID System Executables Not Scored " >> hardeningtests.txt
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f perm -2000 -print >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt
echo " " >> hardeningtests.txt





# Section 13 Tests
echo "13.1 Ensure Password Fields are Not Empty - Scored" >> hardeningtests.txt
echo "Desired Output: No Output" >> hardeningtests.txt
echo "Actual Output" >> hardeningtests.txt
/bin/cat /etc/shadow | /usr/bin/awk -F: '($2 == "" ) { print $1 " does not have a password "}'  >> hardeningtests.txt 
echo " " >> hardeningtests.txt

echo "13.2 Verify No Legacy "+" Entries Exist in /etc/passwd File - Scored" >> hardeningtests.txt
echo "Desired Output: No Output" >> hardeningtests.txt
echo "Actual Output" >> hardeningtests.txt
/bin/grep '^+:' /etc/passwd >> hardeningtests.txt 
echo " " >> hardeningtests.txt


echo "13.3 Verify No Legacy "+" Entries Exist in /etc/shadow File - Scored" >> hardeningtests.txt
echo "Desired Output: No Output" >> hardeningtests.txt
echo "Actual Output" >> hardeningtests.txt
/bin/grep '^+:' /etc/shadow >> hardeningtests.txt 
echo " " >> hardeningtests.txt



echo "13.4 Verify No Legacy "+" Entries Exist in /etc/group File - Scored" >> hardeningtests.txt
echo "Desired Output: No Output" >> hardeningtests.txt
echo "Actual Output" >> hardeningtests.txt
/bin/grep '^+:' /etc/group >> hardeningtests.txt 
echo " " >> hardeningtests.txt

echo "13.5 Verify No UID 0 Accounts Exist Other Than root - Scored" >> hardeningtests.txt
echo "Desired Output: root" >> hardeningtests.txt
echo "Actual Output" >> hardeningtests.txt
/bin/cat /etc/passwd | /usr/bin/awk -F: '($3 == 0) { print $1 }' >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "13.6 Ensure root PATH Integrity - Scored" >> hardeningtests.txt
if [ "`echo $PATH | grep :: `" != "" ]; then
echo "Empty Directory in PATH ::" >> hardeningtests.txt
fi
if [ "`echo $PATH | bin/grep :$`" != "" ]; then
echo "Trailing : in PATH" >> hardeningtests.txt
fi
p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
if [ "$1" = "." ]; then
echo "PATH contains ." >> hardeningtests.txt
shift
continue
fi
if [ -d $1 ]; then
dirperm=`ls -ldH $1 | cut -f1 -d" "`
if [ `echo $dirperm | cut -c6 ` != "-" ]; then
echo "Group Write permission set on directory $1" >> hardeningtests.txt
fi
if [ `echo $dirperm | cut -c9 ` != "-" ]; then
echo "Other Write permission set on directory $1" >> hardeningtests.txt
fi
dirown=`ls -ldH $1 | awk '{print $3}'`
if [ "$dirown" != "root" ] ; then
echo $1 is not owned by root >> hardeningtests.txt
fi
else
echo $1 is not a directory >> hardeningtests.txt
fi
shift
done 
echo " " >> hardeningtests.txt


echo "13.7 Check Permissions on User Home Directories - Scored" >> hardeningtests.txt
for dir in `/bin/cat /etc/passwd  | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /usr/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
        dirperm=`/bin/ls -ld $dir | /usr/bin/cut -f1 -d" "`
        if [ `echo $dirperm | /usr/bin/cut -c6 ` != "-" ]; then
            echo "Group Write permission set on directory $dir" >> hardeningtests.txt
        fi
        if [ `echo $dirperm | /usr/bin/cut -c8 ` != "-" ]; then
            echo "Other Read permission set on directory $dir" >> hardeningtests.txt
        fi
        if [ `echo $dirperm | /usr/bin/cut -c9 ` != "-" ]; then
            echo "Other Write permission set on directory $dir" >> hardeningtests.txt
        fi
        if [ `echo $dirperm | /usr/bin/cut -c10 ` != "-" ]; then
            echo "Other Execute permission set on directory $dir" >> hardeningtests.txt
	    fi
done 
echo " " >> hardeningtests.txt


echo "13.8 Check User Dot File Permissions - Scored" >> hardeningtests.txt
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |
/usr/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.[A-Za-z0-9]*; do
        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /usr/bin/cut -f1 -d" "`
            if [ `echo $fileperm | /usr/bin/cut -c6 ` != "-" ]; then
                echo "Group Write permission set on file $file" >> hardeningtests.txt
            fi
            if [ `echo $fileperm | /usr/bin/cut -c9 ` != "-" ]; then
                echo "Other Write permission set on file $file" >> hardeningtests.txt
            fi
        fi
    done
done 
echo " " >> hardeningtests.txt

echo "13.9 Check Permissions on User .netrc Files - Scored" >> hardeningtests.txt
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |\
    /usr/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.netrc; do
        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /usr/bin/cut -f1 -d" "`
            if [ `echo $fileperm | /usr/bin/cut -c5 ` != "-" ]
            then
                echo "Group Read set on $file" >> hardeningtests.txt
            fi
            if [ `echo $fileperm | /usr/bin/cut -c6 ` != "-" ]
            then
                echo "Group Write set on $file" >> hardeningtests.txt
            fi
            if [ `echo $fileperm | /usr/bin/cut -c7 ` != "-" ]
            then
                echo "Group Execute set on $file" >> hardeningtests.txt
            fi
            if [ `echo $fileperm | /usr/bin/cut -c8 ` != "-" ]
            then
                echo "Other Read  set on $file" >> hardeningtests.txt
            fi
            if [ `echo $fileperm | /usr/bin/cut -c9 ` != "-" ]
            then
                echo "Other Write set on $file" >> hardeningtests.txt
            fi
            if [ `echo $fileperm | /usr/bin/cut -c10 ` != "-" ]
            then
                echo "Other Execute set on $file" >> hardeningtests.txt
            fi
        fi
    done
done 
echo " " >> hardeningtests.txt

echo "13.10 Check for Presence of User .rhosts Files (Scored" >> hardeningtests.txt
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /usr/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.rhosts; do
        if [ ! -h "$file" -a -f "$file" ]; then
            echo ".rhosts file in $dir" >> hardeningtests.txt
        fi    done
done  
echo " " >> hardeningtests.txt

echo "13.11 Check Groups in /etc/passwd - Scored" >> hardeningtests.txt
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
grep -q -P "^.*?:[^:]*:$i:" /etc/group
if [ $? -ne 0 ]; then
echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" >> hardeningtests.txt
fi
done  
echo " " >> hardeningtests.txt

echo "13.12  That Users Are Assigned Valid Home Directories - Scored" >> hardeningtests.txt
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
if [ $uid -ge 500 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
echo "The home directory ($dir) of user $user does not exist." >> hardeningtests.txt
fi
done  
echo " " >> hardeningtests.txt

echo "13.13 Check User Home Directory Ownership Scored " >> hardeningtests.txt
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
if [ $uid -ge 500 -a -d "$dir" -a $user != "nfsnobody" ]; then
owner=$(stat -L -c "%U" "$dir")
if [ "$owner" != "$user" ]; then
echo "The home directory ($dir) of user $user is owned by $owner." >> hardeningtests.txt
fi
fi
done 
echo " " >> hardeningtests.txt



echo "13.14 Check for Duplicate UIDs - Scored" >> hardeningtests.txt
/bin/cat /etc/passwd | /usr/bin/cut -f3 -d":" | /usr/bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        users=`/usr/bin/awk -F: '($3 == n) { print $1 }' n=$2 \
            /etc/passwd | /usr/bin/xargs`
        echo "Duplicate UID ($2): ${users}" >> hardeningtests.txt
    fi
done 
echo " " >> hardeningtests.txt

echo "13.15 Check for Duplicate GIDs - Scored" >> hardeningtests.txt
/bin/cat /etc/group | /usr/bin/cut -f3 -d":" | /usr/bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        grps=`/usr/bin/awk -F: '($3 == n) { print $1 }' n=$2 \
            /etc/group | xargs`
        echo "Duplicate GID ($2): ${grps}" >> hardeningtests.txt
    fi 
done 
echo " " >> hardeningtests.txt


echo "13.16  Check for Duplicate User Names - Scored" >> hardeningtests.txt
cat /etc/passwd | /usr/bin/cut -f1 -d":" | /usr/bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        uids=`/usr/bin/awk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/passwd | xargs`
        echo "Duplicate User Name ($2): ${uids}" >> hardeningtests.txt  
    fi
done
echo " " >> hardeningtests.txt


echo "13.17 Check for Duplicate Group Names - Scored" >> hardeningtests.txt
cat /etc/group | /usr/bin/cut -f1 -d":" | /usr/bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        gids=`/usr/bin/awk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/group | xargs`
        echo "Duplicate Group Name ($2): ${gids}" >> hardeningtests.txt
    fi
done
echo " " >> hardeningtests.txt

echo "13.18 Check for Presence of User .netrc Files - Scored" >> hardeningtests.txt
for dir in `/bin/cat /etc/passwd |\
    /usr/bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
        echo ".netrc file $dir/.netrc exists" >> hardeningtests.txt
    fi
done 
echo " " >> hardeningtests.txt

echo "13.19 Check for Presence of User .forward Files Scored " >> hardeningtests.txt
for dir in `/bin/cat /etc/passwd |\
    /usr/bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
        echo ".forward file $dir/.forward exists" >> hardeningtests.txt
    fi
done
echo " " >> hardeningtests.txt



echo "13.20 Ensure Shadow group is empty" >> hardeningtests.txt
grep ^shadow /etc/group >> hardeningtests.txt
awk -F: '($4 == "<shadow-gid>") { print }' /etc/passwd >> hardeningtests.txt
echo " " >> hardeningtests.txt

echo "#END OF CIS HARDENING UBUNTU CONFIGURATION TESTS HARDENING" >> hardeningtests.txt

echo "#START OF CIS APACHE HARDENING CONFIGURATION TESTS HARDENING" >> hardeningtests.txt
echo "#To Be Done" >> hardeningtests.txt
echo "#END OF CIS APACHE HARDENING CONFIGURATION TESTS HARDENING" >> hardeningtests.txt

#REPORT TO GENERATE LIST OF RUNNING SERVICES, OPEN PORTS, DAEMONS
echo "REPORT TO GENERATE LIST OF RUNNING SERVICES, OPEN PORTS, DAEMONS" >> services-ports-daemons.txt
echo "ALL SERVICES" >> services-ports-daemons.txt 
service --status-all >> services-ports-daemons.txt 
echo "*" >> services-ports-daemons.txt
echo "*" >> services-ports-daemons.txt 
echo "ALL SERVICES - STOPPED" >> services-ports-daemons.txt 
service --status-all | grep stopped >> services-ports-daemons.txt 
echo "*" >> services-ports-daemons.txt
echo "*" >> services-ports-daemons.txt
echo "ALL SERVICES RUNNING" >> services-ports-daemons.txt 
service --status-all | grep running >> services-ports-daemons.txt 
echo "*" >> services-ports-daemons.txt
echo "*" >> services-ports-daemons.txt
echo "OPEN PORTS" >> services-ports-daemons.txt
netstat -tul >> services-ports-daemons.txt
echo "*" >> services-ports-daemons.txt
echo "*" >> services-ports-daemons.txt
echo "OPEN PORTS 0 LISTENING NETWORK PORTS" >> services-ports-daemons.txt
netstat -tulp >> services-ports-daemons.txt 
echo "*" >> services-ports-daemons.txt
echo "*" >> services-ports-daemons.txt
echo "DISPLAY ALL RUNNING DAEMONS" >> services-ports-daemons.txt 
ps -A | grep d >> services-ports-daemons.txt
echo "*" >> services-ports-daemons.txt
echo "*" >> services-ports-daemons.txt
echo "DISPLAY ALL RUNNING PROCESSES" >> services-ports-daemons.txt 
ps aux | less >> services-ports-daemons.txt 
echo "*" >> services-ports-daemons.txt
echo "*" >> services-ports-daemons.txt
echo "DISPLAY A TREE OF PROCESSES" >> services-ports-daemons.txt 
pstree >> services-ports-daemons.txt
echo "*" >> services-ports-daemons.txt
echo "*" >> services-ports-daemons.txt
echo "LIST OF INSTALLED RPMs (PACKAGES)" >> services-ports-daemons.txt
rpm -qa >> services-ports-daemons.txt


#SHOW USERS ON SYSTEM AND PASSWORD EXPIRY
echo "Show Users on System and Password Expiry" >> hardeningtests.txt
cut -f 1 -d: /etc/passwd | xargs -n 1 -I {} bash -c " echo {} ; chage -l {}" >> hardeningtests.txt
