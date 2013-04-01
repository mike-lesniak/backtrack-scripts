#!/bin/bash

clear

echo
echo -e "\e[1;34mSetting up aliases.\e[0m"
touch /root/.bash_aliases
cp /opt/scripts/alias /root/.bash_aliases
source /root/.bash_aliases

echo
echo -e "\e[1;34mInstalling Filezilla.\e[0m"
apt-get install filezilla

echo
echo -e "\e[1;34mInstalling xdotool.\e[0m"
apt-get install xdotool

echo
echo -e "\e[1;34m##################################\e[0m"
echo
echo -e "\e[1;34mRemoving nmap files and folders.\e[0m"

rm -rf /root/.zenmap/
rm -rf /root/nmap-svn/
rm -rf /usr/local/share/ncat/
rm -rf /usr/local/share/nmap/
rm -rf /usr/local/share/zenmap/
rm /usr/local/bin/ncat
rm /usr/local/bin/ndiff
rm /usr/local/bin/nmap
rm /usr/local/bin/nmap-update
rm /usr/local/bin/nmapfe
rm /usr/local/bin/nping
rm /usr/local/bin/uninstall_zenmap
rm /usr/local/bin/xnmap
rm /usr/local/bin/zenmap
rm /usr/local/share/nmap
rm /usr/local/share/zenmap

apt-get remove nmap

echo
echo -e "\e[1;34mInstalling nmap.\e[0m"
svn co https://svn.nmap.org/nmap/ /root/nmap-svn/
cd /root/nmap-svn/
./configure && make && make install

echo
echo -e "\e[1;34mUpdating .bashrc.\e[0m"
grep -v "export PATH=\$PATH:/etc/alternatives/gem-bin" /root/.bashrc > /root/tmp
echo "export PATH=\$PATH:/etc/alternatives/gem-bin:root/nmap-svn/" >> /root/tmp
mv /root/tmp /root/.bashrc

echo
echo
