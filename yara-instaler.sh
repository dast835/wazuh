#!/bin/bash

apt update
apt install automake jq libtool libssl-dev make gcc pkg-config git libjansson-dev libmagic-dev -y
wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.3.1.tar.gz
tar xvf v4.3.1.tar.gz --directory /usr/local/bin/
cd /usr/local/bin/yara-4.3.1/
./bootstrap.sh
./configure --enable-cuckoo --enable-magic --enable-dotnet --with-crypto
make
make install
cd /usr/local
git clone https://github.com/Neo23x0/signature-base.git
wget https://github.com/dast835/wazuh/raw/main/yara_rules_updater.sh

##########################
chmod +x /usr/local/yara_rules_updater.sh
/usr/local/yara_rules_updater.sh
# 
# Create yara.sh script
#
cd  /var/ossec/active-response/bin/
wget https://github.com/dast835/wazuh/raw/main/yara.sh

#####
chown root:wazuh yara.sh
chmod 750 yara.sh
mkdir /tmp/quarantined
echo "Instalation completed"


