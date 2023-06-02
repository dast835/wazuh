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
https://github.com/dast835/wazuh/raw/main/yara_rules_updater.sh
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
root@backup-media-am:~# nano yara-install.sh 
root@backup-media-am:~# cat yara-install.sh 
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
cat > yara_rules_updater.sh <<EOF1
#!/bin/bash
# Yara rules - Compiled file creation
#
#------------------------- Aadjust IFS to read files -------------------------#
SAVEIFS=$IFS
IFS=$(echo -en "\n\b")
# Static active response parameters
LOCAL=`dirname $0`
#------------------------- Folder where Yara rules (files) will be placed -------------------------#
git_repo_folder="/usr/local/signature-base"
yara_file_extenstions=( ".yar" )
yara_rules_list="/usr/local/signature-base/yara_rules_list.yar"

#------------------------- Main workflow --------------------------#

# Update Github Repo
cd $git_repo_folder
git pull https://github.com/Neo23x0/signature-base.git

# Remove .yar files not compatible with standard Yara package
rm git_repo_folder/yara/gen_mal_3cx_compromise_mar23.yar  $git_repo_folder/yara/generic_anomalies.yar $git_repo_folder/yara/general_cloaking.yar $git_repo_folder/yara/thor_inverse_matches.yar $git_repo_folder/yara/yara_mixed_ext_vars.yar $git_repo_folder/yara/apt_cobaltstrike.yar $git_repo_folder/yara/apt_tetris.yar $git_repo_folder/yara/gen_susp_js_obfuscatorio.yar $git_repo_folder/yara/configured_vulns_ext_vars.yar $git_repo_folder/yara/gen_webshells_ext_vars.yar

# Create File with rules to be compiled
if [ ! -f $yara_rules_list ]
then
    /usr/bin/touch $yara_rules_list
else rm $yara_rules_list
fi
for e in "${yara_file_extenstions[@]}"
do
  for f1 in $( find $git_repo_folder/yara -type f | grep -F $e ); do
    echo "include \"""$f1"\""" >> $yara_rules_list
  done
done
# Compile Yara Rules
/usr/local/bin/yara-4.3.1/yarac $yara_rules_list /usr/local/signature-base/yara_base_ruleset_compiled.yar
IFS=$SAVEIFS
exit 1;
EOF1
##########################
chmod +x /usr/local/yara_rules_updater.sh
/usr/local/yara_rules_updater.sh
# 
# Create yara.sh script
#
cd  /var/ossec/active-response/bin/
cat > yara.sh <<EOF2
#!/bin/bash
# Wazuh - Yara active response
#------------------------- Gather parameters -------------------------#

# Extra arguments
read INPUT_JSON
YARA_PATH=$(echo $INPUT_JSON | jq -r .parameters.extra_args[1])
YARA_RULES=$(echo $INPUT_JSON | jq -r .parameters.extra_args[3])
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.syscheck.path)
QUARANTINE_PATH="/tmp/quarantined"

# Set LOG_FILE path
LOG_FILE="logs/active-responses.log"

size=0
actual_size=$(stat -c %s ${FILENAME})
while [ ${size} -ne ${actual_size} ]; do
    sleep 1
    size=${actual_size}
    actual_size=$(stat -c %s ${FILENAME})
done

#----------------------- Analyze parameters -----------------------#

if [[ ! $YARA_PATH ]] || [[ ! $YARA_RULES ]]
then
    echo "wazuh-yara: ERROR - Yara active response error. Yara path and rules parameters are mandatory." >> ${LOG_FILE}
    exit 1
fi

#------------------------- Main workflow --------------------------#

# Execute Yara scan on the specified filename
yara_output="$("${YARA_PATH}"/yara -C -w -r -f -m "$YARA_RULES" "$FILENAME")"

if [[ $yara_output != "" ]]
then
    # Iterate every detected rule and append it to the LOG_FILE
    while read -r line; do
        echo "wazuh-yara: INFO - Scan result: $line" >> ${LOG_FILE}
    done <<< "$yara_output"
    /usr/bin/mv -f $FILENAME ${QUARANTINE_PATH}
    FILEBASE=$(/usr/bin/basename $FILENAME)
    /usr/bin/chattr -R +i ${QUARANTINE_PATH}/${FILEBASE}
    /usr/bin/echo "wazuh-yara: $FILENAME moved to ${QUARANTINE_PATH}" >> ${LOG_FILE}
fi

exit 0;
EOF2
#####
chown root:wazuh yara.sh
chmod 750 yara.sh
mkdir /tmp/quarantined
echo "Instalation completed"
