#!/bin/bash

#Load Configuration
source LinSecGuard.conf

#write a function to check for log file and if doesnt exit we make it and write log in it
log_entry() {
	if [ ! -f "$LOG_FILE" ]; then
		sudo touch "$LOG_FILE"
		sudo chmod 664 "$LOG_FILE"
		sudo chown $(whoami):$(whoami) "$LOG_FILE"
		echo "$(date '+%Y-%m-%d %H:%M:%S') -📝 Log file created: $LOG_FILE" >> "$LOG_FILE"
	fi

	echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
	
	#log file can only hold 1000 lines
	max_lines=1000
	current_lines=$(wc -l < "$LOG_FILE")

	if [ "$current_lines" -gt "$max_lines" ]; then
		tail -n "$max_lines" "$LOG_FILE" > "$LOG_FILE.tmp"
		mv "$LOG_FILE.tmp" "$LOG_FILE"
	fi
}

#FUNCTIONS
#function to check ssh
check_ssh_settings() {
	log_entry "⏳Checking SSH settings..."
	
	#check if SSH is installed
	if ! command -v sshd &> /dev/null; then
		log_entry "❌ SSH is not installed. Would you like to install it? (y/n)"
		read -p "Your choice: " install_ssh
		if [[ $install_ssh == "y" || $install_ssh == "Y" ]]; then
			sudo apt update
			sudo apt install openssh-server -y
			sudo systemctl enable ssh
			sudo systemctl start ssh
			log_entry "✅ SSH has been installed and started."
		else
			log_entry "❌ SSH will not be installed. You may not be able to access this machine remotely."
			return
		fi
	else 
		log_entry "✅ SSH is already installed."
	fi

	#check if root login is disabled
	grep -q "^PermitRootLogin no" /etc/ssh/sshd_config
	if [[ $? -eq 0 ]]; then
		log_entry "✅ Root login is already disabled."
	else
		echo "Root login in enabled. Would you like to disable root login? (y/n)"
		read -p "Your choice: " disable_root
		if [[ $disable_root == "y" || $disable_root == "Y" ]]; then
			echo "Disabling root login..."
			sudo sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
			sudo systemctl restart sshd
			log_entry "✅ Root login has been disabled."
		else
			log_entry "❌ Root login will not be disabled."
		fi
	fi

	#check if SSH port has been changed
	if grep -q "^#Port $SSH_PORT" /etc/ssh/sshd_config; then
    		sudo sed -i 's/^#Port 22/Port $SSH_PORT/' /etc/ssh/sshd_config
	fi

	grep -q "^Port $SSH_PORT" /etc/ssh/sshd_config
	if [[ $? -eq 0 ]]; then
		echo "SSH is already using a custom port ($SSH_PORT)."
	else
		echo "SSH is using the default port (22). Would you like to change it to a custom port ($SSH_PORT)? (y/n)"
		read -p "Your choice: " change_port
		if [[ $change_port == "y" || $change_port == "Y" ]]; then
			echo "Changing SSH port to 22022..."
			sudo sed -i 's/^#Port 22/Port $SSH_PORT/' /etc/ssh/sshd_config 
			sudo systemctl restart sshd
			log_entry "✅ SSH port changed to $SSH_PORT."
		else
			log_entry "❌ SSH port will not be changed."
		fi
	fi
}

#function to configure firewall
configure_firewall() {
	log_entry "⏳Checking if UFW is installed..."

	#checking if it's installed
	if ! command -v ufw &> /dev/null; then
		echo "UFW is not installed. Would you like to install it? (y/n)"
		read install_ufw
		if [[ "$install_ufw" == "y" || "$install_ufw" == "Y" ]]; then
			sudo apt update
			sudo apt install ufw -y
			log_entry "✅ UFW has been installed."

			#configure UFW
			if ! sudo ufw status | grep -q "Status: active"; then
   				 sudo ufw enable
			fi
			sudo ufw default deny incoming
        		sudo ufw default allow outgoing
			log_entry "✅ UFW enabled and default settings configured."
			
			#allow default ports (SSH/HTTP/HTTPS)
			sudo ufw allow 22/tcp
			sudo ufw allow 80/tcp
			sudo ufw allow 443/tcp
			log_entry "Default ports (SSH, HTTP, HTTPS) have been allowed."
			
			#ask user which ports to allow
			echo "Enter any additional ports you want to allow (comma-separated, e.g., 8080,443):"
			read additional_ports
			if [[ -n $additional_ports ]]; then
				for port in $(echo $additional_ports | tr "," "\n"); do
					sudo ufw allow $port/tcp
					log_entry "Port $port has been allowed."
				done
			else
				log_entry "❌ No additional ports specified. Only default ports are open."
			fi
		else
			log_entry "❌ UFW will not be installed. Skipping firewall configuration."
		fi
	else
		log_entry "✅ UFW is already installed."
		#configure ufw settings
		if ! sudo ufw status | grep -q "Status: active"; then
   			 sudo ufw enable
		fi
       		sudo ufw default deny incoming
       		sudo ufw default allow outgoing
		log_entry "Firewall configured with UFW."
		
		#allow default ports (SSH/HTTP/HTTPS)
                sudo ufw allow 22/tcp
                sudo ufw allow 80/tcp
                sudo ufw allow 443/tcp
                log_entry "Default ports (SSH, HTTP, HTTPS) have been allowed."

                #ask user which ports to allow
                echo "Enter any additional ports you want to allow (comma-separated, e.g., 8080,443):"
                read additional_ports
                if [[ -n $additional_ports ]]; then
                	for port in $(echo $additional_ports | tr "," "\n"); do
                        	sudo ufw allow $port/tcp
                                log_entry "✅ Port $port has been allowed."
                        done
		else
                        log_entry "❌ No additional ports specified. Only deafult ports are open."
		fi
	fi
}

#function to check running services
check_running_services() {
	log_entry "⏳Checking running services..."

	#get a list of all running services
	services=$(systemctl list-units --type=service --state=running --no-pager --output=json)
	service_names=()

	if [ -z "$services" ]; then
		log_entry "✅ No services are currently running."
		return
	fi

	echo "Here are the running services:"
	index=1
	while IFS= read -r line; do
		service_name=$(echo "$line" | grep -oP '"unit":"\K[^"]*')
		if [[ -n "$service_name" ]]; then
			service_names+=("$service_name")
			echo "$index) $service_name"
			((index++))
		fi
	done <<< "$(echo "$services" | jq -c '.[]')"

	#ask user to select services
	echo "You can select multiple services by entering their numbers separated by space."
	read -p "Enter the numbers to manage: " -a service_numbers

	#validate user input
	selected_services=()
	for num in "${service_numbers[@]}"; do
		if [[ "$num" =~ ^[0-9]+$ ]] && (( num >= 1 && num < index )); then
			selected_services+=("${service_names[$((num-1))]}")
		else
			echo "❌ Invalid number $num, skipping."
		fi
	done

	if [ ${#selected_services[@]} -eq 0 ]; then
		echo "❌ No valid services selected. Exiting."
		return
	fi

	#ask for action
	echo "You selected the following services: ${selected_services[@]}"
	echo "What would you like to do with these services?"
	echo "1) Stop these services"
	echo "2) Restart these services"
	echo "3) Disable these services on boot"
	echo "4) Enable these sevices on boot"
	echo "5) Show detailed status of these services"
	echo "6)⛔ Exit"

	read -p "Choose an option (1-6): " option
	case $option in
		1)
			for service in ${selected_services[@]}; do
				echo "Stopping $service..."
				sudo systemctl stop "$service"
				log_entry "✅ $service has been stopped."
			done
			;;
		2)
			for service in ${selected_services[@]}; do
				echo "Restarting $service..."
				sudo systemctl restart "$service"
				log_entry "✅ $service has been restarted."
			done
			;;
		3)
			for service in ${selected_services[@]}; do
				echo "Disabling $service on boot..."
				if systemctl list-unit-files | grep -q "$service"; then
    					sudo systemctl disable "$service"
				fi
				log_entry "✅ $service will not start on boot anymore."
			done
			;;
		4)
			for service in ${selected_services[@]}; do
				echo "Enabling $service on boot..."
				sudo systemctl enable "$service"
				log_entry "✅ $service will start on boot."
			done
			;;
		5)
			for service in ${selected_services[@]}; do
				echo "📝 Showing detailed status for $service..."
				sudo systemctl status "$service"
			done
			;;
		6)
			echo "⛔ Exiting service management."
			;;
		*)
			echo "❌ Invalid option. Please select a number between 1 and 6."
			;;
	esac
}

#function to check file permissions
check_file_permissions() {
	log_entry "⏳Checking file permissions..."
	
	#get the path from user
	read -p "Enter directory or file path to check (default: /home): " user_path
	user_path=${user_path:-/home}
	echo "🗂️ Path set to $user_path"	
	#now check if exist
	if [ ! -e "$user_path" ]; then
		log_entry "⚠️  Error: The path does not exist."
		return
	fi

	echo "🔍 Scanning $user_path for insecure file permissions..."
	
	#finding file with insecure permissions
	insecure_files=$(find "$user_path" -type f \( -perm 777 -o -perm -002 \) 2>/dev/null)

	if [ -z "$insecure_files" ]; then
		log_entry "💪 No insecure files found."
		return
	fi

	echo "🚨 The following files have insecure permissions:"
	index=1
	file_list=()
	while IFS= read -r file; do
		echo "$index) $file (Permissions: $(stat -c "%a" "$file"))"
		file_list+=("$file")
		((index++))
	done <<< "$insecure_files"

	echo "What would you like to do?"
	echo "1)🔒 Fix all insecure files"
	echo "2)🔧 Select specific files to fix"
	echo "3)📝 Show details (owner, group, permissions) for all files"
	echo "4)⛔ Exit"

	read -p "Choose an option (1-4): " user_choice
	case $user_choice in
		1)
			for file in "${file_list[@]}"; do
				read -p "Enter desired file permissions (default: 664): " file_permissions
				file_permissions=${file_permissions:-664}
				chmod "$file_permissions" "$file"
				log_entry "✅ Fixed permissions for $file"
			done
			;;
		2)
			read -p "Enter file numbers to fix (space-separated): " file_numbers
			for num in $file_numbers; do
				if [[ "$num" -ge 1 && "$num" -le "${#file_list[@]}" ]]; then
					read -p "Enter desired file permissions (default: 664): " file_permissions
					file_permissions=${file_permissions:-664}
					chmod "$file_permissions" "${file_list[$((num-1))]}"
					log_entry "✅ Fixed permissions for ${file_list[$((num-1))]}"
				else
					echo "❌ Invalid selection: $num"
				fi
			done
			;;
		3)
			for file in "${file_list[@]}"; do
				ls -l "$file"
			done
			;;
		4)
			echo "⛔ Exiting."
			;;
		*)
			echo "❌ Invalid choice."
			;;
	esac
}

#function to check open ports
check_open_ports() {
		log_entry "🔍 Scanning for open ports..."

		#check if ntstat is installed if not use ss
		if command -v netstat &>/dev/null; then
			sudo netstat -tulnp | tail -n +3
		else
			log_entry "⚠️  Netstat is not installed. Using 'ss' instead..."
			sudo ss -tulnp
		fi

		#detect firewall type
		if command -v ufw &>/dev/null; then
			FIREWALL="ufw"
		elif command -v firewall-cmd &>/dev/null; then
			FIREWALL="firewalld"
		elif command -v iptables &>/dev/null; then
			FIREWALL="iptables"
		else
			echo "⚠️  No firewall found. Exiting..."
			return
		fi
	
		echo "✅ Detected firewall: $FIREWALL"

		while true; do
			echo ""
			echo "What would you like to do?"
			echo "1) Close specific ports"
			echo "2) Open a new port"
			echo "3) Show process details for open ports"
			echo "4) Exit"
			read -p "Select an option (1-4): " choice

			case $choice in
				1)
					read -p "Enter port(s) to close (comma-separated): " ports
					for port in $(echo $ports | tr ',' ' '); do
						case $FIREWALL in
							"ufw")
								sudo ufw deny $port
								;;
							"firewalld")
								sudo firewall-cmd --permanent --remove-port=$port/tcp
								sudo firewall-cmd --reload
								;;
							"iptables")
								sudo iptables -A INPUT -p tcp --dport $port -j DROP
								;;
						esac
						log_entry "✅ Port $port closed."
					done
					;;
				2)
					read -p "Enter port to open: " new_port
					case $FIREWALL in
						"ufw")
							sudo ufw allow $new_port
							;;
						"firewalld")
							sudo firewall-cmd --permanent --add-port=$new_port/tcp
							sudo firewall-cmd --reload
							;;
						"iptables")
							sudo iptables -A INPUT -p tcp --dport $new_port -j ACCEPT
							;;
					esac
					log_entry "✅ Port $new_port opened."
					;;
				3)
					echo "📝 Showing procccess details for open ports..."
					sudo lsof -i -P -n | grep LISTEN
					;;
				4)
					echo "Returning to main menu..."
					break
					;;
				*)
					echo "❌ Invalid choice. Please enter a number between 1 and 4."
					;;

			esac
		done
}

#function to check login attemps
check_login_attemps() {
	log_entry "🔍 Checking failed login attemps..."

	#detect log file based on system type
	if [[ -f /var/log/auth.log ]]; then
		LOG_FILE="/var/log/auth.log"
	elif [[ -f /var/log/secure ]]; then
		LOG_FILE="/var/log/secure"
	else
		log_entry "⚠️  No authentication log file found!"
		return
	fi

	#detect firewall type
        if command -v ufw &>/dev/null; then
        	FIREWALL="ufw"
        elif command -v firewall-cmd &>/dev/null; then
                FIREWALL="firewalld"
        elif command -v iptables &>/dev/null; then
                FIREWALL="iptables"
        else
                FIREWALL="none"
        fi
	
	echo "🗂️ Using log file: $LOG_FILE"

	while true; do
		echo ""
		echo "Options:"
		echo "1) Show last 10 failed login attemps"
		echo "2) Filtered by username"
		echo "3) Filtered bt IP"
		echo "4) Block a suspicious IP"
		echo "5) Exit"
		read -p "Select an option (1-5): " log_choice

		case $log_choice in 
			1)
				echo "📝 Last 10 failed login attemps:"
				sudo grep "Failed password" $LOG_FILE | tail -10
				;;
			2)
				read -p "Enter username to filter: " username_filter
				echo "📝 Failed attemps for user '$username_filter':"
				if [[ -n "$username_filter" ]]; then
    					sudo grep "Failed password.*$username_filter" $LOG_FILE | tail -10
				fi
				;;
			3)
				read -p "Enter IP to filter: " IP_filter
				echo "📝 Failed attemps from IP '$IP_filter':"
				if [[ -n "$IP_filter" ]]; then
    					sudo grep "Failed password.*$IP_filter" $LOG_FILE | tail -10
				fi
				;;
			4)
				read -p "Enter IP to block: " block_ip
				case $FIREWALL in
					"ufw")
						sudo ufw deny from $block_ip
						;;
					"firewalld")
						sudo firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$block_ip' reject"
						sudo firewall-cmd --reload
						;;
					"iptables")
						sudo iptables -A INPUT -s $block_ip -j DROP
						;;
					"none")
						log_entry "⚠️  No firewall detected. Cannot block IP."
						;;
				esac
				log_entry "⛔ IP $block_ip blocked."
				;;
			5)
				echo "Returning to main menu..."
				break
				;;
			*)
				echo "❌ Invalid choice. Please enter a number between 1 and 5."
				;;
		esac
	done
}

#function to check system updates
check_system_updates() {
	log_entry "🔍 Checking for system updates..."
	
	#detecting pachage manager
	if command -v apt &>/dev/null; then
		PKG_MANAGER="apt"
		UPDATE_CMD="sudo apt update"
		LIST_CMD="apt list --upgradable"
		if command -v unattended-upgrade &> /dev/null; then
   			 SECURITY_CMD="unattended-upgrade --dry-run"
		else
    		log_entry "❌ unattended-upgrade command not found."
		fi
		UPGRADE_CMD="sudo apt upgrade -y"
	elif command -v dnf &>/dev/null; then
		PKG_MANAGER="dnf"
		UPDATE_CMD="sudo dnf check-update"
		LIST_CMD="dnf list updates"
		SECURITY_CMD="dnf updateinfo list security"
		UPGRADE_CMD="sudo dnf upgrade -y"
	elif command -v yum &>/dev/null; then
		PKG_MANAGER="yum"
		UPDATE_CMD="sudo yum check-update"
		LIST_CMD="yum list updates"
		SECURITY_CMD="yum updateinfo list security"
		UPGRADE_CMD="sudo yum update -y"
	else
		log_entry "⚠️  No compatible package manager found!"
		return
	fi

	echo "🛠️ Detected package manager: $PKG_MANAGER"
	echo ""
	echo "📦 Checking available updates..."
	$UPDATE_CMD
	$LIST_CMD
	
	#installing updates
	echo ""
	read -p "🔄 Do you want to install all updates? (y/n): " install_updates
	if [[ "$install_updates" == "y" ]]; then
		echo "📥 Installing updates..."
		$UPDATE_CMD
		log_entry "✅ Updates installed successfully!"
	else
		log_entry "⏩ Skipping updates."
	fi
	
	#security updates
	echo ""
	read -p "🛡️ Do you want to check for security updates? (y/n)" check_security
	if [[ "$check_security" == "y" ]]; then
		log_entry "🛡️ Cheking security updates..."
		$SECURITY_CMD
	else
		log_entry "⏩ Skipping security update check."
	fi

	#rebooting system after update
	echo ""
	read -p "🔁 Do you want to reboot the system after updates? (y/n): " reboot_choice
	if [[ "$reboot_choice" == "y" ]]; then
		log_entry "🔁 Rebooting the system in 5 seconds..."
		sleep 5
		sudo reboot
	else
		log_entry "🚀 System update process completed without reboot."
	fi
}

#function to run all checks
run_all_checks() {
	log_entry "🚀 Starting full security check..."
	
	check_ssh_settings
	configure_firewall
	check_running_services
	check_file_permissions
	check_open_ports
	check_login_attemps
	check_system_updates

	log_entry "✅ Full security check completed!"
}



#building the main menu
while true; do
	clear
	echo "============================================================="
	echo "           🔒 Welcome to LinSecGuard!🔒"
	echo "============================================================="
	echo "      🛠️  Please select a security check:"
	echo "-------------------------------------------------------------"
	echo "   1️⃣  Check SSH Settings"
	echo "   2️⃣  Configure UFW Firewall"
	echo "   3️⃣  Check Running Services"
	echo "   4️⃣  Check File Permissions"
	echo "   5️⃣  Check Open Ports"
	echo "   6️⃣  Check Login Attemps"
	echo "   7️⃣  Check System Updates"
	echo "   8️⃣  Run All Checks"
	echo "   9️⃣  Exit"
	echo "-------------------------------------------------------------"

	read -p "👉 Enter your choice: " menu_choice

	case $menu_choice in
		1) echo "✅ You selected: Check SSH Settings"; log_entry "Checked SSH Settings"; check_ssh_settings ;;
		2) echo "✅ You selected: Configure UFW Firewall"; log_entry "Configured UFW Firewall"; configure_firewall ;;
		3) echo "✅ You selected: Check Running Services"; log_entry "Checked Running Services"; check_running_services ;;
		4) echo "✅ You selected: Check File Permissions"; log_entry "Checked File Permissions"; check_file_permissions ;;
		5) echo "✅ You selected: Check Open Ports"; log_entry "Checked Open Ports" check_open_ports ;;
		6) echo "✅ You selected: Check Login Attemps"; log_entry "Checked Login Attemps"; check_login_attemps ;;
		7) echo "✅ You selected: Check System Updates"; log_entry "Checked System Updates"; check_system_updates ;;
		8) echo "🚀 Running All Security Checks..."; log_entry "Ran All Security Checks"
			check_ssh_settings
			configure_firewall
			check_running_services
			check_file_permissions
			check_open_ports
			check_login_attemps
			check_system_updates ;;
		9) echo "👋 Exiting LinSecGuard. Stay safe!"; log_entry "Exited LinSecGuard"; exit 0 ;;
		*) echo "❌ Invalid choice! Please select a valid option." ;;
	esac

	read -p "🔄 Press Enter to return to the main menu..."
done

