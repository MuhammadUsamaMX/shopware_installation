#!/bin/bash

# Log file location
log_file="/var/log/script.log"

# Function to log messages
log() {
    local message="$1"
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $message" | sudo tee -a "$log_file"
}

# Create the log file and set permissions
sudo touch "$log_file"
sudo chmod 644 "$log_file"
log "Log file created and permissions set."

# Function to check if the OS is Ubuntu and version is 22.04 or above
is_supported_ubuntu_version() {
    if [ -n "$(lsb_release -a 2>/dev/null | grep 'Ubuntu')" ]; then
        ubuntu_version=$(lsb_release -r | awk '{print $2}')
        if [ "$(echo "$ubuntu_version >= 22.04" | bc)" -eq 1 ]; then
            return 0
        fi
    fi
    return 1
}

# Function to check if the script is run with root privileges
is_root() {
    if [ "$EUID" -eq 0 ]; then
        return 0
    fi
    return 1
}

# Function to get the external interface
get_external_interface() {
    external_interface=""
    # Using the 'ip route' command to determine the default route's interface
    default_interface=$(ip route | awk '/default/ {print $5}')
    if [ -n "$default_interface" ]; then
        external_interface="$default_interface"
    fi
    echo "$external_interface"
}

# Function to get the internal interfaces
get_internal_interfaces() {
    internal_interfaces=()
    # Using 'ip addr' command to find interfaces other than the external one
    interfaces=$(ip -o link show | awk -F ': ' '{print $2}')
    for interface in $interfaces; do
        if [ "$interface" != "$external_interface" ]; then
            internal_interfaces+=("$interface")
        fi
    done
    echo "${internal_interfaces[@]}"
}

# Applying iptables rules
apply_iptables_rules() {

    #Allow incomming SSH connections & block 80,443,3306
    sudo iptables -F && sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT && sudo iptables -P INPUT DROP && iptables -A INPUT -p tcp --dport 80 -j DROP &&  iptables -A INPUT -p tcp --dport 443 -j DROP && iptables -A INPUT -p tcp --dport 3306 -j DROP
   
    internal_interfaces=("$@")
    # Allow loopback connections
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT

    # Allowing established and related incoming connections
    sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allowing established outgoing connections
    sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT

    # Allow incoming SSH connections
    sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    sudo iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
 
    # Allow internal to access the external
    for int_interface in "${internal_interfaces[@]}"; do
        sudo iptables -A FORWARD -i "$int_interface" -o "$external_interface" -j ACCEPT
    done

    # Dropping invalid packets
    sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
}


# Function to install dependencies
install_dependencies() {
    log "Installing dependencies..."
    sudo apt update
    sudo apt install -y lsb-release curl openssl mysql-client iptables curl wget sudo nano zip ufw apache2 php-fpm php-mysql php-curl php-dom php-json php-zip php-gd php-xml php-mbstring php-intl php-opcache
    sudo apt install -y  mariadb-server 
    log "Dependencies installed."
    clear
}

# Ask the user for the domain name
get_domain_name() {
    read -p "Enter the domain name: " domain_name

    while true; do
    if check_a_record "$domain_name" || check_aaaa_record "$domain_name"; then
        echo "A or AAAA records exist for $domain_name."
        echo "Delete A and AAAA records from cloudflare."
        sleep 2
        echo "A or AAAA records again check after 10 seconds."
    else
        echo "No A or AAAA records found for $domain_name"
        sleep 3
        break
    fi
    sleep 10  # Sleep for 10 seconds before checking again
    done
}

check_a_record() {
  if dig +short "$1" | grep -q '^[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+'; then
    return 0  # A record exists
  else
    return 1  # A record doesn't exist
  fi
}

check_aaaa_record() {
  if dig +short AAAA "$1" | grep -qE '^[0-9a-fA-F:]+$'; then
    return 0  # AAAA record exists
  else
    return 1  # AAAA record doesn't exist
  fi
}

# Function to set up Cloudflare access
cloudflare_setup() {
    clear
    echo -e "Setting up Cloudflare Zero Trust access for $domain_name"
    
    external_interface=$(get_external_interface)
    if [ -z "$external_interface" ]; then
        echo "Could not detect the external interface."
        exit 1
    fi

    internal_interfaces=($(get_internal_interfaces))
    if [ ${#internal_interfaces[@]} -eq 0 ]; then
        echo "No internal interfaces detected."
        exit 1
    fi

    apply_iptables_rules "${internal_interfaces[@]}"
    sudo iptables-save
    sudo iptables-legacy-save

    cd /tmp/
    curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
    sudo dpkg -i cloudflared.deb
    echo "Goto Zero Trust Cloudflare  URL https://one.dash.cloudflare.com"
    sleep 5
    echo "> Access "
    sleep 5
    echo "> Tunnel "
    sleep 5
    echo "> Create Tunnel name as Shopware "
    sleep 5
    echo "> Save Tunnel"
    sleep 5
    echo "Extract the Tunnel token  it's consist after cmd sudo cloudflared service install "
    sleep 5
    read  -p "Enter Tunnel Token " token    
    sudo cloudflared service install $token
    clear
    echo "> Press Next butten"
    echo "> Select Public Hostname "
    echo "> Add Public Hostname (subdomain section leave it  empty)"
    echo "> Select domain"
    echo "> Type HTTP"
    echo "> In url add localhost:"80
    echo "> Save te hostname"
    echo "Type 'yes' to confirm successful completion of all above mention steps"
    while true; do
    
    read -p " " response

    if [ "$response" == "yes" ]; then
        break
    else
        echo "Please type 'yes' to confirm successful completion of all above mention steps."
    fi
    done

    echo "> Cloudflare Zero Trust access setup completed for $domain_name."
}

# Function to install RainLoop Webmail
install_rainloop() {

    echo -e "\e[92mOnly use subddomain for RainLoop installation (like webmail.domain.com)...\e[0m"
    
    get_domain_name  # Ask the user for the domain name

    sudo mkdir /var/www/$domain_name
    sudo cd /var/www/$domain_name
    curl -sL https://repository.rainloop.net/installer.php | sudo php
    sudo chown -R www-data:www-data /var/www/$domain_name

    vhost_file="/etc/apache2/sites-available/$domain_name.conf"
    echo "<VirtualHost *:8080>
    ServerName $domain_name
    DocumentRoot /var/www/$domain_name
    ErrorLog \${APACHE_LOG_DIR}/$domain_name_error.log
    CustomLog \${APACHE_LOG_DIR}/$domain_name_access.log combined
    <Directory /var/www/$domain_name>
        Options -Indexes +FollowSymLinks +MultiViews
        AllowOverride All
        Require all granted
    </Directory>
    # Block access to the 'data' directory
    <Directory /var/www/$domain_name/data>
        Order deny,allow
        Deny from all
    </Directory>
    # For PHP 8.1
    <FilesMatch \.php$>
        SetHandler \"proxy:unix:/run/php/php8.1-fpm.sock|fcgi://localhost/\"
    </FilesMatch>
    </VirtualHost>" | sudo tee $vhost_file
    echo "Listen 8080" | sudo tee -a /etc/apache2/ports.conf
    sudo a2ensite $domain_name.conf
    sudo systemctl restart apache2
    
    echo "> Goto Cloudflare Zero Trust Dashoard https://one.dash.cloudflare.com >  Access > Tunnel > "
    sleep 10
    echo " Select Tunnel name as Shopware > Configure Tunnel"
    sleep 5
    echo "Select the Public Hostname > " 
    sleep 5
    echo "Add Public Hostname >"
    sleep 5
    echo "Enter webmail in subdomain section >"
    sleep 5
    echo " Select domain >"
    sleep 5
    echo " Type HTTP >"
    sleep 5
    echo " In url add localhost:8080 >"
    sleep 5
    echo " Save te hostname"
    sleep 5
    while true; do
    clear
    read -p "Type 'yes' to confirm successful completion of all above mention steps" response

    if [ "$response" == "yes" ]; then
        break
    else
        echo "Please type 'yes' to confirm successful completion of all above mention steps."
    fi
    done
    
    echo -e "\e[92mCloudflare  Zero Trust access setup completed for $domain_name.\e[0m"
}

install_shopware() {
    
    get_domain_name  # Ask the user for the domain name

    log "Dependencies logs Start."
    install_dependencies  # Install dependencies
    log "Dependencies installed."
    log "Starting cloudflare setup."
    cloudflare_setup      # setup cloudflare
    log "Cloudflare setup Completed"
    
    echo -e "\e[92mInstalling Shopware 6...\e[0m"

    sudo apt update && sudo apt upgrade -y
    curl -fsSL https://raw.githubusercontent.com/MuhammadUsamaMX/node18_install/main/script.sh | sudo -E bash -
    sudo apt install -y nodejs
    sudo sed -i 's/memory_limit = .*/memory_limit = 512M/' /etc/php/8.1/fpm/php.ini
    sudo sed -i 's/upload_max_filesize = .*/upload_max_filesize = 20M/' /etc/php/8.1/fpm/php.ini
    sudo sed -i 's/max_execution_time = .*/max_execution_time = 300/' /etc/php/8.1/fpm/php.ini
    sudo mkdir -p /var/www/$domain_name
    sudo wget https://github.com/shopware/web-recovery/releases/latest/download/shopware-installer.phar.php -P /var/www/$domain_name
    sudo chown -R www-data:www-data /var/www/$domain_name
    sudo chmod -R 755 /var/www/$domain_name

    rm /etc/apache2/sites-available/000-default.conf
    vhost_file="/etc/apache2/sites-available/000-default.conf"
    echo "<VirtualHost *:80>
    ServerAdmin webmaster@$domain_name
    DocumentRoot /var/www/$domain_name

    ErrorLog \${APACHE_LOG_DIR}/$domain_name_error.log
    CustomLog \${APACHE_LOG_DIR}/$domain_name_access.log combined
    <Directory /var/www/$domain_name>
        Options -Indexes +FollowSymLinks +MultiViews
        AllowOverride All
        Order allow,deny
        allow from all
    </Directory>

    #Redirect requests from the /public URL path to /
    RewriteEngine On
    RewriteRule ^/public(/.*)?$ /$1 [R=301,L]

    # For PHP 8.1
    <FilesMatch \.php$>
        SetHandler \"proxy:unix:/run/php/php8.1-fpm.sock|fcgi://localhost/\"
    </FilesMatch>
    </VirtualHost>" | sudo tee $vhost_file


    sudo sed -i 's/;opcache.memory_consumption=128/opcache.memory_consumption=256/' /etc/php/8.1/cli/php.ini
    sudo sed -i 's/memory_limit =.*/memory_limit = 512M/' /etc/php/8.1/cli/php.ini
    sudo a2enmod rewrite
    sudo a2enmod proxy_fcgi setenvif
    sudo systemctl restart php8.1-fpm
    sudo systemctl restart apache2
    while true; do
    clear
    read -p "Type 'yes' to confirm successful installation of Shopware 1st installer at https://$domain_name/shopware-installer.phar.php/install (until you get Forbidden 403 Error)" response
    if [ "$response" == "yes" ]; then
        break
    else
        echo "Please type 'yes' to confirm the successful installation."
    fi
    done
    clear
     # Update the configuration files
    sudo sed -i "s|DocumentRoot /var/www/$domain_name|DocumentRoot /var/www/$domain_name/public|g" /etc/apache2/sites-available/000-default.conf
    echo "After getting Forbidden Error Refresh the Web page."   
    # Restart Apache
    sudo systemctl restart apache2
    
    db_password=$(openssl rand -base64 12)
    echo -e "\e[92mCreating database and user...\e[0m"
    sudo mysql -uroot -e "CREATE DATABASE shopware;"
    sudo mysql -uroot -e "CREATE USER shopware@'localhost' IDENTIFIED BY '$db_password';"
    sudo mysql -uroot -e "GRANT ALL PRIVILEGES ON shopware.* TO shopware@'localhost';"
    sudo mysql -uroot -e "FLUSH PRIVILEGES;"
   
    # Print DB Details
    echo -e "\e[92mDatabase Name: shopware\e[0m"
    echo -e "\e[92mDatabase User: shopware\e[0m"
    echo -e "\e[92mDatabase Password: $db_password\e[0m"
    
    # Create the credentials.txt file
    echo -e "# Print DB Details\nDatabase Name: shopware\nDatabase User: shopware\nDatabase Password: $db_password" > /root/credentials.txt
    
    # Inform the user that the file has been created
    echo "Credentials have been saved in credentials.txt"
    
    sleep 5
    break
    echo -e "\e[92mChanges have been made. You can access the 2nd Shopware installer at https://$domain_name/installer\e[0m"

    while true; do
        read -p "After installing Shopware from the 2nd installer, press 'y': " user_input
        if [ "$user_input" == "y" ]; then
            break
        fi
    done

}

# Main script
#Root permission check

if ! is_root; then
    echo "This script requires root privileges. Please run it with sudo."
    exit 1
fi
# Check the OS and it's version 
if ! is_supported_ubuntu_version; then
    echo "This script is designed to run on Ubuntu 22.4 or above only."
    exit 1
fi

PS3="Select an option: "
options=("Install Shopware With Zero Trust" "Install Shopware & RainLoop Webmail With Zero Trust" "Quit")
select option in "${options[@]}"; do
    case $REPLY in
    1)
        
        log "Starting Shopware installation."
        install_shopware
        log "Shopware installation completed."

        exit
        ;;
    2)
        log "Starting Shopware installation."
        install_shopware      # Install shopware6
        log "Shopware installation completed."
        log "Starting RainLoop Webmail installation."
        install_rainloop      # Install webmail_rainloop
        log "RainLoop Webmail installation completed."
        exit
        ;;
    3)
        log "Script terminated."
        exit
        ;;
    *)
        log "Invalid option. Please select a valid option."
        ;;
    esac
done
