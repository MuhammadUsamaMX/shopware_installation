#!/bin/bash

# Log file location
log_file="/var/log/script.log"

# Function to log messages
log() {
    local message="$1"
    echo "$(date +"%Y-%m-%d %H:%M:%S") - $message" |  tee -a "$log_file"
}

check_internet_connection() {
    if ! ping -c 1 google.com &> /dev/null; then
        echo "No internet connection. Exiting the script."
        exit 1
    fi
}

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

# Function to install dependencies
install_dependencies() {
    log "Installing dependencies..."
    apt update
    curl -fsSL https://raw.githubusercontent.com/MuhammadUsamaMX/shopware_installation/main/node_18.x | sudo -E bash -
    apt install -y lsb-release curl openssl mysql-client iptables curl wget  nano zip ufw apache2 php-fpm php-mysql php-curl php-dom php-json php-zip php-gd php-xml php-mbstring php-intl php-opcache
    apt install -y  mariadb-server 
    apt install -y nodejs
    log "Dependencies installed."
    # Setup php8.1-fpm
    sed -i 's/memory_limit = .*/memory_limit = 512M/' /etc/php/8.1/fpm/php.ini
    sed -i 's/upload_max_filesize = .*/upload_max_filesize = 20M/' /etc/php/8.1/fpm/php.ini
    sed -i 's/max_execution_time = .*/max_execution_time = 300/' /etc/php/8.1/fpm/php.ini
    sed -i 's/;opcache.memory_consumption=128/opcache.memory_consumption=256/' /etc/php/8.1/cli/php.ini
    sed -i 's/memory_limit =.*/memory_limit = 512M/' /etc/php/8.1/cli/php.ini
    clear
}

# Function to install RainLoop Webmail
install_rainloop() {

    domain_name='webmail.'$domain_name
    
    mkdir /var/www/$domain_name
    chown -R www-data:www-data /var/www/$domain_name

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
    </VirtualHost>" | tee $vhost_file
    echo "Listen 8080" | tee -a /etc/apache2/ports.conf

    cd /var/www/$domain_name

    curl -sL https://repository.rainloop.net/installer.php | php

    a2ensite $domain_name.conf
    systemctl restart apache2
    
    echo "> Goto Cloudflare Zero Trust Dashoard https://one.dash.cloudflare.com >  Access > Tunnel > "
    sleep 5
    echo " Select Tunnel name as Shopware > Configure Tunnel"
    sleep 3
    echo "Select the Public Hostname > " 
    sleep 3
    echo "Add Public Hostname >"
    sleep 3
    echo "Enter webmail in subdomian >"
    sleep 3
    echo " Select domain >"
    sleep 2
    echo " Type HTTP >"
    sleep 2
    echo " In url add localhost:8080 >"
    sleep 2
    echo " Save te hostname"
    sleep 2
    while true; do
    echo "Type 'yes' to confirm successful completion of all above mention steps"
    read -p "" response

    if [ "$response" == "yes" ]; then
        break
    else
        echo "Please type 'yes' to confirm successful completion of all above mention steps."
    fi
    done
    
    echo -e "\e[92mCloudflare  Zero Trust access setup completed for $domain_name.\e[0m"
}

# Function to install Shopware

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

generate_self_signed_ssl() {
    echo -e "\e[92mGenerating a self-signed SSL certificate...\e[0m"
    openssl req -x509 \
            -sha256 -days 356 \
            -nodes \
            -newkey rsa:2048 \
            -subj "/CN=$domain_name/C=US/L=San Fransisco" \
            -keyout /etc/ssl/private/selfsigned.key -out /etc/ssl/certs/selfsigned.crt     
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


allow_cloudflare_ips() {
    url="https://www.cloudflare.com/ips-v4/"
    cloudflare_ips=$(curl -s "$url")

    # Allow Cloudflare IPs to access specified ports
    while IFS= read -r ip_range; do
        iptables -A INPUT -p tcp --dport 80 -s "$ip_range" -j ACCEPT
        iptables -A INPUT -p tcp --dport 443 -s "$ip_range" -j ACCEPT
        iptables -A INPUT -p tcp --dport 3306 -s "$ip_range" -j ACCEPT  # Added for port 3306 (MySQL)
    done <<< "$cloudflare_ips"

    # Drop other IPs for the specified ports
    iptables -A INPUT -p tcp --dport 80 -j DROP
    iptables -A INPUT -p tcp --dport 443 -j DROP
    iptables -A INPUT -p tcp --dport 3306 -j DROP
}

# Applying iptables rules
apply_iptables_rules() {

    internal_interfaces=("$@")
    # Allow loopback connections
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT

    # Allowing established and related incoming connections
    sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allowing established outgoing connections
    sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT

    # Allow incoming SSH connections
    sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT && sudo iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

    # Allow internal to access the external
    for int_interface in "${internal_interfaces[@]}"; do
        sudo iptables -A FORWARD -i "$int_interface" -o "$external_interface" -j ACCEPT
    done

    # Dropping invalid packets
    sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

    allow_cloudflare_ips
}

# Function to set up Cloudflare access
cloudflare_setup() {
        
    clear
    echo -e "Setting up Cloudflare Zero Trust access for $domain_name"
    
    cd /tmp/
    
    curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
    dpkg -i cloudflared.deb
    
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
    echo "Extract the Tunnel token  it's consist after cmd cloudflared service install "
    sleep 5
    read  -p "Enter Tunnel Token " token    
    
    cloudflared service install $token
    
    clear
    echo "> Press Next butten"
    echo "> Select Public Hostname "
    echo "> Add Public Hostname (subdomain section leave it  empty)"
    echo "> Select domain"
    echo "> Type HTTPS"
    echo "> In url add localhost:443"
    sleep 5
    echo "Click on Additional application settings"
    sleep 5
    echo "Select TLS"
    sleep 5
    echo "Enable No TLS Verify"
    sleep 5
    echo "> Save te hostname"
    
    while true; do
    read -p "Type 'yes' to confirm successful completion of all above mention steps" response

    if [ "$response" == "yes" ]; then
        break
    else
        echo "Please type 'yes' to confirm successful completion of all above mention steps."
    fi
    done
    echo "> Cloudflare Zero Trust access setup completed for $domain_name."
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
install_shopware() {
    
    get_domain_name  # Ask the user for the domain name

    log "Dependencies logs Start."
    install_dependencies  # Install dependencies
    log "Dependencies installed."
    log "Starting cloudflare setup."
    cloudflare_setup      # setup cloudflare
    log "Cloudflare setup Completed"

    #make dir $domain_name and download shopware
    mkdir -p /var/www/$domain_name
    wget https://github.com/shopware/web-recovery/releases/latest/download/shopware-installer.phar.php -P /var/www/$domain_name
    chown -R www-data:www-data /var/www/$domain_name
    chmod -R 755 /var/www/$domain_name
    
    #Genrate self-assign SSL
    generate_self_signed_ssl

    #setup vhost for shopware

    vhost_file_https="/etc/apache2/sites-available/default-ssl.conf"
    
    echo "<VirtualHost *:443>
        ServerAdmin webmaster@$domain_name
        DocumentRoot /var/www/$domain_name
        
        ErrorLog \${APACHE_LOG_DIR}/$domain_name_error.log
        CustomLog \${APACHE_LOG_DIR}/$domain_name_access.log combined
        
        SSLEngine on
        SSLCertificateFile /etc/ssl/certs/selfsigned.crt
        SSLCertificateKeyFile /etc/ssl/private/selfsigned.key
        
        <Directory /var/www/$domain_name>
            Options -Indexes +FollowSymLinks +MultiViews
            AllowOverride All
            Order allow,deny
            allow from all
        </Directory>
        
        # For PHP 8.1
        <FilesMatch \.php$>
            SetHandler \"proxy:unix:/run/php/php8.1-fpm.sock|fcgi://localhost/\"
        </FilesMatch>
        
        #Redirect requests from the /public URL path to /
        RewriteEngine on
        RewriteRule ^/public(/.*)?$ /$1 [R=301,L]
        RewriteCond %{SERVER_NAME} =$domain_name

    </VirtualHost>" | sudo tee $vhost_file_https
    
    #setup db for shopware
    db_password=$(openssl rand -base64 12)
    echo -e "\e[92mCreating database and user...\e[0m"
    mysql -uroot -e "CREATE DATABASE shopware;"
    mysql -uroot -e "CREATE USER shopware@'localhost' IDENTIFIED BY '$db_password';"
    mysql -uroot -e "GRANT ALL PRIVILEGES ON shopware.* TO shopware@'localhost';"
    mysql -uroot -e "FLUSH PRIVILEGES;"
    
    # Create the credentials.txt file
    echo -e "# Print DB Details\nDatabase Name: shopware\nDatabase User: shopware\nDatabase Password: $db_password" > /root/credentials.txt
    
    #relaod apache & php8.1-fpm
    sudo a2enmod rewrite
    sudo a2enmod ssl
    a2enmod rewrite
    a2ensite default-ssl
    a2enmod proxy_fcgi setenvif
    systemctl restart php8.1-fpm
    systemctl restart apache2
    clear
    
    echo "Type 'yes' to confirm successful installation of Shopware 1st installer at https://$domain_name/shopware-installer.phar.php/install (untill you get Forbidden 403 error)"
    while true; do
    read -p "" response
    if [ "$response" == "yes" ]; then
        break
    else
        echo "If you are facing bad gateway error Check cloudflare Tunnel setting in public host to make sure "
        echo "Click on Additional application settings"
        sleep 3
        echo "Enable No TLS Verify"
        sleep 3
        echo "Please type 'yes' to confirm the successful installation."
    fi
    done
    clear    

    # Update the vhost configuration files
    sed -i "s|DocumentRoot /var/www/$domain_name|DocumentRoot /var/www/$domain_name/public|g" /etc/apache2/sites-available/default-ssl.conf
    sed -i "s|<Directory /var/www/$domain_name>|<Directory /var/www/$domain_name/public>|g" /etc/apache2/sites-available/default-ssl.conf
     
    # Restart Apache
    systemctl restart apache2
    clear
    
    # Print DB Details
    echo -e "\e[92mDatabase Name: shopware\e[0m"
    echo -e "\e[92mDatabase User: shopware\e[0m"
    echo -e "\e[92mDatabase Password: $db_password\e[0m"
    # Inform the user that the file has been created
    echo "Credentials have been saved in credentials.txt"
    sleep 5
    
    echo -e "\e[92mChanges have been made. You can access the 2nd Shopware installer at https://$domain_name/installer or just refresh the page\e[0m"

    while true; do
        read -p "After installing Shopware from the 2nd installer, press 'y': " user_input
        if [ "$user_input" == "y" ]; then
            break
        fi
    done

}

# Main script
main(){

    if ! is_root; then
        echo "This script requires root privileges. Please run it with sudo."
        exit 1
    fi
    # Check the OS and it's version 
    if ! is_supported_ubuntu_version; then
        echo "This script is designed to run on Ubuntu 22.04 or above only."
        exit 1
    fi

    # Create the log file and set permissions
    touch "$log_file"
    chmod 644 "$log_file"
    log "Log file created and permissions set."
    
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
    clear

    check_internet_connection

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

}

#run main script
main
