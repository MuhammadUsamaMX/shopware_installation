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

# Function to install dependencies
install_dependencies() {
    log "Installing dependencies..."
    iptables -A INPUT -p tcp --dport 80 -j DROP &&  iptables -A INPUT -p tcp --dport 22 -j ACCEPT &&  iptables -A INPUT -p tcp --dport 443 -j DROP && iptables -A INPUT -p tcp --dport 3306 -j DROP
    sudo apt update
    sudo apt install -y lsb-release curl openssl iptables curl wget sudo nano zip ufw apache2 mariadb-server php-fpm php-mysql php-curl php-dom php-json php-zip php-gd php-xml php-mbstring php-intl php-opcache
    sudo apt install -y mysql-client
    log "Dependencies installed."
    sleep 3
    clear
}

# Function to display IP information
ipinfo() {
    curl -s ifconfig.me
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
    echo "<VirtualHost *:80>
    ServerName $domain_name
    DocumentRoot /var/www/$domain_name
    ErrorLog \${APACHE_LOG_DIR}/$domain_name_error.log
    CustomLog \${APACHE_LOG_DIR}/$domain_name_access.log combined
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/selfsigned.crt
    SSLCertificateKeyFile /etc/ssl/private/selfsigned.key
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
    sudo a2ensite $domain_name.conf

    sudo systemctl restart apache2

    cd /var/www/$domain_name
    echo "$(ipinfo)" "$domain_name" | sudo tee -a /etc/hosts

    #Genrate self-assign SSL
    generate_self_signed_ssl
    
    echo ">Goto Cloudflare Zero Trust Dashoard https://one.dash.cloudflare.com >  Access > Tunnel > "
    sleep 10
    echo " Select Tunnel name as Shopware > Configure Tunnel"
    sleep 10
    echo "\e[92select the Public Hostname > Add Public Hostname > enter webmail in subdomain section > Select domain > Type HTTPS > In url add localhost:443 \e[0m\e[91m Save te hostname\e[0m"
    sleep 10
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

# Function to install Shopware

check_a_record() {
  if dig +short "$1" | grep -q '^[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+'; then
    return 0  # A record exists
  else
    return 1  # A record doesn't exist
  fi
}

generate_self_signed_ssl() {
    echo -e "\e[92mGenerating a self-signed SSL certificate...\e[0m"
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/selfsigned.key -out /etc/ssl/certs/selfsigned.crt
}
# Function to set up Cloudflare access
cloudflare_setup() {
    clear
    echo -e "Setting up Cloudflare Zero Trust access for $domain_name"
    cd /tmp/
    curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
    sudo dpkg -i cloudflared.deb
    echo "\e[92m\e[92mGoto Zero Trust Cloudflare  URL https://one.dash.cloudflare.com"
    echo "> Access > Tunnel >  "
    echo "Create Tunnel name as Shopware  > Save Tunnel"
    echo "Extract the Tunnel token  it's consist after cmd sudo cloudflared service install "
    read  -p "Enter Tunnel Token " token    
    sudo cloudflared service install $token
    echo " Press Next butten"
    echo "> Select Public Hostname > \e[0m\e[91mAdd Public Hostname (\e[0m \e[92msubdomain section emptp > Select domain > Type HTTPS > In url add localhost:443 \e[0m\e[91m Save te hostname"
    echo -e "\e[92mCloudflare  Zero Trust access setup completed for $domain_name.\e[0m"
}

# Ask the user for the domain name
get_domain_name() {
    read -p "Enter the domain name: " domain_name

    while true; do
    if check_a_record "$domain_name"; then
        echo "A record exists for $domain_name. Exiting."
        echo "Remove A Record of $domain_name in Cloudflare"
        read -p "Have you removed the A Record and want to continue (y/n)? " user_input
        if [ "$user_input" = "y" ]; then
        break  # Exit the loop
        else
        read -p "Enter the domain name: " domain_name  # Ask again
        fi
    fi
    done
}
install_shopware() {
    get_domain_name  # Ask the user for the domain name

    log "Starting cloudflare setup."
    cloudflare_setup      # setup cloudflare
    log "Cloudflare setup Completed"
    
    echo -e "\e[92mInstalling Shopware 6...\e[0m"

    sudo apt update && sudo apt upgrade -y
    curl -fsSL https://raw.githubusercontent.com/MuhammadUsamaMX/node18_install/main/script.sh | sudo -E bash -
    sudo apt install -y nodejs npm
    sudo sed -i 's/memory_limit = .*/memory_limit = 512M/' /etc/php/8.1/fpm/php.ini
    sudo sed -i 's/upload_max_filesize = .*/upload_max_filesize = 20M/' /etc/php/8.1/fpm/php.ini
    sudo sed -i 's/max_execution_time = .*/max_execution_time = 300/' /etc/php/8.1/fpm/php.ini
    sudo mkdir -p /var/www/$domain_name
    sudo wget https://github.com/shopware/web-recovery/releases/latest/download/shopware-installer.phar.php -P /var/www/$domain_name
    sudo chown -R www-data:www-data /var/www/$domain_name
    sudo chmod -R 755 /var/www/$domain_name
    
    #Genrate self-assign SSL
    generate_self_signed_ssl
    
    vhost_file="/etc/apache2/sites-available/$domain_name.conf"
    echo "<VirtualHost *:80>
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

    #Redirect requests from the /public URL path to /
    RewriteEngine On
    RewriteRule ^/public(/.*)?$ /$1 [R=301,L]

    # For PHP 8.1
    <FilesMatch \.php$>
        SetHandler \"proxy:unix:/run/php/php8.1-fpm.sock|fcgi://localhost/\"
    </FilesMatch>
    RewriteEngine on
    RewriteCond %{SERVER_NAME} =$domain_name
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>" | sudo tee $vhost_file

    sudo a2dissite /etc/apache2/sites-enabled/000-default.conf
    sudo a2ensite $domain_name.conf
    sudo a2enmod rewrite
    sudo a2enmod proxy_fcgi setenvif
    sudo sed -i 's/;opcache.memory_consumption=128/opcache.memory_consumption=256/' /etc/php/8.1/cli/php.ini
    sudo sed -i 's/memory_limit =.*/memory_limit = 512M/' /etc/php/8.1/cli/php.ini
    sudo systemctl restart php8.1-fpm
    sudo systemctl restart apache2
    echo "$(ipinfo)" "$domain_name" | sudo tee -a /etc/hosts
    db_password=$(openssl rand -base64 12)
    echo -e "\e[92mCreating database and user...\e[0m"
    sudo mysql -uroot -e "CREATE DATABASE shopware;"
    sudo mysql -uroot -e "CREATE USER shopware@'localhost' IDENTIFIED BY '$db_password';"
    sudo mysql -uroot -e "GRANT ALL PRIVILEGES ON shopware.* TO shopware@'localhost';"
    sudo mysql -uroot -e "FLUSH PRIVILEGES;"
    echo -e "\e[92mRestarting Apache one more time...\e[0m"
    sudo systemctl restart apache2
    while true; do
    clear
    read -p "Type 'yes' to confirm successful installation of Shopware 1st installer at https://$domain_name/shopware-installer.phar.php/install" response
    if [ "$response" == "yes" ]; then
        break
    else
        echo "Please type 'yes' to confirm the successful installation."
    fi
    done
    clear
    
    
    while true; do
        echo "After the first installer, press 'yes' to remove the 'public' after $domain_name that is not changeable after installation"
        
        # Update the configuration files
        sudo sed -i "s|DocumentRoot /var/www/$domain_name|DocumentRoot /var/www/$domain_name/public|g" /etc/apache2/sites-available/$domain_name-le-ssl.conf
        sudo sed -i "s|DocumentRoot /var/www/$domain_name|DocumentRoot /var/www/$domain_name/public|g" /etc/apache2/sites-available/$domain_name.conf
        
        # Restart Apache
        sudo systemctl restart apache2
        clear

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
    done

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
        install_dependencies  # Install dependencies
        log "Dependencies installed."
        install_shopware
        log "Shopware installation completed."

        exit
        ;;
    2)
        log "Dependencies logs Start."
        install_dependencies  # Install dependencies
        log "Dependencies installed."
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