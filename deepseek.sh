#!/usr/bin/env bash
# Travium one-shot installer for Ubuntu 24.04 + aaPanel + MariaDB 11.4
#set -Eeuo pipefail

#####################################
# helpers
#####################################
log(){ printf "\033[1;34m[*]\033[0m %s\n" "$*"; }
ok(){  printf "\033[1;32m[OK]\033[0m %s\n" "$*"; }
err(){ printf "\033[1;31m[ERR]\033[0m %s\n" "$*" >&2; }
die(){ err "$*"; exit 1; }

require_root(){ [[ ${EUID:-0} -eq 0 ]] || die "Run as root."; }

# randoms
rand_pw(){ tr -dc 'A-Za-z0-9!@#%+=' </dev/urandom | head -c "${1:-24}"; }
rand_hex(){ tr -dc 'A-Fa-f0-9' </dev/urandom | head -c "${1:-32}"; }

#####################################
# parse args
#####################################
DOMAIN=""
SITE_USER=""
RECAPTCHA_PUBLIC=""
RECAPTCHA_PRIVATE=""
DEFAULT_SITE_USER="travium"
DEFAULT_RECAPTCHA_PUBLIC="6LdQ8AIsAAAAAM0SKRYd_JiGqVqxZPTYflrdPOvH"
DEFAULT_RECAPTCHA_PRIVATE="6LdQ8AIsAAAAANlEknjUf9LWLODJrpoDiHXTvPAV"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2;;
    --user) SITE_USER="${2:-}"; shift 2;;
    --recaptchaPublic) RECAPTCHA_PUBLIC="${2:-}"; shift 2;;
    --recaptchaPrivate) RECAPTCHA_PRIVATE="${2:-}"; shift 2;;
    *) die "Unknown arg: $1";;
  esac
done

[[ -n "$DOMAIN" ]] || die "Missing --domain arg."

SITE_USER="${SITE_USER:-$DEFAULT_SITE_USER}"

#####################################
# sanity checks
#####################################
require_root

[[ -r /etc/os-release ]] || die "Cannot read /etc/os-release."
. /etc/os-release
case "${ID,,}" in
  ubuntu)
    case "${VERSION_ID}" in
      24.04|22.04|20.04|18.04) : ;;
      *) die "Unsupported Ubuntu ${VERSION_ID}. Supported: 18.04, 20.04, 22.04, 24.04";;
    esac
    ;;
  debian)
    case "${VERSION_ID}" in
      13|12|11|10|9) : ;;
      *) die "Unsupported Debian ${VERSION_ID}. Supported: 9, 10, 11, 12, 13";;
    esac
    ;;
  centos|rocky|almalinux)
    case "${VERSION_ID}" in
      9*|8*|7*) : ;;
      *) die "Unsupported ${ID} ${VERSION_ID}";;
    esac
    ;;
  *)
    die "Unsupported OS: ${PRETTY_NAME:-unknown}"
    ;;
esac

export DEBIAN_FRONTEND=noninteractive
export UCF_FORCE_CONFNEW=1

#####################################
# base packages
#####################################
log "Updating packages and installing prerequisites..."
if [[ "${ID,,}" =~ ^(ubuntu|debian)$ ]]; then
    apt-get -yq update
    apt-get -yq -o Dpkg::Options::="--force-confold" dist-upgrade
    apt-get -yq install curl wget sudo ca-certificates git lsb-release jq
elif [[ "${ID,,}" =~ ^(centos|rocky|almalinux)$ ]]; then
    yum -y update
    yum -y install curl wget sudo ca-certificates git epel-release jq
fi

#####################################
# install aaPanel
#####################################
log "Installing aaPanel..."
if [[ "${ID,,}" =~ ^(ubuntu|debian)$ ]]; then
    wget -O install.sh http://www.aapanel.com/script/install-ubuntu_6.0_en.sh
    bash install.sh aapanel
else
    wget -O install.sh http://www.aapanel.com/script/install_6.0_en.sh
    bash install.sh aapanel
fi

ok "aaPanel installed successfully"

# Wait for aaPanel to start
log "Waiting for aaPanel to start..."
sleep 10

#####################################
# Configure aaPanel
#####################################
log "Configuring aaPanel..."

# Get aaPanel port and credentials
AAPANEL_PORT=$(grep -oP 'port:\s*\K\d+' /www/server/panel/data/port.pl 2>/dev/null || echo "7800")
AAPANEL_USER="admin"
AAPANEL_PASS=$(grep -oP '\w{8}$' /www/server/panel/data/admin_path.pl 2>/dev/null || echo "aa123456")

# Configure aaPanel to allow API access (optional)
btpython /www/server/panel/tools.py panel username

#####################################
# Install required software via aaPanel
#####################################
log "Installing required software via aaPanel..."

# Use bt command to install PHP, MySQL, etc.
if [[ -f "/www/server/panel/install/install_soft.sh" ]]; then
    # Install PHP 7.3 (or your preferred version)
    bash /www/server/panel/install/install_soft.sh 0 install php 73
    
    # Install MySQL/MariaDB
    bash /www/server/panel/install/install_soft.sh 0 install mysql 5.7
    
    # Install Nginx
    bash /www/server/panel/install/install_soft.sh 0 install nginx 1.24
    
    # Install phpMyAdmin
    bash /www/server/panel/install/install_soft.sh 0 install phpmyadmin 5.2
fi

sleep 10

#####################################
# Create site in aaPanel
#####################################
log "Creating website in aaPanel..."
SITE_PASS="$(rand_pw 20)"
DB_PASS="$(rand_pw 24)"

# Create MySQL database
mysql -uroot -p"$AAPANEL_PASS" -e "CREATE DATABASE IF NOT EXISTS travium_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -uroot -p"$AAPANEL_PASS" -e "CREATE USER IF NOT EXISTS 'travium_user'@'localhost' IDENTIFIED BY '$DB_PASS';"
mysql -uroot -p"$AAPANEL_PASS" -e "GRANT ALL PRIVILEGES ON travium_db.* TO 'travium_user'@'localhost';"
mysql -uroot -p"$AAPANEL_PASS" -e "FLUSH PRIVILEGES;"

# Create directory structure
WEB_ROOT="/www/wwwroot/$DOMAIN"
mkdir -p "$WEB_ROOT"
chown -R www:www "$WEB_ROOT"

# Create site using bt command
btpython <<PYTHON
import sys
sys.path.insert(0, '/www/server/panel')
import public

# Create site
site_info = public.add_site_api(
    webname="$DOMAIN,www.$DOMAIN",
    path="$WEB_ROOT",
    port=80,
    ps="Travium Site",
    ftp=False,
    sql=True,
    version="73"
)
print("Site created:", site_info)
PYTHON

# Create FTP user if needed
btpython <<PYTHON
import sys
sys.path.insert(0, '/www/server/panel')
import public

ftp_user = public.add_ftp_user_api(
    username="$SITE_USER",
    password="$SITE_PASS",
    path="$WEB_ROOT",
    ps="Travium FTP"
)
print("FTP user created:", ftp_user)
PYTHON

#####################################
# Repo checkout
#####################################
log "Cloning Travium repo..."
rm -rf "$WEB_ROOT"/* 2>/dev/null || true
cd /www/wwwroot
git clone https://github.com/Travium/Travium "$DOMAIN"
chown -R www:www "$WEB_ROOT"

log "Running composer install..."
if [[ -f "${WEB_ROOT}/composer.json" ]]; then
    cd "$WEB_ROOT"
    
    # Install Composer if not exists
    if ! command -v composer &> /dev/null; then
        curl -sS https://getcomposer.org/installer | php
        mv composer.phar /usr/local/bin/composer
        chmod +x /usr/local/bin/composer
    fi
    
    # Run composer as www user
    sudo -u www composer install --no-interaction --prefer-dist --optimize-autoloader --no-dev
    ok "Composer install finished."
else
    log "No composer.json found in ${WEB_ROOT}; skipping composer install."
fi

# ensure ownership
chown -R www:www "$WEB_ROOT"

#####################################
# Import DB if exists
#####################################
if [[ -f "${WEB_ROOT}/maindb.sql" ]]; then
    log "Importing database..."
    mysql -u travium_user -p"$DB_PASS" travium_db < "${WEB_ROOT}/maindb.sql"
    ok "Database imported."
fi

#####################################
# Patch config & frontend keys
#####################################
log "Patching config and frontend keys..."
INSTALLER_SECRET="$(rand_hex 32)"
VOTING_SECRET="$(rand_hex 16)"
RECAPTCHA_PUBLIC_EFFECTIVE="${RECAPTCHA_PUBLIC:-$DEFAULT_RECAPTCHA_PUBLIC}"
RECAPTCHA_PRIVATE_EFFECTIVE="${RECAPTCHA_PRIVATE:-$DEFAULT_RECAPTCHA_PRIVATE}"

SAMPLE_CONFIG_FILE="${WEB_ROOT}/config.sample.php"
CONFIG_FILE="${WEB_ROOT}/config.php"

if [[ -f "$SAMPLE_CONFIG_FILE" ]]; then
    cp "$SAMPLE_CONFIG_FILE" "$CONFIG_FILE"
    chown www:www "$CONFIG_FILE"

    sed -i \
      -e "s/INIT_RECAPTCHA_PUBLIC_KEY/${RECAPTCHA_PUBLIC_EFFECTIVE//\//\\/}/g" \
      -e "s/INIT_RECAPTCHA_PRIVATE_KEY/${RECAPTCHA_PRIVATE_EFFECTIVE//\//\\/}/g" \
      -e "s/INIT_DOMAIN/${DOMAIN//\//\\/}/g" \
      -e "s/INIT_MAIN_DB_PASSWORD/${DB_PASS//\//\\/}/g" \
      -e "s/INIT_INSTALLER_SECRET_KEY/${INSTALLER_SECRET//\//\\/}/g" \
      -e "s/INIT_SECRET_TOKEN/${VOTING_SECRET//\//\\/}/g" \
      "$CONFIG_FILE"
    
    # Update database connection info
    sed -i \
      -e "s/INIT_DB_HOST/localhost/g" \
      -e "s/INIT_DB_NAME/travium_db/g" \
      -e "s/INIT_DB_USER/travium_user/g" \
      "$CONFIG_FILE"
fi

# Some builds obfuscate the bundle name. Hit every homepage JS under /homepage/
find "${WEB_ROOT}/homepage" -type f -name "*.js" -print0 2>/dev/null \
  | xargs -0 -I {} sed -i "s/INIT_RECAPTCHA_PUBLIC_KEY/${RECAPTCHA_PUBLIC_EFFECTIVE//\//\\/}/g" {} || true

#####################################
# Configure Nginx for Laravel
#####################################
log "Configuring Nginx for Laravel..."
NGINX_CONF="/www/server/panel/vhost/nginx/${DOMAIN}.conf"

if [[ -f "$NGINX_CONF" ]]; then
    # Backup original config
    cp "$NGINX_CONF" "${NGINX_CONF}.backup"
    
    # Update Nginx configuration for Laravel
    cat > "$NGINX_CONF" << NGINX
server {
    listen 80;
    server_name ${DOMAIN} www.${DOMAIN};
    root ${WEB_ROOT}/public;
    index index.php index.html index.htm;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
    
    # Laravel rewrite rules
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    
    # Handle PHP
    location ~ \.php$ {
        fastcgi_pass unix:/tmp/php-cgi-73.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$realpath_root\$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_hide_header X-Powered-By;
    }
    
    # Deny access to hidden files
    location ~ /\. {
        deny all;
    }
    
    # Deny access to sensitive files
    location ~ /(\.env|\.git|\.svn|\.ht) {
        deny all;
    }
    
    # Cache static files
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|woff|woff2|ttf|svg)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
NGINX
    
    # Test and reload Nginx
    nginx -t && nginx -s reload
    ok "Nginx configured for Laravel."
fi

#####################################
# Configure PHP settings
#####################################
log "Configuring PHP settings..."
PHP_INI="/www/server/php/73/etc/php.ini"

if [[ -f "$PHP_INI" ]]; then
    sed -i \
      -e "s/^upload_max_filesize = .*/upload_max_filesize = 100M/" \
      -e "s/^post_max_size = .*/post_max_size = 100M/" \
      -e "s/^max_execution_time = .*/max_execution_time = 300/" \
      -e "s/^max_input_time = .*/max_input_time = 300/" \
      -e "s/^memory_limit = .*/memory_limit = 256M/" \
      "$PHP_INI"
    
    # Restart PHP
    /etc/init.d/php-fpm-73 restart
fi

#####################################
# Configure Laravel environment
#####################################
log "Configuring Laravel environment..."
cd "$WEB_ROOT"

# Create .env file if it doesn't exist
if [[ ! -f ".env" ]] && [[ -f ".env.example" ]]; then
    cp .env.example .env
    chown www:www .env
fi

if [[ -f ".env" ]]; then
    sed -i \
      -e "s/^APP_URL=.*/APP_URL=https:\/\/${DOMAIN}/" \
      -e "s/^DB_HOST=.*/DB_HOST=localhost/" \
      -e "s/^DB_DATABASE=.*/DB_DATABASE=travium_db/" \
      -e "s/^DB_USERNAME=.*/DB_USERNAME=travium_user/" \
      -e "s/^DB_PASSWORD=.*/DB_PASSWORD=${DB_PASS}/" \
      -e "s/^RECAPTCHA_SITE_KEY=.*/RECAPTCHA_SITE_KEY=${RECAPTCHA_PUBLIC_EFFECTIVE}/" \
      -e "s/^RECAPTCHA_SECRET_KEY=.*/RECAPTCHA_SECRET_KEY=${RECAPTCHA_PRIVATE_EFFECTIVE}/" \
      .env
    
    # Generate Laravel key
    sudo -u www php artisan key:generate
    
    # Set permissions for Laravel
    chown -R www:www "$WEB_ROOT"
    chmod -R 755 "$WEB_ROOT"
    chmod -R 775 "$WEB_ROOT/storage"
    chmod -R 775 "$WEB_ROOT/bootstrap/cache"
fi

#####################################
# systemd units for Travium engines
#####################################
log "Installing systemd units for Travium engines..."

cat >/etc/systemd/system/travium@.service <<UNIT
[Unit]
Description=Travium engine for %i
After=network.target mysql.service

[Service]
User=www
WorkingDirectory=${WEB_ROOT}
ExecStart=/usr/bin/env TRAVIUM_UNDER_SYSTEMD=1 /usr/bin/php ${WEB_ROOT}/servers/%i/include/engine.php
Type=simple
Restart=on-failure
RestartSec=2
KillMode=control-group
StandardOutput=journal
StandardError=journal
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/travium.target <<UNIT
[Unit]
Description=Travium all engines

[Install]
WantedBy=multi-user.target
UNIT

install -m 0755 -o root -g root /dev/stdin /usr/local/bin/travium-sync <<SCRIPT
#!/usr/bin/env bash
systemctl daemon-reload
set -euo pipefail
SERVERS_DIR="${WEB_ROOT}/servers"
TARGET_WANTS_DIR="/etc/systemd/system/travium.target.wants"
mkdir -p "\$TARGET_WANTS_DIR"
mapfile -t desired < <(find "\$SERVERS_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
mapfile -t current < <(find "\$TARGET_WANTS_DIR" -maxdepth 1 -type l -name 'travium@*.service' -printf '%f\n' | sed -E 's/^travium@(.+)\.service$/\1/' | sort)
for w in "\${desired[@]}"; do
  if [[ -f "\$SERVERS_DIR/\$w/include/engine.php" ]]; then
    if ! systemctl is-enabled --quiet "travium@\${w}.service"; then
      echo "Enabling travium@\${w}.service"
      systemctl enable --now "travium@\${w}.service"
      ln -sf "/etc/systemd/system/travium@.service" "\$TARGET_WANTS_DIR/travium@\${w}.service"
    fi
  fi
done
for w in "\${current[@]}"; do
  if [[ ! -d "\$SERVERS_DIR/\$w" ]]; then
    echo "Disabling travium@\${w}.service"
    systemctl disable --now "travium@\${w}.service" || true
    rm -f "\$TARGET_WANTS_DIR/travium@\${w}.service"
  fi
done
systemctl daemon-reload
SCRIPT

cat >/etc/systemd/system/travium-sync.service <<UNIT
[Unit]
Description=Sync Travium instances with /servers
After=network.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/bin/travium-sync
UNIT

cat >/etc/systemd/system/travium-sync.path <<UNIT
[Unit]
Description=Watch ${WEB_ROOT}/servers for changes

[Path]
PathModified=${WEB_ROOT}/servers
PathChanged=${WEB_ROOT}/servers

[Install]
WantedBy=multi-user.target
UNIT

chmod +x /usr/local/bin/travium-sync
systemctl daemon-reload
systemctl start travium-sync.service
systemctl enable --now travium-sync.path
systemctl enable travium.target || true

#####################################
# Set up SSL certificate
#####################################
log "Setting up SSL certificate..."
if command -v bt &> /dev/null; then
    log "Requesting Let's Encrypt SSL certificate..."
    bt << EOF
6
1
${DOMAIN}
www.${DOMAIN}

2
EOF
    sleep 5
fi

#####################################
# summary
#####################################
PUBLIC_IP="$(curl -s4 ifconfig.me || hostname -I | awk '{print $1}')"
AAPANEL_URL="http://${PUBLIC_IP}:${AAPANEL_PORT}"
INSTALL_URL="https://${DOMAIN}/install?key=${INSTALLER_SECRET}"

ok "All done."

cat <<OUT

===== aaPanel =====
URL:        ${AAPANEL_URL}
Admin user: ${AAPANEL_USER}
Password:   ${AAPANEL_PASS}

===== Website =====
URL:        https://${DOMAIN}
FTP User:   ${SITE_USER}
FTP Pass:   ${SITE_PASS}
Web Root:   ${WEB_ROOT}

===== Database =====
Database:   travium_db
User:       travium_user
Password:   ${DB_PASS}

===== Installer =====
Install URL: ${INSTALL_URL}

===== Systemd =====
Target: travium.target
Sync watcher: travium-sync.path

===== Next Steps =====
1. Access aaPanel: ${AAPANEL_URL}
2. Complete Laravel installation: ${INSTALL_URL}
3. Run migrations: sudo -u www php artisan migrate --seed
4. Create storage link: sudo -u www php artisan storage:link

OUT

# persist details for later
SETUP_CONF="/root/travium-setup.conf"
cat >"$SETUP_CONF" <<CONF
AAPANEL_URL=${AAPANEL_URL}
AAPANEL_ADMIN_USER=${AAPANEL_USER}
AAPANEL_ADMIN_PASS=${AAPANEL_PASS}
DOMAIN=${DOMAIN}
SITE_URL=https://${DOMAIN}
FTP_USER=${SITE_USER}
FTP_PASS=${SITE_PASS}
WEB_ROOT=${WEB_ROOT}
DB_NAME=travium_db
DB_USER=travium_user
DB_PASS=${DB_PASS}
INSTALLER_SECRET=${INSTALLER_SECRET}
INSTALL_URL=${INSTALL_URL}
CONF

chmod 600 "$SETUP_CONF"
ok "Saved setup details to $SETUP_CONF"

# Display aaPanel login command
echo ""
echo "To get aaPanel password again, run: bt"