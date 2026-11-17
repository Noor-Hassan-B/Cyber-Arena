#!/bin/sh
set -e

echo "=== AegisHunt Threat Hunting Backend Initializing ==="

DB_HOST=${DB_HOST:-mysql}
DB_PORT=${DB_PORT:-3306}
DB_NAME=${DB_NAME:-threat_hunter}
DB_USER=${DB_USER:-threat_user}
DB_PASS=${DB_PASS:-threat_pass}

echo "[*] Waiting for MySQL service at ${DB_HOST}:${DB_PORT}..."

MAX_TRIES=30
TRIES=0

until php -r "
try {
    \$dbh = new PDO('mysql:host=${DB_HOST};port=${DB_PORT}', '${DB_USER}', '${DB_PASS}');
    exit(0);
} catch (Exception \$e) {
    exit(1);
}
" > /dev/null 2>&1; do
    TRIES=$((TRIES + 1))
    if [ $TRIES -ge $MAX_TRIES ]; then
        echo "[-] MySQL connection timed out after $MAX_TRIES attempts. Starting Apache with in-memory fallback mode."
        break
    fi
    echo "    Attempt $TRIES/$MAX_TRIES: MySQL not reachable yet. Retrying in 2 seconds..."
    sleep 2
done

if [ $TRIES -lt $MAX_TRIES ]; then
    echo "[✓] MySQL database connection established successfully."
    echo "[*] Running database migrations and seed script..."
    php /var/www/html/seed.php || echo "[!] Database already populated or seed encountered warning."
fi

echo "[✓] AegisHunt PHP API backend ready. Launching Apache HTTP server..."
exec apache2-foreground
