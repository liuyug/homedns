
host=$1

if [ x"$host" = "x" ]; then
    host=www.google.com
fi

declare -A dns_provider=(
[CleanBrowsing]=185.228.168.168,185.228.169.168
[Cloudflare]=1.1.1.1
[Comodo]=8.26.56.26,8.20.247.20
[Dyn]=216.146.35.35,216.146.36.36
[Freenom]=80.80.80.80,80.80.81.81
[Google_Public_DNS]=8.8.8.8,8.8.4.4
[Norton_ConnectSafe]=199.85.126.10,199.85.127.10
[OpenDNS]=208.67.222.222,208.67.220.220,208.67.222.220,208.67.220.222
[OpenNIC]=172.98.193.42,162.248.241.94,185.121.177.177,169.239.202.202
[Quad9]=9.9.9.9,149.112.112.112
[Verisign]=64.6.64.6,64.6.65.6
[Yandex]=77.88.8.8,77.88.8.1
)

keys=${!dns_provider[@]}

for key in ${keys[@]}; do
    echo "$key (${dns_provider[$key]})"
    echo "============================================================"
    while IFS=',' read -ra IPs; do
        for ip in "${IPs[@]}"; do
            echo ${ip}
            time nslookup $host $ip
            echo "------------------------------------------------------------"
        done
    done <<< ${dns_provider[$key]}
done

exit 0


