# watch-this

## Surveiller les tentatives de connexions SSH

### Avec les logs

- Installation de rsyslog pour avoir `auth.log`
- Installation de ccze pour une mise en page un peu plus human friendly
```BASH
sudo apt update && sudo apt full-ugrade -y && \
sudo apt install rsyslog ccze lnav
```

- Visualisation en direct via `tail -f` et `ccze`
```BASH
sudo tail -f /var/log/auth.log | ccze
```

- Afficher les tentatives de connexions par IP
```BASH
echo -e "Occurrences   | IP Address"
echo "-------------------------------"
awk '
/sshd\[.*\]: Invalid user|Failed password/ {
    if (match($0, /from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/, arr)) {
        ip_count[arr[1]]++
    }
}
END {
    for (ip in ip_count) {
        printf "%-13s | %-15s\n", ip_count[ip], ip
    }
}' /var/log/auth.log | sort -nr
```

- Afficher les tentatives de connexion par usernames
```BASH
echo -e "Occurrences   | Username" && \
echo "-------------------------------------------" && \
awk '/sshd\[.*\]: Invalid user/ {count[$6]++} END {for (user in count) printf "%-13s | %s\n", count[user], user}' /var/log/auth.log | sort -nr
```

- Afficher les noms d'utilisateurs tentés par addresses IPv4 sources
```BASH
echo -e "Occurrences   | IP Address      | Usernames"
echo "------------------------------------------------------------"
awk '
/sshd\[.*\]: Invalid user/ {
    if (match($0, /Invalid user ([^ ]+) from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/, arr)) {
        ip_count[arr[2]]++                     # Comptage global de l’IP
        user_attempts[arr[2], arr[1]]++         # Comptage par (IP, username)
        if (!seen[arr[2], arr[1]]) {
            user_list[arr[2]] = user_list[arr[2]] (user_list[arr[2]] ? ", " : "") arr[1]
            seen[arr[2], arr[1]] = 1
        }
    }
}
END {
    for (ip in ip_count) {
        printf "%-13s | %-15s | %s\n", ip_count[ip], ip, user_list[ip]
    }
}' /var/log/auth.log | sort -nr
```

### Avec le réseau

- Installation de tcpdump
```BASH
sudo apt install tcpdump
```

- Utilisation de tcpdump pour afficher les connexions ssh et exclure son IPv4
```BASH
sudo tcpdump -i eth0 -n -vv port 22 and not host 188.231.29.5
```

- Possibilité de stocker le rendu de cette commande dans un fichier (pour tests et analyse)
```BASH
sudo tcpdump -i eth0 port 22 and not host 188.231.29.5 -w tcpdump-ssh.pcap
```

*BONUS*

- Utilisation de screen pour garder la caoture active même après avoir fermé la session SSH
```BASH
screen -S tcpdump-ssh
```

- Pour se détacher de la session screen `CTRL+A+D` (aka. revenir au terminal de base)

- Pour lister les sessions screen existantes
```BASH
screen -ls
```

- Pour se rattacher à une session screen
```BASH
screen -r tcpdump-ssh
```

- Pour supprimer une session screen en cours
```BASH
screen -XS tcpdump-ssh quit
```

## WHOIS

### WHOIS - auth.log

- Installation de WHOIS
```BASH
sudo apt install whois
```

- Enrichissement des logs 
```BASH
grep -E "Failed password|Invalid user" /var/log/auth.log \
  | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
  | sort | uniq \
  | while read ip; do
    echo "=== $ip ==="
    whois $ip | grep -Ei '^(OrgName|organisation|netname|descr|country|OrgId|CIDR|inetnum)'
    echo ""
done
```

### WHOIS - TCPDUMP

- Installation de tshark
```BASH
sudo apt install tshark
```

- Pour enrichissement des logs
```BASH
tshark -r ssh_traffic.pcap -Y "tcp.dstport == 22" -T fields -e ip.src \
  | sort | uniq \
  | while read ip; do
    echo "=== $ip ==="
    whois $ip | grep -Ei '^(OrgName|organisation|netname|descr|country|OrgId|CIDR|inetnum)'
    echo ""
done
```

## Maxmind GeoIP

> Maxmind GeoIP est 

- Rendez-vous sur maxmind.com
- Création d'un compte pour accéder à la base GeoLite2
- Aller sur My License Key et générer une clé et la sauvegarder !

- Télécharger le dpkg depuis [github/maxmind/geoipupdate](https://github.com/maxmind/geoipupdate?tab=readme-ov-file#installing-on-ubuntu-or-debian-via-the-deb)
```BASH
wget -P /tmp https://github.com/maxmind/geoipupdate/releases/download/v7.1.0/geoipupdate_7.1.0_linux_amd64.deb
```

- Installer le dpkg
```BASH
sudo dpkg -i /tmp/geoipupdate_7.1.0_linux_amd64.deb
```

- Modifier le fichier de configuration `/etc/GeoIP.conf` et renseigner
	- Account ID
	- License Key
- Puis
```BASH
sudo geoipupdate
```
### Mise en place de l'environnement Python

> Avec quelques scripts Python, tentons d'exploiter ce que nous observons.

**Environnement de travail**

- Installation de pip et venv
```BASH
sudo apt install python3-pip python3-venv
```

- Création d'un environnement virtuel sous Python
```BASH
python3 -m venv ~/geoip_env
```

- Activation de l'environnement virtuel
```BASH
source ~/geoip_env/bin/activate
```

- Installation des dépendances
```PYTHON
pip install pandas geoip2 folium
```

- Si besoin de quitter le venv
```PYTHON
deactivate
```

**Scripts**

- Création d'un script Python `geoip-to-csv.py` pour enrichir nos IPv4 publiques avec la géolocalisation de Maxmind GeoIP.
```PYTHON
import geoip2.database
import pandas as pd
import sys
import os

# Check args 
if len(sys.argv) != 2:
    print("Usage : python geoip_to_csv.py <fichier_ip.txt>")
    sys.exit(1)

input_file = sys.argv[1]

# Does this file exist ?
if not os.path.isfile(input_file):
    print(f"No such file : {input_file}")
    sys.exit(1)

# Load the IPs
with open(input_file) as f:
    ips = [line.strip() for line in f if line.strip()]

# Load the GeoIP mmdb 
reader = geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-City.mmdb')

results = []
for ip in ips:
    try:
        r = reader.city(ip)
        results.append({
            'ip': ip,
            'country': r.country.name,
            'city': r.city.name,
            'latitude': r.location.latitude,
            'longitude': r.location.longitude
        })
    except:
        continue

reader.close()

# Generate CSV
output_file = "geoip-results.csv"
pd.DataFrame(results).to_csv(output_file, index=False)
print(f"CSV file generated : {output_file}")
```

- Création d'un script Python `csv-to-map.py` pour créer une carte agrémenté de la géolocalisation de nos IPv4 publiques.
```PYTHON
import folium
import pandas as pd
import sys
import os

# Check arg
if len(sys.argv) != 2:
    print("Usage : python geoip_to_map.py <fichier_csv>")
    sys.exit(1)

input_file = sys.argv[1]

# Check if file exist
if not os.path.isfile(input_file):
    print(f"No such file : {input_file}")
    sys.exit(1)

# Load CSV
df = pd.read_csv(input_file)

# Create map
m = folium.Map(location=[20, 0], zoom_start=2)

# Add points 
for _, row in df.iterrows():
    if pd.notna(row['latitude']) and pd.notna(row['longitude']):
        folium.Marker(
            location=[row['latitude'], row['longitude']],
            popup=f"{row['ip']} ({row.get('country', '')})",
            icon=folium.Icon(color='red')
        ).add_to(m)

# Save as HTML
output_file = "connections-map.html"
m.save(output_file)
print(f"Map saved : {output_file}")
```

### GeoIP - auth.log

#### Création de la carte

> L'environnement est en place, passons à l'analyse.

- Exporter les IP vues dans `auth.log`.
```BASH
grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' /var/log/auth.log | sort | uniq > authlog-ips.csv
```

**Depuis le venv**

- Lancement du premier script pour l'enrichissement des IP
```PYTHON
python geoip-to-csv.py authlogs-ips.csv
```

- Lancement du second script pour générer la carte
```PYTHON
python csv-to-map.py geoip-results.csv
```

#### Observation de la carte

- Téléchargement du fichier pour lecture sur votre poste en local (commande à lancer depuis votre machine personnelle)
```BASH
scp username@azure-vm:/home/username/connections-map.html authlog-connection-map-$(date +%F).html
```

### GeoIP - TCPDUMP

#### Création de la carte 

- Extraction des IPs contenues dans la capture
```BASH
tshark -r tcpdump-ssh.pcap -T fields -e ip.src -e ip.dst \
  | tr '\t' '\n' \
  | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
  | sort -u > tcpdump-ips.csv
```

**Depuis le venv**

- Lancement du premier script pour l'enrichissement des IP
```PYTHON
python geoip-to-csv.py tcpdump-ips.csv
```

- Lancement du second script pour générer la carte
```PYTHON
python csv-to-map.py geoip-results.csv
```

#### Observation de la carte

- Téléchargement du fichier pour lecture sur votre poste en local (commande à lancer depuis votre machine personnelle)
```BASH
scp username@azure-vm:/home/username/connections-map.html tcpdump-connection-map-$(date +%F).html
