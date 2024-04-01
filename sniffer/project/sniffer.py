from scapy.all import *
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from urllib import parse
import os
from scapy.layers.inet import TCP

interface = "lo"

def filter_HTTP(pkt):return TCP in pkt and (pkt[TCP].dport == 5001 or pkt[TCP].sport == 5001)  # Capture on default HTTP port (80)

SENSITIVE_DATA = {
    "login": ["username", "user", "nome", "user name", "fname"],
    "senha": ["password", "pass", "pwd", "passwd", "senha"],
    "cartão de crédito": ["cc", "credit card", "card number", "card num", "creditcard"],
    "cvv": ["cvv", "cvc", "security code", "sec code", "cvv code"],
    "cpf": ["cpf", "CPF", "C.P.F."],
    "email": ["email", "e-mail", "mail"],
    "data de nascimento": ["birth date", "birthdate", "date of birth", "bday", "birth day", "data de nasc",
                           "aniversario"],
}

save_dir = "/home/gengar/PycharmProjects/sniffer/captures"
os.makedirs(save_dir, exist_ok=True)

print("1) Captura iniciada...")
packets = sniff(iface=interface, count=20, lfilter=filter_HTTP)

sensitive_data_found = {}
json_packets = []
for pkt in packets:
    print("-" * 40)
    print(f"**Pacote capturado:**")
    print(pkt.summary())
    print(pkt.show())
    url = ""
    body = ""
    method = ""
    if Raw in pkt:
        load = pkt[Raw].load.lower()
        try:
            http_packet = HTTP(load)
            if http_packet.haslayer(HTTPRequest):
                url = parse.unquote(
                    http_packet[HTTPRequest].Host.decode() + http_packet[HTTPRequest].Path.decode() + "?" +
                    http_packet[HTTPRequest].Query.decode()
                )
                method = http_packet[HTTPRequest].Method.decode()
            if http_packet.haslayer(HTTPResponse):
                body = http_packet[HTTPResponse].Body.decode(errors='ignore')
            for key, values in SENSITIVE_DATA.items():
                for value in values:
                    if value in load:
                        print(f"[!] Sensitive data '{value}' found in packet:")
                        print(pkt.show())
                        if key not in sensitive_data_found:
                            sensitive_data_found[key] = []
                        # Add location information ("Raw" or "Body")
                        sensitive_data_found[key].append((url, value, method, "Raw"))
        except:
            pass
    for key, values in SENSITIVE_DATA.items():
        for value in values:
            if value in url.lower() or value in body:
                if key not in sensitive_data_found:
                    sensitive_data_found[key] = []
                sensitive_data_found[key].append((url, value, method, "Body"))
    print("-" * 40)

for key, data in sensitive_data_found.items():
    print(f"**Dados sensíveis encontrados ({key}):**")
    for url, value, method, location in data:
        print(f"• URL: {url}, Dado sensível: {value}, Método: {method}, Localização: {location}")
        if location == "Raw":
            load = url.split('&')
            for i in load:
                if value in i:
                    print(f"    - {i.replace('+', ' ')}")

filename = "captura_completa.pcap"
filepath = os.path.join(save_dir, filename)
wrpcap(filepath, packets)

print(f"**Captura salva: {filepath}")
print("...Captura finalizada!")