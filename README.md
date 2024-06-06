
# Farejador de Pacotes HTTP

Este é um projeto em Python que funciona como um farejador de pacotes HTTP, capaz de capturar e analisar o tráfego de rede em busca de dados sensíveis transmitidos sem criptografia. Ele pode ser útil para administradores de rede e segurança para detectar vazamentos de informações.

## Instalação
Antes de executar o projeto, você precisa instalar algumas bibliotecas Python. Certifique-se de ter o Python instalado em seu sistema. Em seguida, execute o seguinte comando para instalar as dependências:


```bash
    pip install scapy tkinter python-dotenv requests
```
Certifique-se de ter um arquivo .env no mesmo diretório que o arquivo sniffer.py com as seguintes variáveis:
```bash
    EMAIL_ADDRESS=seu_email@gmail.com
    EMAIL_PASSWORD=sua_senha
    TELEGRAM_BOT_TOKEN=seu_token_do_bot
    TELEGRAM_CHAT_ID=seu_chat_id
```

# Executando o Projeto
Para executar o farejador de pacotes HTTP, você precisa navegar até o diretório onde o projeto está localizado. Certifique-se de que o arquivo sniffer.py está na pasta do project. Em seguida, execute o seguinte comando:
```bash
   sudo python3 sniffer.py
```
O projeto iniciará a captura de pacotes HTTP na interface de rede especificada e analisará o tráfego em busca de dados sensíveis.

# Funcionalidades

## Captura de Pacotes HTTP
O projeto utiliza a biblioteca Scapy para capturar pacotes HTTP da rede. Ele filtra os pacotes HTTP para analisar apenas aqueles que contêm dados brutos (Raw), onde os dados sensíveis podem ser encontrados.
## Identificação de Dados Sensíveis
Ao capturar os pacotes HTTP, o projeto procura por uma lista de palavras-chave associadas a dados sensíveis, como nomes de usuário, senhas, números de cartão de crédito, etc. Ele identifica esses dados nos pacotes e os exibe em uma interface gráfica.

## Exibição de Dados Sensíveis
Os dados sensíveis capturados são exibidos em uma interface gráfica usando a biblioteca Tkinter. A interface mostra uma lista dos URLs dos pacotes capturados juntamente com os dados sensíveis encontrados em cada URL.
## Envio de Alertas
O projeto é capaz de enviar alertas por e-mail e pelo Telegram quando dados sensíveis são detectados. Ele utiliza as seguintes bibliotecas para realizar esse processo:
### Para E-mail
O projeto utiliza a biblioteca smtplib para enviar e-mails através do protocolo SMTP (Simple Mail Transfer Protocol). Essa biblioteca é padrão do Python e permite a comunicação com servidores de e-mail. As credenciais de e-mail são configuradas no arquivo .env para autenticar-se no servidor SMTP.
### Para Telegram
Para enviar mensagens pelo Telegram, o projeto utiliza a biblioteca requests para fazer requisições HTTP para a API do Telegram. As credenciais do bot do Telegram, incluindo o token do bot e o ID do chat, são configuradas no arquivo .env. O projeto constrói a mensagem de alerta e a envia para a API do Telegram, que encaminha a mensagem para o chat especificado.

Ambos os métodos de alerta são ativados quando dados sensíveis são detectados durante a captura de pacotes HTTP.
## Mudando a Interface de Rede
Para alterar a interface de rede utilizada para a captura de pacotes, você precisa modificar a variável interface no arquivo sniffer.py. Por padrão, ela está definida como:
```bash
  interface = "wlp4s0"
```
Substitua "wlp4s0" pelo nome da interface de rede que você deseja usar. Você pode encontrar o nome da interface executando o comando ifconfig no terminal.
## Contribuindo
Contribuições são bem-vindas! Sinta-se à vontade para abrir problemas e solicitações de melhoria.
## Licença
Este projeto é licenciado sob a MIT License.
