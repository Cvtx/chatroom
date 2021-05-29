import os
import sys
import socket
import hashlib
import json
import rsa
import argparse
import time
import logging
import enum
import tkinter as tk # UI

import commands

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from common.unid import UNID
import common.messages as messages
import common.settings as settings
import common.utility as utility
import common.com as com
from common.utility import * 
from common.com import *
from common.classes import * 


class Status(enum.Enum):
    NOT_CONNECTED         = 0
    CONNECTED             = 1
    KEY_EXCHANGE          = 2


class Client(MessageExchanger):
    """
    Клиент.    

    Поля:                 
        sock (socket.socket): Подключенный сокет.        
        send (ClientPacketSender): Поток отправки пакетов.
        receive (ClientPacketReceiver): Поток приема пакетов.
        executor (ClientCommandExecutor) Выполнение команд:
        username (str): Имя клиента.        
    """
    def __init__(self, host, port):
        super().__init__(host, port)                        
        self.executor            = ClientCommandExecutor  (self)    # Исполнитель команд                
        self.packets_processor   = ClientPacketsProcessor (self)    # Обработчик приходящих пакетов        
        self.sender              = ClientPacketSender(self.sock)
        self.status              = Status.NOT_CONNECTED
        self.server_public_key   = None

    def __init_threads__(self):
        super().__init_threads__()
        self.sender.start()

    def __bind_socket__(self):          
        self.sock.bind((self.host, 0))

    def set_server(self, host, port):                   
        self.host = str(host)
        self.port = int(port)

    def clear_server(self):
        self.host = None
        self.port = None

    def get_server(self):
        return (self.host, self.port)         

    def start(self):
        self.sender.set_client(self)
        self.set_name()                 # Спрашиваем имя пользователя               
        self.packets_processor.start()  # Запускаем поток обработки пакетов                                
        self.__init_threads__()         # Запускаем потоки отправки и приема
        #self.info(f"Выбран сервер на сокете {self.get_server()}.")
        self.executor.set_help(commands.COMMANDS_CLIENT_SIDE_DESCRIPTIONS)                   
        return self.packets_processor

    def __set_server_public_key__(self, server_public_key: rsa.PublicKey):
        self.server_public_key = server_public_key

    def set_name(self):
        self.username = input('Ваше имя: ')                
        # Если пользователь отказался вводить имя
        if self.username == '':
            self.username = utility.get_random_username()
        
        
class ClientPacketSender(PacketSender):

    def __init__(self,  sock: socket.socket):
        super().__init__(sock)           
                 
    def set_client (self, client: Client):
        self.client = client

    def run(self):
        """
        Прослушивает ввод пользователя только в командной строке и отправляет его на сервер.
        Команда /quit закроет подключение.        
        """
        super().run()
        while self.is_running:                                
            user_input = input(f"{self.client.username}: ")
            self.process_input(user_input)
             
    def process_input_ui(self, messages: tk.Listbox , input: tk.Entry):
        user_input = input.get()
        input.delete(0, tk.END)
        messages.insert(tk.END, f"{user_input}")
        self.process_input(user_input)        

    def process_input(self, user_input: str):

        if user_input == "":     # Если пустое сообщение, ничего не делаем
            return 

        tokens = user_input.split()
        first_token = tokens[0]
        del tokens[0]
        params = tokens

        # Если передана команда, выполняем ее и пропускаем итерацию
        if self.client.executor.execute(user_input): 
            return

        if self.client.status == Status.NOT_CONNECTED:
            self.info(f"Вы не подключены к серверу. Используйте команду {commands.COMMAND_JOIN}")
            return

        # Команды для простой передачи на сервер
        if first_token in commands.COMMANDS_SEND_TO_SERVER:
            self.send_encrypted_packet_to_server(UNID.COMMAND, params)                 
            return

        # Простое сообщение в чат                       
        self.send_encrypted_packet_to_server(UNID.CHAT_MESSAGE, user_input)                 

    def send_packet_to_server(self, id: UNID, data):
        upacket : UniversalPacket = UniversalPacket(id, data)
        upacket_json = json.dumps(upacket, cls=UniversalPacketEncoder)                    
        upacket_bytes = upacket_json.encode(settings.DEFAULT_ENCODING)        
        self.send_data_to_server(upacket_bytes)
    
    def send_encrypted_packet_to_server(self, id: int, data):
        upacket : UniversalPacket = UniversalPacket(id, data)
        upacket_json = json.dumps(upacket, cls=UniversalPacketEncoder)                    
        upacket_bytes = upacket_json.encode(settings.DEFAULT_ENCODING)        
        upacket_bytes_encrypted = rsa.encrypt(upacket_bytes, self.client.server_public_key)
        self.send_data_to_server(upacket_bytes_encrypted)

    def send_data_to_server(self, data: bytes):        
        self.sendto(data, self.client.get_server())

class ClientPacketsProcessor(PacketProcessor):
    """
    Обработка пришедших пакетов.            
    """
    def __init__(self, client: Client):
        super().__init__(client)   
        self.client = client         
        self.requests_replier  = RequestsReplier(client)         
        self.messages = None # tk.Listbox с сообщениями 

    def run(self):
        """
        Разбирает пришедшие пакеты от PacketReciever.        
        """
        super().run()
        while self.is_running:        
            while not self.reciever.is_empty():                
                packet = self.reciever.get_packet()  
                if (packet.source != self.client.get_server()): 
                    self.info(f"Полученны данные от адреса {packet.address}, который не является текущим сервером {self.client.get_server()}.")
                else:
                    self.process_packet(packet)                                            

    def process_packet(self, packet: Packet):      
        # Обмен ключами                                                                   
        if self.client.status == Status.KEY_EXCHANGE:    
            upacket_bytes = packet.data
            upacket =  json.loads(upacket_bytes)
            id = upacket["id"]
            data = upacket["data"]                                            
            if id == UNID.PUBLIC_KEY:
                self.info("Получили ключ шифрования от сервера.")                                                                                       
                pubkey = rsa.PublicKey.load_pkcs1(data)
                self.client.server_public_key = pubkey
                self.info(f"Ключ шифрования сервера принят. {packet.source}")                  
                self.client.status = Status.CONNECTED
                self.info("Вы подключены к чату.")
                return
            return                

        try:            
            upacket_encrypted = packet.data
            upacket_decrypted = rsa.decrypt(upacket_encrypted, self.client.rsa.privkey)
            upacket = json.loads(upacket_decrypted)
            id = upacket["id"]
            data = upacket["data"]             
        except:
            self.info(f"Ошибка расшифровки пакета, попробуйте переподключиться к серверу.")
            return
            
        if id == UNID.REQUEST:
            self.requests_replier.reply(data)
            return                        

        if id == UNID.RESPONSE:
            return
                                    
        if id == UNID.USER_CHAT_MESSAGE:                        
            username = data[0]
            message = data[1]
            self.print_message(username, message)                                            
            return

        if id == UNID.SERVER_CHAT_MESSAGE:
            self.print_server_message(data)
            return 

        if id == UNID.SERVER_COMMAND_RESPONSE:
            print("Получили ответ на команду")
            self.print_server_command_response(data)
            return

    def info(self, message):
        super().info(message)
        if self.messages:             
            self.messages.insert(tk.END, f"{message}")            

    def print_message(self, username, message):
        print(f'\r[{username}] {message}\n{self.client.username}: ', end = '')
        if self.messages:             
            self.messages.insert(tk.END, f"[{username}] {message}")                    

    def print_server_message(self, message):
        print(f'\r[Сервер] {message}\n{self.client.username}: ', end = '')
        if self.messages:             
            self.messages.insert(tk.END, f"[Сервер] {message}")                    

    def print_server_command_response(self, message):
        print(f'\r[*] {message}\n{self.client.username}: ', end = '')
        if self.messages:             
            self.messages.insert(tk.END, f"[*] {message}")  


class ClientCommandExecutor (CommandExecutor):
    '''
        Осуществляет исполнение команд на клиенте
    '''
    def __init__(self, client: Client):
        super().__init__(client)
        self.client = client  
        
    def execute(self, command):

        parse_result = super().parse(command)
        if parse_result:
            command, tokens, tokens_amount = parse_result
        else:
            return False 
        
        # Команда из тех, которые надо просто передать на сервер?
        if command in commands.COMMANDS_SEND_TO_SERVER:    
            self.client.sender.send_encrypted_packet_to_server(UNID.COMMAND, command)                 
            return True

        # Действительно ли передана команда?
        if command not in commands.COMMANDS_CLIENT_SIDE:            
            return False
        
        # Присоединение к серверу
        if command == commands.COMMAND_JOIN:                        
            if tokens_amount == 1:
                host = socket.gethostbyname(socket.gethostname())
                port = tokens[0]
                self.connect(host, port)
            elif tokens_amount == 2:
                host = tokens[0]
                port = tokens[1]
                self.connect(host, port)
            return True
        
        # Подсказка по командам
        if command == commands.COMMAND_HELP:
            self.print_help()
            return True
        
        # Поиск серверов
        if command == commands.COMMAND_SEARCH:
            self.search()
            return True

        # Выход с сервера
        if command == commands.COMMAND_QUIT:            
            self.quit()
            return True

        # Поменять имя
        if command == commands.COMMAND_RENAME:
            if tokens_amount == 1:
                username = tokens[0]                
                self.rename(username)
            return True

        # Завершение работы
        if command == commands.COMMAND_SHUTDOWN:                      
            self.shutdown() 
            return True
                
        return True

    def __create_broadcast_socket__(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(5)
        return sock 

    def connect(self, host, port):
        self.client.set_server(host, port)  
        self.client.status = Status.KEY_EXCHANGE
        public_key = self.client.rsa.get_public_key().save_pkcs1()                
        public_key_decoded = public_key.decode('utf-8')
        public_key_bytes_sha256 = hashlib.sha256(public_key).hexdigest()
        data = (public_key, public_key_bytes_sha256)
        self.client.sender.send_packet_to_server(UNID.PUBLIC_KEY, public_key_decoded)             

    def quit(self):  
        self.client.status = Status.NOT_CONNECTED              
        self.client.sender.send_encrypted_packet_to_server(UNID.COMMAND, commands.COMMAND_QUIT)
        self.client.clear_server()

    def search(self):        
        sock = self.__create_broadcast_socket__()        
        server_address = ("255.255.255.255", settings.DEFAULT_BROADCAST_PORT) # Выбранный broadcast адрес
        message = com.BROADCAST_REQUEST_IP.encode(settings.DEFAULT_ENCODING)  # В качестве сообщения запрашиваем IP чат-комнат
        attempts = 3                                                          # Попыток, прежде чем найти сервер
        timeout = 7                                                           # Сколько ждать ответа в каждую попытку
        found_server = False                                                  # Найден ли хоть один сервер
        action = "Поиск серверов"                                             # Название действия, надо бы рефактор
        attempt = 1                                                           # Номер попытки
        try:
            while attempt < attempts and not found_server:                          
                self.info(f"{action} | Попытка №{attempt}") 
                attempt += 1                                 
                sock.sendto(message, server_address)   # Отправляем широковещательный запрос                                                
                stop_wait_responses_time = time.time() + timeout
                # Ждем ответ
                while time.time() < stop_wait_responses_time:
                    try:                         
                        data, server = sock.recvfrom(4096)  # Ждем ответа
                        decoded_data = data.decode(settings.DEFAULT_ENCODING)
                        if  decoded_data == com.BROADCAST_RESPONSE_IP: 
                            found_server = True  
                            self.info(f"{action} | IP Сервера: {str(server[0])} {server[1]}")                                  
                        else:
                            self.info(f"{action} | Получили сообщение {decoded_data}, но сообщение не распознано ...")
                    except: 
                        if attempts > 1:               
                            self.info(f"{action} | Превышено время ожидания ...")
        finally:            
            sock.close()
            if found_server:
                self.info(f"{action} | Команда завершена.")	
            else:
                self.info(f"{action} | Сервера не найдены.")

    def shutdown(self):
        self.quit()
        super().shutdown()

    def rename(self, username):  
        self.client.username = username         
        self.send_command_to_server(commands.COMMAND_RENAME, username)             
    
    def send_command_to_server(self, command, tokens):
        self.client.sender.send_encrypted_packet_to_server(UNID.COMMAND, f"{command} {tokens}" )

class RequestsReplier(object):      
    '''
        Отвечает за обработку запросов
    '''
    def __init__(self, client: Client):
        super().__init__()
        self.client = client
    
    def reply(self, message):
    
        # Сообщение является запросом?
        if message not in com.REQUESTS:            
            return False

        # Онлайн ли мы?
        if message == com.REQUEST_IS_ONLINE:                           
            self.client.sender.send_encrypted_packet_to_server(UNID.RESPONSE, com.RESPONSE_IS_ONLINE)
            return True                       
                            
        return True


def main(host, port):
    """
    GUI приложение.

    Аргументы:
        host (str): IP адрес слушающего сокета на сервере.
        port (int): Номер порта слушающего сокута на сервере.
    """
    client = Client(host, port)
    client.start()

    window = tk.Tk()
    window.title('Чат')

    frm_messages = tk.Frame(master=window)
    scrollbar = tk.Scrollbar(master=frm_messages)
    messages = tk.Listbox(
        master=frm_messages, 
        yscrollcommand=scrollbar.set
    )
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y, expand=False)
    messages.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    client.packets_processor.messages = messages 

    frm_messages.grid(row=0, column=0, columnspan=2, sticky="nsew")

    frm_entry = tk.Frame(master=window)
    text_input = tk.Entry(master=frm_entry)
    text_input.pack(fill=tk.BOTH, expand=True)
    text_input.bind("<Return>", lambda x: client.sender.process_input_ui(messages, text_input))
    text_input.insert(0, "Ваше сообщение.")

    btn_send = tk.Button(
        master=window,
        text='Отправить',
        command=lambda: client.send(text_input)
    )

    frm_entry.grid(row=1, column=0, padx=10, sticky="ew")
    btn_send.grid(row=1, column=1, pady=10, sticky="ew")

    window.rowconfigure(0, minsize=500, weight=1)
    window.rowconfigure(1, minsize=50, weight=0)
    window.columnconfigure(0, minsize=500, weight=1)
    window.columnconfigure(1, minsize=200, weight=0)

    window.mainloop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Клиент чат-комнты')
    parser.add_argument('-host', default=settings.DEFAULT,help='Интерфейс, прослушивающийся сервером')
    parser.add_argument('-p', metavar='PORT', type=int, default=settings.DEFAULT_CLIENT_PORT, help='UDP port (default 1060)')
    args = parser.parse_args()

    # Небольшая настройка логгера    
    utility.setup_logger("client-log.txt", logging.INFO, __name__)    

    main(args.host, args.p)   