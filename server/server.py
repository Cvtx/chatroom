import os
import sys
import socket
import json
import argparse
import time
import rsa
import logging
import typing
import os

import commands
from commands import * 

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from common.unid import UNID
import common.messages as messages
import common.settings as settings
import common.utility as utility
import common.com as com
from common.utility import * 
from common.com import *
from common.classes import * 


class Server(MessageExchanger):
    '''
        Основной класс сервера.
    '''
    def __init__(self, host, port):
        super().__init__(host, port)                
        self.clients             = ClientsManager        (self)    # Менеджер клиентов        
        self.processor           = ServerPacketProcessor (self)    # Обработка пришедших пакетов
        self.responses_processor = ResponsesProcessor    (self)    # Обработка пришедших ответов
        self.request_replier     = RequestsReplier       (self)    # Ответы на пришедшие запросы
        self.broadcast_replier   = BroadcastReplier      (self)    # Ответы на широковещательные запросы             
        self.sender              = ServerPacketSender    (self.sock)

    def __init_threads__(self):
        super().__init_threads__()
        self.sender.start()

    def __bind_socket__(self):                
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        
    def start(self):                                        
        self.sender.set_clients_manager(self.clients)        
        self.clients.launch()           # Запускаем менеджера клиентов        
        self.broadcast_replier.start()  # Запускаем поток ответов на широковещательные запросы
        self.processor.start()          # Запускаем поток обработки пакетов         
        self.__init_threads__()         # Запускаем потоки отправки и приема                             


class ClientStatus(object):

    def __init__(self) -> None:
        super().__init__()
        self.is_online = True


class Client(object):

    def __init__(self, name :str, address) -> None:
        super().__init__()
        self.name = name        
        self.address = address
        self.rsa_public_key = None
        self.status = ClientStatus()

    def set_rsa(self, rsa_public_key: rsa.PublicKey):
        self.rsa_public_key = rsa_public_key

    def get_status(self):
        return self.status


class ClientsManager(Logger):

    '''
        Менеджер клиентов. 
        Сделать бы оповещения в чате по ивентам.
    '''    
    def __init__(self, server: Server):
        super().__init__()
        self.clients = []
        self.server = server
        self.afk = QuestionerAFK(self)   
    
    def launch(self):
        self.afk.start()        

    def get_clients(self) -> typing.List[Client]:
        return self.clients

    def get_username_by_address(self, address):
        for client in self.clients:
            if client.address == address:
                return client.name
        return None

    def add_client(self, client: Client):        
        if self.is_can_be_client(client):
            self.clients.append(client)            
            message = f"{client.name} присоединился к чату. Поприветствуйте его!"                                                              
            self.info(message)
            packet = self.server.sender.get_packet(UNID.SERVER_CHAT_MESSAGE, message)                            
            self.server.sender.encrypted_broadcast(packet)                
    
    def rename_client(self, client: Client, new_name):
        if not self.is_name_taken(new_name):
            message = f"{client.name} переименовался в {new_name}."  
            self.info(message)
            client.name = new_name  
            packet = self.server.sender.get_packet(UNID.SERVER_CHAT_MESSAGE, message)                            
            self.server.sender.broadcast(packet)                

    def is_new_client(self, address):
        return not self.is_socket_taken(address)

    def get_clients_names(self):
        return [client.name for client in self.clients]
    
    def get_client_by_address(self, address):
        for client in self.clients:
            if client.address == address:
                return client
        return None

    def get_client_by_name(self, name: str):
        for client in self.clients:
            if client.name == name:
                return client
        return None

    def get_client_by_rsa(self, rsa_public_key):
        for client in self.clients:
            if client.rsa_public_key == rsa_public_key:
                return client
        return None

    def __client_removed_message__(self, name:str, reason:str):
        message = f"{name} удален с сервера. Причина: {reason}."
        self.info(message)
        packet = self.server.sender.get_packet(UNID.SERVER_CHAT_MESSAGE, message)                            
        return packet

    def remove_client(self, client_to_remove: Client, reason: str):
        for client in self.clients:
            if client == client_to_remove:
                self.clients.remove(client)
                packet = self.__client_removed_message__(client.name, reason)                
                self.server.sender.encrypted_broadcast(packet)

    def remove_client_by_name(self, name: str, reason: str):
        for client in self.clients:
            if client.name == name:
                self.clients.remove(client)
                packet = self.__client_removed_message__(client.name, reason)                
                self.server.sender.encrypted_broadcast(packet)

    def remove_client_by_address(self, address, reason: str):
        for client in self.clients:
            if client.address == address:
                self.clients.remove(client)
                packet = self.__client_removed_message__(client.name, reason)                
                self.server.sender.encrypted_broadcast  (packet)

    def is_name_taken(self, name: str):
        return name in (client.name for client in self.clients)

    def is_socket_taken(self, address):
        return address in (client.address for client in self.clients)
    
    def is_can_be_client(self, client: Client):
        return not self.is_name_taken(client.name) and not self.is_socket_taken(client.address)


class QuestionerAFK(ThreadPausable):

    def __init__(self, manager :ClientsManager):
        super().__init__()
        self.manager = manager
        self.server = manager.server                
        self.time_to_wait_response    = 10 
        self.time_between_questions   = 60 * 5 - self.time_to_wait_response               

    def run(self):
        super().run()
        upacket_afk = self.server.sender.get_packet(UNID.REQUEST, com.REQUEST_IS_ONLINE)                            
        while self.is_running:                
            time.sleep(self.time_between_questions)
            # Отправляем всем подключенным клиентам вопрос, онлайн ли они еще                        
            self.server.sender.encrypted_broadcast(upacket_afk)            
            time.sleep(self.time_to_wait_response)  # Ждем ответы от клиентов            
            self.delete_afk()
  
    # Удаляет всех клиентов, у которых статус оффлайн
    def delete_afk(self):
        self.info("Удаляем неактивных клиентов ...")        
        for client in self.manager.get_clients():
            if not client.status.is_online:            
                self.manager.remove_client(client, "Бездействие")
            else:
                client.status.is_online = False # Сразу делаем их afk-шерами
 

class ServerPacketSender(PacketSender):
    '''
        Рассылает пакеты из очереди всем клиентам, кроме источника.
        Имеет метод для рассылки ВСЕМ клиентам.     
    '''    
    def __init__(self, sock: socket.socket):
        super().__init__(sock)
        self.clients_manager = None        

    def set_clients_manager(self, clients_manager: ClientsManager):
        self.clients_manager = clients_manager

    def __get_packet__(self) -> Packet:
        return self.packets.get()

    def get_packet(self, id: int, data):
        upacket :UniversalPacket = UniversalPacket(id, data)
        upacket_json = json.dumps(upacket, cls=UniversalPacketEncoder)                    
        upacket_bytes = upacket_json.encode(settings.DEFAULT_ENCODING)
        return upacket_bytes

    def encrypted_sendto(self, upacket: bytes, client: Client):
        upacket_encrypted = EncoderRSA.encrypt(upacket, client.rsa_public_key)  
        self.sendto(upacket_encrypted, client.address)

    def broadcast(self, data: bytes):  
        for client in self.clients_manager.get_clients():
            self.sendto(data, client.address)

    def broadcast_except_source(self, data: bytes,  source):
        for client in self.clients_manager.get_clients():
            if client.address != source:                
                self.sendto(data, client.address)

    def encrypted_broadcast(self, upacket_bytes: bytes):
        for client in self.clients_manager.get_clients():                                        
            upacket_encrypted = EncoderRSA.encrypt(upacket_bytes, client.rsa_public_key)        
            self.sendto(upacket_encrypted, client.address)

    def encrypted_broadcast_except_source(self, upacket_bytes: bytes,  source):   
        for client in self.clients_manager.get_clients():    
            if client.address != source:                               
                upacket_encrypted = EncoderRSA.encrypt(upacket_bytes, client.rsa_public_key)        
                self.sendto(upacket_encrypted, client.address)

    def __remove_source_from_clients__(self, source_address):
            return (client for client in self.clients_manager.get_clients() if client.address != source_address)

    def run(self):
        super().run()
        while self.is_running:            
            while not self.is_empty():
                packet = self.__get_packet__()                
                clients_no_source = self.__remove_source_from_clients__(packet.source)
                for client in clients_no_source:                      
                    self.sendto(packet, client)


class ServerPacketProcessor(PacketProcessor):

    def __init__(self, server: Server):
        super().__init__(server)    
        self.server = server
        self.executor = ServerCommandExecutor(server)
        self.request = RequestsReplier(server)
        self.responses = ResponsesProcessor(server)

    def chat_message_packet(self, username: str, message: str):
        upacket = UniversalPacket(UNID.USER_CHAT_MESSAGE, (username, message))
        upacket_json = json.dumps(upacket, cls=UniversalPacketEncoder) 
        upacket_encoded = upacket_json.encode(settings.DEFAULT_ENCODING)        
        return upacket_encoded

    def encrypted_packet(self, id: UNID, data, public_key: rsa.PublicKey):
        upacket = UniversalPacket(id, data)
        upacket_json = json.dumps(upacket, cls=UniversalPacketEncoder)                    
        upacket_bytes = upacket_json.encode(settings.DEFAULT_ENCODING)
        upacket_json_encrypted = EncoderRSA.encrypt(upacket_bytes, public_key)
        return upacket_json_encrypted

    def packet(self, id: UNID, data):
        upacket = UniversalPacket(id, data)
        upacket_json = json.dumps(upacket, cls=UniversalPacketEncoder)                    
        upacket_bytes = upacket_json.encode(settings.DEFAULT_ENCODING)        
        return upacket_bytes

    def run(self):
        super().run()
        while self.is_running:                        
            while not self.reciever.is_empty():                                 # Цикл разбора пришедших пакетов.                        
                try:                
                    packet = self.reciever.get_packet()                             # Получаем пакет
                    is_new_client: bool = self.server.clients.is_new_client(packet.source)            
                               
                    if is_new_client:                        
                        upacket = json.loads(packet.data)
                        id = upacket["id"]
                        data = upacket["data"]   
                        if id == UNID.PUBLIC_KEY:                           
                            self.info(f"Принят запрос на подключение. {packet.source}")                        
                            pubkey = rsa.PublicKey.load_pkcs1(data)
                            self.info(f"Ключ шифрования принят. {packet.source}")
                            client = Client(get_random_username(), packet.source)
                            client.status.is_online = True
                            client.set_rsa(pubkey)                                            
                            self.info(f"Клиент авторизован. {packet.source}")
                            public_key = self.server.rsa.get_public_key().save_pkcs1()                
                            public_key_decoded = public_key.decode('utf-8') 
                            upacket_bytes = self.packet(UNID.PUBLIC_KEY, public_key_decoded)                                                                                    
                            self.server.sender.sendto(upacket_bytes, packet.source)
                            self.info(f"Ключ шифрования отправлен. {packet.source}")
                            self.server.clients.add_client(client)
                        continue                
                                        
                    if is_new_client:
                        self.info(f"Проигнорирован пакет от нового клиента {packet.source} - неправильная авторизация")
                        continue

                    upacket_bytes_decrypted = rsa.decrypt(packet.data, self.server.rsa.privkey)
                    upacket = json.loads(upacket_bytes_decrypted)
                    id = upacket["id"]
                    data = upacket["data"]

                    if id == UNID.CHAT_MESSAGE:                                                                        
                        client = self.server.clients.get_client_by_address(packet.source)
                        self.info(f'[Чат] [{client.name} {packet.source}] {data}')
                        upacket = self.chat_message_packet(client.name, data)
                        self.server.sender.encrypted_broadcast_except_source(upacket, packet.source)
                        continue                    

                    if id == UNID.COMMAND:
                        self.executor.execute(data, packet.source)
                        continue
                    
                    if id == UNID.REQUEST:
                        self.request.reply(data, packet.source)
                        continue

                    if id == UNID.RESPONSE:
                        self.responses.process(data, packet.source)                        
                        continue 

                    self.info(f"Пакет от {packet.source} не распознан | {id} {data}")                                       

                except: 
                    continue
        

class ServerCommandExecutor(CommandExecutor):

    def __init__(self, exchanger: MessageExchanger) -> None:
        super().__init__(exchanger)
        self.server: Server = exchanger

    def execute(self, command_str: str, address):

        parse_result = super().parse(command_str)
        if (parse_result):
            command, tokens, tokens_amount = parse_result
        else:
            return False

        # Проверка, действительно ли передана команда
        if command not in commands.COMMANDS_SERVER_SIDE:            
            return False
        
        # Подключение нового клиента
        if command == commands.COMMAND_JOIN:
            # Если пишет уже подключенный клиент - ничего не делаем
            if not self.server.clients.is_new_client(address):
                return True
                        
            client = Client(utility.get_random_username(), address)
            command_str = command_str.replace(commands.COMMAND_JOIN + " ", '')
            print(command_str)
            rsa_public_key = rsa.PublicKey.load_pkcs1(command_str)
            client.set_rsa(rsa_public_key)
            self.server.clients.add_client(client)  
            return True
                    
        # Отключение клиента
        if command == commands.COMMAND_QUIT:
            self.server.clients.remove_client_by_address(address, "вышел из чата.")                             
            return True

        # Переименование клиента
        if command == commands.COMMAND_RENAME:
            if tokens_amount == 1:
                new_username = tokens[0]
                self.server.clients.rename_client(address, new_username)
            return True

        # Вывод списка клиентов
        if command == commands.COMMAND_WHO:            
            client = self.server.clients.get_client_by_address(address)
            upacket = self.server.sender.get_packet(UNID.SERVER_COMMAND_RESPONSE, self.server.clients.get_clients_names())            
            self.server.sender.encrypted_sendto(upacket, client)            
            return True
                        
        return True
                        

class BroadcastReplier(ThreadPausable):
    '''
        Отвечает на широковещательные запросы
    '''
    def __init__(self, server):
        super().__init__()   
        self.server = server                          
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
        self.sock.bind(('', settings.DEFAULT_BROADCAST_PORT))

    def run(self):
        super().run()                             
        while self.is_running:
            data, address = self.sock.recvfrom(settings.DEFAULT_BUFFER_SIZE)
            data = data.decode(settings.DEFAULT_ENCODING)
            self.info(f"Получено {str(len(data))} байт от {str(address)} : {data}")
        
            # Если получен не широковещательный запрос
            if data not in com.BROADCAST_REQUESTS:
                self.info("Данные не являются запросом, пропускаем.")
                continue

            # Если запросили ip чат-комнаты
            if data == com.BROADCAST_REQUEST_IP:
                response  = com.BROADCAST_RESPONSE_IP                
                self.sock.sendto(response.encode(settings.DEFAULT_ENCODING), address)                                


class RequestsReplier(object):
    '''
        Отвечает за обработку запросов
    '''
    def __init__(self, server: Server):
        super().__init__()
        self.server = server
    
    def reply(self, message, address):

        # Если сообщение не является запросом
        if message not in com.REQUESTS:
            return False

        # Подключен ли
        if message == com.REQUEST_CONNECTED:
            if self.server.clients.is_socket_taken(address):                
                self.server.send_message(com.RESPONSE_CONNECTED, address)
            return True
                            

        return True
    

class ResponsesProcessor(Logger):
    '''
        Обрабатывает пришедшие ответы на запросы
    '''
    def __init__(self, server: Server):
        super().__init__()
        self.server = server

    def process(self, data, address):
        
        # Действительно пришел ли ответ
        if data not in com.RESPONSES:            
            return False

        # Если клиент ответил, что он онлайн
        if data == com.RESPONSE_IS_ONLINE:            
            client: Client = self.server.clients.get_client_by_address(address)
            client.status.is_online = True 
            return True

        return True
    

class ServerConsole(ThreadPausable):

    def __init__(self, server: Server):
        super().__init__()
        self.server = server
    
    def run(self):
        super().run()

        """
        Консоль, доступная только с сервера.
        Для подсказки по командам введите /help
        """
        server = self.server
        while True:

            command = input()

            tokens = command.split()
            tokens_amount = len(tokens)
            
            try:
                command = tokens[0]
            except:
                return False

            # Проверка, действительно ли передана команда
            if command not in commands.COMMANDS_SERVER_SIDE_CONSOLE:            
                continue
            
            # Подсказка по командам
            if command == commands.COMMAND_HELP:
                for command in commands.COMMANDS_SERVER_SIDE_CONSOLE_DESCRIPTIONS.keys():
                    print(f"{command} : {commands.COMMANDS_SERVER_SIDE_CONSOLE_DESCRIPTIONS[command]}")
                continue
                    
            # Кикнуть с сервера
            if command == commands.COMMAND_KICK:
                if tokens_amount == 2:
                    username = tokens[0]
                    server.clients.remove_client_by_username(username)
                continue

            # Кто на сервере?
            if command == commands.COMMAND_WHO:
                if len(server.clients.get_clients_names()) > 0:
                    print(server.clients.clients)
                else:
                    print("Никто не подключен к серверу.")
                continue
            
            # Выключить сервер
            if command == commands.COMMAND_SHUTDOWN:
                print('Закрываем все подключения...')            
                server.shutdown()
                print('Выключаем сервер...')
                os._exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Сервер чат-комнаты')
    parser.add_argument('-host', default=settings.DEFAULT, help='Интерфейс, прослушивающийся сервером')
    parser.add_argument('-p', metavar='PORT', type=int, default=settings.DEFAULT_SERVER_PORT, help='UDP port (default 1060)')
    args = parser.parse_args()

    # Небольшая настройка логгера    
    utility.setup_logger("server-log.txt", logging.INFO, __name__)    

    # Создаем и запускаем поток сервера в качестве класса-отправщика передаем ServerPacketSender, наследника PacketSender    
    server = Server(args.host, args.p)
    server.start()

    # Запускаем поток для консоли сервера
    console = ServerConsole(server)    
    console.start()