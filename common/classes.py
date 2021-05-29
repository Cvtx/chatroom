import os
import socket
import threading
import logging
import queue
import hashlib
import json
import rsa
import datetime

import common.com
import common.settings
import common.unid as unid


class AutoName(object):

    def __init__(self) -> None:
        super().__init__()
        self.name = self.__class__.__name__ # Автоименование по названию класса  


class Logger(AutoName):

    def __init__(self) -> None:
        super().__init__()

    def get_time(self):
        format = '%d-%m-%Y : %I:%M %p'
        time = datetime.datetime.now()
        formatted_time = time.strftime(format)
        return formatted_time

    def __log__(self, message):
        print(f"[{self.get_time()}] | [{self.name}] | {message}")

    def info(self, message):
        self.__log__(message)
        logging.info(message)
    
    def debug(self, message):
        self.__log__(message)
        logging.debug(message)

    def warning(self, message):
        self.__log__(message)
        logging.warning(message)

    def error(self, message):
        self.__log__(message)
        logging.error(message)
        

class Connection(object):
    
    def __init__(self, host, port):
        super().__init__()

        if host == common.settings.DEFAULT:
            self.host = socket.gethostbyname(socket.gethostname())   
        else:
            self.host = host
        
        if port == common.settings.DEFAULT:
            self.port = common.settings.DEFAULT_PORT
        else:    
            self.port = port


class RSA(Logger):

    def __init__(self):
        super().__init__()
        self.bits = 1024 * 4
        self.info("Генерируем ключи шифрования ... ")
        self.new_keys()

    def set_bits(self, bits: int):
        self.bits = bits

    def new_keys(self):
        (self.pubkey, self.privkey) = rsa.newkeys(self.bits, poolsize=4)

    def get_public_key(self):
        return self.pubkey

    def encrypt(self, message):
        return rsa.encrypt(message, self.pubkey)

    def decrypt(self, encrypted_message):
        return rsa.decrypt(encrypted_message, self.privkey)


class EncoderRSA():

    @staticmethod
    def encrypt(data: bytes, public_key: rsa.PublicKey):
        return rsa.encrypt(data, public_key)

    @staticmethod
    def decrypt(data: bytes, private_key: rsa.PrivateKey):
        return rsa.decrypt(data, private_key)        


class ThreadPausable(threading.Thread, Logger):
    
    def __init__(self):
        super().__init__()
        self.is_running = False        
        self.name = self.__class__.__name__ # Автоименование по названию класса  
    
    def pause(self):
        self.is_running = False    
    
    def run(self):
        self.is_running = True


class Encoder():

    @staticmethod
    def encode(data, encoding):
        return data.encode(encoding)

    @staticmethod
    def decode(data, encoding):
        return data.decode(encoding)


class Packet(object):      

    def __init__(self, source, data):
        self.source = source
        self.data: bytes   = data


class PacketQueue(ThreadPausable):
    '''
        Представляет очередь из пакетов. 
        Содержит сокет для осуществления действий с очередью пакетов.
    '''
    def __init__(self, sock: socket.socket):
        super().__init__()
        self.sock = sock
        self.packets = queue.Queue()        

    def is_empty(self) -> bool:
        return self.packets.empty()


class PacketReciever(PacketQueue):
    '''
        Получает пакеты и сохраняет их в очередь
    '''
    def __init__(self, sock: socket.socket):
        super().__init__(sock)        

    def get_packet(self) -> Packet: 
        return self.packets.get()    

    def run(self):
        """
        Получает сообщения, приходящие на сокет и сохраняет их в очередь.    
        """
        super().run()
        while self.is_running:
            try:                
                data, address = self.sock.recvfrom(common.settings.DEFAULT_BUFFER_SIZE)
                self.packets.put(Packet(address, data))
            except:                
                continue      


class EncryptedPacketReciever(PacketReciever):

    def __init__(self, sock: socket.socket):
        super().__init__(sock)
        self.private_key = None

    def set_private_key(self, private_key: rsa.PrivateKey):
        self.private_key = private_key

    def run(self):
        self.is_running = True
        while self.is_running:
            try:                
                data, address = self.sock.recvfrom(common.settings.DEFAULT_BUFFER_SIZE)
                data = EncoderRSA.decrypt(data, self.private_key)                
                self.packets.put(Packet(address, data))
            except:                
                continue      


class PacketSender(PacketQueue):
    '''
        Класс с очередью пакетов для дальнейшей отправки.     
    '''
    def __init__(self, sock: socket.socket):
        super().__init__(sock)  
    
    def add_packet(self, packet :Packet):
        self.packets.put(packet)
    
    def sendto(self, data: bytes, address):                            
        self.sock.sendto(data, address)

    def sendto_bytes(self, data: bytes, address):                            
        self.sock.sendto(data, address)        


class MessageExchanger(Connection, Logger):
    '''
        Класс, содержащий базовый функционал для приема-отправки пакетов.
        Дополнительная логика должна расширяться в наследниках.
    '''    
    def __init__(self, host, port):
        '''
        host (str): IP адрес слушающего сокета на сервере.
        port (int): Номер порта слушающего сокета на сервере.
        '''
        super().__init__(host, port)
        self.sock                = self.__init_socket__()      # Основной сокет для приема/передачи пакетов        
        self.__bind_socket__()                                 # Байнд сокета      
        self.rsa                 = RSA()                       # RSA шифрование, дешифрование            
        self.reciever            =  PacketReciever(self.sock)          
        self.name                = self.__class__.__name__     # Автоименование по названию класса                

    def __init_socket__(self):        
        return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def __bind_socket__(self):
        # Созданем UDP сокет типа AF_INET (пара ip и номера порта)                
        #self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def __init_threads__(self):
        '''
            Инициализирует поток отправки и приема пакетов, 
            должен вызываться в наследниках в самом конце настройки работы
        ''' 
        self.info(f"{self.name} запущен на {self.sock.getsockname()}")
        self.reciever.start()


class PacketProcessor(ThreadPausable):

    def __init__(self, exchanger: MessageExchanger) -> None:
        super().__init__()
        self.exchanger = exchanger
        self.reciever = exchanger.reciever        
    
    def process(self, packet: Packet):
        pass

    
class CommandExecutor(Logger):
    
    def __init__(self, exchanger: MessageExchanger) -> None:
        super().__init__()
        self.exchanger = exchanger
        self.help_dict = None

    def execute(self, command):
        pass

    def set_help(self, help_dict: dict):
        self.help_dict = help_dict

    def print_help(self):
        for command in self.help_dict.keys():
            print(f"{command} : {self.help_dict[command]}")

    def parse(self, command_str: str):
        tokens = command_str.split()                
        try:
            command = tokens[0]
        except:
            return None
        del tokens[0] # Удаляем первый токен (команду)
        tokens_amount = len(tokens) 
        return command, tokens, tokens_amount

    def shutdown(self):
        '''
            Любые действия для освобождения ресурсов.
            Наследники должны вызывать super().shutdown().
        '''
        self.info("Завершение работы ...")
        self.exchanger.sock.close()        
        os._exit(0)


class AutoSocketBinder(object):

    def __init__(self) -> None:
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.host = socket.gethostbyname(socket.gethostname())   
        self.sock.bind((self.host, 0))        

        
class UniversalPacket(object):

    def __init__(self, id: int, data) -> None:
        super().__init__()
        self.id: int   = id
        self.data      = data
    
    def get_id(self):
        return self.id

    def get_data(self):
        return self.data


class UniversalPacketEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, UniversalPacket):
            return obj.__dict__
        return json.JSONEncoder.default(self, obj)

# class UniversalPacketDecoder(json.JSONDecoder):
#     def default(self, obj):
#         if isinstance(obj, UniversalPacket):
#             return obj.__dict__
#         return json.JSONEncoder.default(self, obj)