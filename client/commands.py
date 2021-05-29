import socket
import sys
import time
import os

EMPTY_MESSAGE = ""

# Клиентские команды
COMMAND_JOIN     = "/join"
COMMAND_QUIT     = "/quit"
COMMAND_RENAME   = "/rename"
COMMAND_SEARCH   = "/search"

# Общие команды
COMMAND_HELP     = "/help"
COMMAND_SHUTDOWN = "/shutdown"
COMMAND_WHO      = "/who"

# Клиентские команды
COMMANDS_CLIENT_SIDE = (
    COMMAND_JOIN, COMMAND_QUIT, COMMAND_RENAME, COMMAND_SEARCH, COMMAND_HELP, COMMAND_SHUTDOWN
)

COMMANDS_SEND_TO_SERVER = (
    COMMAND_WHO,
)

# Подсказки клиентским командам
COMMANDS_CLIENT_SIDE_DESCRIPTIONS = {
    COMMAND_HELP   : "Выводит эту подсказку",
    COMMAND_JOIN   : "[-ip] -port | Присоединение к серверу",
    COMMAND_QUIT   : "Выход с сервера",
    COMMAND_RENAME : "-name | Поменять имя",
    COMMAND_SEARCH : "Найти серверы чат-комнат",
    COMMAND_WHO    : "Список людей на сервере",    
}