import socket
import sys
import time
import os

EMPTY_MESSAGE = ""

# Команды в консоли сервера
COMMAND_KICK      = "/kick"
COMMAND_HELP     = "/help"
COMMAND_SHUTDOWN = "/shutdown"
COMMAND_WHO      = "/who"

# Клиентские команды, на которые сервер реагирует при отправки клиентом
COMMAND_JOIN     = "/join"
COMMAND_QUIT     = "/quit"
COMMAND_RENAME   = "/rename"
COMMAND_SEARCH   = "/search"

# Клиентские команды, на которые сервер реагирует при отправки клиентом
COMMANDS_SERVER_SIDE = (
    COMMAND_JOIN, COMMAND_QUIT, COMMAND_RENAME, COMMAND_SEARCH, 
    COMMAND_WHO, COMMAND_HELP
)
# Команды в консоли сервера
COMMANDS_SERVER_SIDE_CONSOLE = (
    COMMAND_SHUTDOWN, COMMAND_WHO, COMMAND_KICK
)

# Подсказки к командам в консоли сервера 
COMMANDS_SERVER_SIDE_CONSOLE_DESCRIPTIONS = {
    COMMAND_HELP : "Выводит эту подсказку.",
    COMMAND_KICK : "Выкинуть с сервера по имени клиента",
    COMMAND_WHO  : "Выводит список клиентов",

}