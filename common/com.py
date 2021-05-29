# Отличие команд от запросов и ответов, в том, что первое отправялет пользователь, а
# второе автоматизировано или используется внутри системы

def request(message):
    return "?" + message

def response(message):
    return "!" + message

#/////////////////////////////////////////////////
# Юникаст

IS_ONLINE             = "IS_ONLINE"
CONNECTED             = "CONNECTED"
GET_CHATROOM_SOCKET   = "GET_CHATROOM_SOCKET"

# Запросы (requests)
REQUEST_CONNECTED     = request(CONNECTED)
REQUEST_IS_ONLINE     = request(IS_ONLINE)
REQUEST_GET_CHATROOM_SOCKET = request(GET_CHATROOM_SOCKET)

REQUESTS              = (
    REQUEST_IS_ONLINE, REQUEST_CONNECTED, REQUEST_GET_CHATROOM_SOCKET
)

# Ответы (responses)
RESPONSE_CONNECTED    = response(CONNECTED)
RESPONSE_IS_ONLINE    = response(IS_ONLINE)
RESPONSE_GET_CHATROOM_SOCKET = response(GET_CHATROOM_SOCKET)

RESPONSES             = (
    RESPONSE_IS_ONLINE, RESPONSE_CONNECTED, RESPONSE_GET_CHATROOM_SOCKET
)    

#/////////////////////////////////////////////////
# Специальное
SERVICE_CHATROOM_SOCKET = "SERVER_CHATROOM_SOCKET"

#/////////////////////////////////////////////////
# Широковещание

BROADCAST_IP             = "BROADCAST_CHATROOM_IP"

# Запросы (requests)
BROADCAST_REQUEST_IP     = request(BROADCAST_IP)

# Ответы (responses)    
BROADCAST_RESPONSE_IP    = response(BROADCAST_IP)

BROADCAST_RESPONSES      = (
    BROADCAST_RESPONSE_IP
)
BROADCAST_REQUESTS       = (
    BROADCAST_REQUEST_IP
)