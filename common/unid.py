import enum

class UNID(int, enum.Enum):
    PUBLIC_KEY            = 1
    PUBLIC_KEY_AND_SOCKET = 2
    CHAT_MESSAGE          = 3    
    SERVER_CHAT_MESSAGE   = 4
    USER_CHAT_MESSAGE     = 5
    PERSONAL_USER_CHAT_MESSAGE = 6
    PERSONAL_CHAT_MESSAGE = 7
    COMMAND               = 8
    REQUEST               = 9 
    RESPONSE              = 10
    SERVER_COMMAND_RESPONSE       = 11



