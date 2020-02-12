"""
Configurations related to the LDAP server & the user from which the connection
 will be initialized & binded
"""


URI = 'ldap://<IP>'
HOST = '<IP>'
PORT = 389
DN = 'CN=username,CN=Users,DC=ms,DC=eu'
SAM_ACCOUNT_NAME = '<sAMAccountName>'
PRINCIPAL_NAME = 'username@ms.eu'
PASSWORD = 'secretP@$$word'
USER_BASE_DN = "DC=ms,DC=eu"
AUTH_PARAM = "sAMAccountName"
