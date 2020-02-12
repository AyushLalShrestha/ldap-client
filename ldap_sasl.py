
import ldap
import ldap.sasl
from settings import *


ldap_conn = ldap.initialize("ldap://[%s]:%s" % (HOST, PORT))
ldap_conn.set_option(ldap.OPT_REFERRALS, 0)
auth = ldap.sasl.gssapi("")

try:
    # ldap_conn.sasl_gssapi_bind_s(authz_id=PRINCIPAL_NAME)
    ldap_conn.sasl_bind_s("", auth)
    print(ldap_conn.whoami_s())
except ldap.INVALID_CREDENTIALS as e:
    print(str(e))
except Exception as e:
    print(e)

# res = l.search_s("dc=nil,dc=b17",ldap.SCOPE_BASE,"(objectClass=*)")

