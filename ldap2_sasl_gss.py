import ldap
import ldap.sasl
from settings import *

trace_level = 3
conn = ldap.initialize(URI)

# Normal LDAPv3 compliant simple bind
conn.simple_bind_s(DN, PASSWORD)

# This is AD-specific and not LDAPv3 compliant
conn.simple_bind_s(PRINCIPAL_NAME, PASSWORD)
conn.set_option(ldap.OPT_REFERRALS, 0)

try:
    # SASL bind with mech DIGEST-MD5 with sAMAccountName as SASL user name
    sasl_auth = ldap.sasl.sasl(
        {ldap.sasl.CB_AUTHNAME: SAM_ACCOUNT_NAME, ldap.sasl.CB_PASS: PASSWORD},
        "DIGEST-MD5",
    )
    conn.sasl_interactive_bind_s("", sasl_auth)
except ldap.INVALID_CREDENTIALS as e:
    print("DIGEST-MD5 bind error: %s\n" % e)


try:
    # SASL bind with mech GSSAPI
    # with the help of Kerberos V TGT obtained before with command
    # kinit ablume@ADDOMAIN.EXAMPLE.COM
    sasl_auth = ldap.sasl.sasl({}, "GSSAPI")
    conn.sasl_interactive_bind_s("", sasl_auth)
except ldap.INVALID_CREDENTIALS as e:
    print("GSSAPI bind error: %s" % e)
except Exception as e:
    print("GSSAPI bind error: %s" % e)
