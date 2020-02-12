
import ldap
import json
import sys
from settings import *
from win_sid import WinSID


def get_conn_obj():
    ssl = True if (len(sys.argv) > 1 and sys.argv[1] == "1") else False

    # Create a connection to LDAP server
    if ssl:
        PORT = 636
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        ldap_conn = ldap.initialize("ldaps://[%s]:%s" % (HOST, PORT))
        ldap_conn.set_option(ldap.OPT_REFERRALS, 0)
        ldap_conn.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        ldap_conn.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
        ldap_conn.set_option(ldap.OPT_X_TLS_DEMAND, True)
        ldap_conn.set_option(ldap.OPT_DEBUG_LEVEL, 255)
        print("# Trying SSL bind")
    else:
        PORT = 389
        ldap_conn = ldap.initialize("ldap://[%s]:%s" % (HOST, PORT))
        ldap_conn.set_option(ldap.OPT_REFERRALS, 0)
        print("# Trying Non SSL bind")

    ldap_conn.bind_s(DN, PASSWORD)
    return ldap_conn


def main():
    ldap_conn = get_conn_obj()
    # Logging in user and the user_filter
    user_filter = "{}={}".format(AUTH_PARAM, SAM_ACCOUNT_NAME)

    # Search configurations
    query_base = USER_BASE_DN
    search_filter = user_filter
    retrieve_attrs = None  # ['objectSid']
    search_scope = ldap.SCOPE_SUBTREE

    # Search the LDAP database
    msgid = ldap_conn.search_ext(
        query_base, search_scope, search_filter, retrieve_attrs
    )
    unused_code, results, unused_msgid, serverctrls = ldap_conn.result3(msgid)

    entities = list()

    # Iterate over the results of ldap query
    for result in results:
        entity = dict()
        entity["dn"] = result[0]
        if entity.get("dn") is None:
            continue
        for field, value in result[1].items():
            entity.update({field: value})
        entities.append(entity)

    # Print 1st result's objectSid
    entity = entities[0]
    objectSid = entity["objectSid"][0]
    print(WinSID.strsid(objectSid))


if __name__ == "__main__":
    main()
