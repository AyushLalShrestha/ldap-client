
import gssapi
from ldap3 import Connection, SASL_AVAILABLE_MECHANISMS
from ldap3.protocol.sasl.digestMd5 import sasl_digest_md5
from ldap3.protocol.sasl.external import sasl_external
from ldap3.protocol.sasl.sasl import (
    send_sasl_negotiation, abort_sasl_negotiation)
from settings import *

SASL_AVAILABLE_MECHANISMS.append('GSSAPI')


def sasl_gssapi(connection, controls):
    """
    Performs a bind using the Kerberos v5 ("GSSAPI") SASL mechanism
    from RFC 4752. Does not support any security layers, only authentication!
    """

    NO_SECURITY_LAYER = 1
    INTEGRITY_PROTECTION = 2
    CONFIDENTIALITY_PROTECTION = 4

    authz_id = b''
    krb5mech = gssapi.OID.mech_from_string()
    target_name = gssapi.Name('ldap@' + connection.server.host, gssapi.C_NT_HOSTBASED_SERVICE)
    ctx_kwargs = {
        'mech_type': krb5mech, 'req_flags': (gssapi.C_INTEG_FLAG,)
    }
    if (
            isinstance(connection.sasl_credentials, (list, tuple))
            and len(connection.sasl_credentials) == 2
    ):
        # connection.sasl_credentials can be a 2-tuple. The first element can be a
        # gssapi.Credential to use as the initiator credential. The second can be an authorization ID.
        # Either can be None if the default credential, or no authorization ID is to be used.
        if isinstance(connection.sasl_credentials[0], gssapi.Credential):
            ctx_kwargs['cred'] = connection.sasl_credentials
        if connection.sasl_credentials[1] is not None:
            authz_id = connection.sasl_credentials[1].encode('utf-8')
    ctx = gssapi.InitContext(target_name, **ctx_kwargs)

    in_token = None
    try:
        while not ctx.established:
            # Client calls init_sec_context...
            out_token = ctx.step(in_token)
            if out_token is None:
                out_token = b''
            # and sends the server the result
            result = send_sasl_negotiation(connection, controls, out_token)
            in_token = result['saslCreds']

        # once the Context is established, decode the server's token
        unwrapped_token = ctx.unwrap(in_token, conf_req=False)
        if len(unwrapped_token) != 4:
            raise ValueError("Incorrect response from server.")
        server_security_layers = ord(unwrapped_token[0])
        if server_security_layers in (0, NO_SECURITY_LAYER):
            if unwrapped_token[1:] != b'\x00\x00\x00':
                raise ValueError("Server max buffer size must be 0 if no security layer.")
        if not (server_security_layers & NO_SECURITY_LAYER):
            raise ValueError("Server requires a security layer, but we don't support any.")
        client_security_layers = bytearray([NO_SECURITY_LAYER, 0, 0, 0])
        out_token = ctx.wrap(bytes(client_security_layers) + authz_id, conf_req=False)
        return send_sasl_negotiation(connection, controls, out_token)
    except (gssapi.GSSException, ValueError) as exc:
        abort_sasl_negotiation(connection, controls)
        raise


class GSSAPIConnection(Connection):

    def do_sasl_bind(self, controls):
        response = None
        if not self.sasl_in_progress:
            self.sasl_in_progress = True
            if self.sasl_mechanism == 'EXTERNAL':
                response = sasl_external(self, controls)
            elif self.sasl_mechanism == 'DIGEST-MD5':
                response = sasl_digest_md5(self, controls)
            elif self.sasl_mechanism == 'GSSAPI':
                response = sasl_gssapi(self, controls)

            self.sasl_in_progress = False

        return response

# Use it as follows (assuming you have obtained a valid Kerberos TGT)
# s = Server('my.server.name', port=389, get_info=GET_ALL_INFO)
# c = GSSAPIConnection(s, auto_bind=False, client_strategy=STRATEGY_SYNC, authentication=AUTH_SASL, check_names=True, sasl_mechanism='GSSAPI')
# print("start TLS...")
# c.tls = Tls()
# c.open()
# c.start_tls()
# print("binding...")
# c.bind()
# print("bind done. I am:")
# print(c.extend.standard.who_am_i())
