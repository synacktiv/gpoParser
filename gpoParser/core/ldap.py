from ldap3 import (
    Server,
    Connection,
    SIMPLE,
    SYNC,
    ALL,
    SASL,
    NTLM,
    SIMPLE,
    KERBEROS,
    ENCRYPT,
    TLS_CHANNEL_BINDING,
)
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP, Ticket
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache, CountedOctetString
from pyasn1.codec.der import decoder, encoder
import os

class LDAP:
    def __init__(
        self,
        server,
        domain,
        username="",
        password=None,
        lm_hash="",
        nt_hash="",
        kerberos=None,
    ):
        self.server = server
        self.domain = domain
        self.domain_fqdn = None
        self.username = username if username else ""
        self.password = password
        self.nt_hash = nt_hash if nt_hash else ""
        self.lm_hash = "aad3b435b51404eeaad3b435b51404ee" if not lm_hash else lm_hash
        self.aesKey = None
        self.kerberos = kerberos
        self.base_dn = []
        self.connection = self.init_ldap_connection()

    def init_ldap_connection(self):
        if not self.server or not self.domain:
            print("Insufficient args")
            print("Please specify server (-s) and domain (-d)")
            exit()

        if self.server.startswith("ldaps"):
            server = Server(self.server, port=636, get_info=ALL)
        else:
            server = Server(self.server, port=389, get_info=ALL)

        if self.kerberos:
            domain, user, TGT, TGS = CCache.parseFile(
                self.domain, self.username, f"cifs/{self.server}"
            )
            ldap_connection = Connection(
                server, authentication=SASL, sasl_mechanism=KERBEROS
            )
            if TGS:
                # gssapi wants the target FQDN in lower case
                self.modify_ticket("ldap")
                os.environ["KRB5CCNAME"] = "/tmp/ticket_naeH2TeT.ccache"
            elif TGT:
                ticket_filename = os.environ["KRB5CCNAME"]
                os.chmod(ticket_filename, 0o600)
            else:
                if "." not in self.server:
                    print("Please specify target FQDN")
                else:
                    print("Case not handled, report it to wil :D")
                exit(1)

        else:
            if not self.username:
                print("Please specify a username (-u)")
                exit()
            user = "{}\\{}".format(self.domain, self.username)
            if not self.password:
                credentials = f"{self.lm_hash}:{self.nt_hash}"
            else:
                credentials = self.password

            if self.server.startswith("ldaps"):
                ldap_connection = Connection(
                    server,
                    user=user,
                    password=credentials,
                    authentication=NTLM,
                    channel_binding=TLS_CHANNEL_BINDING,
                )
            else:
                ldap_connection = Connection(
                    server,
                    user=user,
                    password=credentials,
                    authentication=NTLM,
                    session_security=ENCRYPT,
                )

        if ldap_connection.bind():
            self.base_dn = server.info.other["defaultNamingContext"][0]
            self.forest_base = server.info.other["configurationNamingContext"][0].replace("CN=Configuration,", "")
            self.domain_fqdn = (
                self.base_dn.lower().replace(",dc=", ".").replace("dc=", "")
            )
        else:
            print("Unable to bind to the LDAP server")
            exit()

        return ldap_connection

    def query(self, target_filter, attributes, base=None):
        result_set = []

        base = base if base else self.base_dn
        entry_generator = self.connection.extend.standard.paged_search(
            search_base=base,
            search_filter=target_filter,
            search_scope="SUBTREE",
            attributes=attributes,
            controls=[],
            paged_size=1000,
            generator=True,
        )

        def result(x):
            if "dn" in x:
                d = x["attributes"]
                d["dn"] = x["dn"]
                return dict(d)

        try:
            return filter(lambda x: x is not None, map(result, entry_generator))
        except:
            print("Can't retrieve info from LDAP")
            print("Try to specify the FQDN")
            print(
                f"Base: {base}\ntarget_filter {target_filter}\nattributes: {attributes}"
            )

    def resolve_sid(self, sid):
        if "S-1-5-" in sid:
            # we need to resolve the SID
            # clean SID
            if sid.startswith("*"):
                sid = sid[1:]
            if "__Members" in sid:
                sid = sid.strip("__Members")
            if "__Memberof" in sid:
                sid = sid.strip("__Memberof")

            WELL_KNOWN_SIDs = {
                "S-1-5-32-544": r"BUILTIN\Administrators",
                "S-1-5-32-545": r"BUILTIN\Users",
                "S-1-5-32-546": r"BUILTIN\Guests",
                "S-1-5-32-547": r"BUILTIN\Power Users",
                "S-1-5-32-548": r"BUILTIN\Account Operators",
                "S-1-5-32-549": r"BUILTIN\Server Operators",
                "S-1-5-32-550": r"BUILTIN\Print Operators",
                "S-1-5-32-551": r"BUILTIN\Backup Operators",
                "S-1-5-32-552": r"BUILTIN\Replicators",
                "S-1-5-64-10": r"BUILTIN\NTLM Authentication",
                "S-1-5-64-14": r"BUILTIN\SChannel Authentication",
                "S-1-5-64-21": r"BUILTIN\Digest Authentication",
                "S-1-16-4096": r"BUILTIN\Low Mandatory Level",
                "S-1-16-8192": r"BUILTIN\Medium Mandatory Level",
                "S-1-16-8448": r"BUILTIN\Medium Plus Mandatory Level",
                "S-1-16-12288": r"BUILTIN\High Mandatory Level",
                "S-1-16-16384": r"BUILTIN\System Mandatory Level",
                "S-1-16-20480": r"BUILTIN\Protected Process Mandatory Level",
                "S-1-16-28672": r"BUILTIN\Secure Process Mandatory Level",
                "S-1-5-32-554": r"BUILTIN\Pre-Windows 2000 Compatible Access",
                "S-1-5-32-555": r"BUILTIN\Remote Desktop Users",
                "S-1-5-32-556": r"BUILTIN\Network Configuration Operators",
                "S-1-5-32-557": r"BUILTIN\Incoming Forest Trust Builders",
                "S-1-5-32-558": r"BUILTIN\Performance Monitor Users",
                "S-1-5-32-559": r"BUILTIN\Performance Log Users",
                "S-1-5-32-560": r"BUILTIN\Windows Authorization Access Group",
                "S-1-5-32-561": r"BUILTIN\Terminal Server License Servers",
                "S-1-5-32-562": r"BUILTIN\Distributed COM Users",
                "S-1-5-32-569": r"BUILTIN\Cryptographic Operators",
                "S-1-5-32-573": r"BUILTIN\Event Log Readers",
                "S-1-5-32-574": r"BUILTIN\Certificate Service DCOM Access",
                "S-1-5-32-575": r"BUILTIN\RDS Remote Access Servers",
                "S-1-5-32-576": r"BUILTIN\RDS Endpoint Servers",
                "S-1-5-32-577": r"BUILTIN\RDS Management Servers",
                "S-1-5-32-578": r"BUILTIN\Hyper-V Administrators",
                "S-1-5-32-579": r"BUILTIN\Access Control Assistance Operators",
                "S-1-5-32-580": r"BUILTIN\Remote Management Users",
            }

            if sid in WELL_KNOWN_SIDs:
                res = WELL_KNOWN_SIDs[sid]
            else:
                target_filter = f"(ObjectSid={sid})"
                attributes = ["+"]
                res = self.query(target_filter, attributes)
                if res:
                    try:
                        res = res[0]["dn"].split(",")[0].split("CN=")[1]
                    except:
                        print(f"Can't parse CN {res} from sid {sid}")

            if res:
                return res
            else:
                return sid
        else:
            # sid is already resolved
            return sid

    def modify_ticket(self, new_service_class):
        ccache = CCache.loadFile(os.getenv("KRB5CCNAME"))
        credential = ccache.credentials[0]
        tgs = credential.toTGS()
        decodedST = decoder.decode(tgs["KDC_REP"], asn1Spec=TGS_REP())[0]
        tgs = ccache.credentials[0].toTGS()

        sname = decodedST["ticket"]["sname"]["name-string"]
        service_class, service_hostname = decodedST["ticket"]["sname"]["name-string"]
        service_realm = decodedST["ticket"]["realm"]
        # modifications
        # gssapi requires target hostname in lowercase for ST
        new_service_hostname = service_hostname._value.lower()

        current_service = "%s/%s@%s" % (service_class, service_hostname, service_realm)
        new_service = "%s/%s@%s" % (
            new_service_class,
            new_service_hostname,
            service_realm,
        )

        # replace
        decodedST["ticket"]["sname"]["name-string"][0] = new_service_class
        decodedST["ticket"]["sname"]["name-string"][1] = new_service_hostname
        decodedST["ticket"]["realm"] = service_realm
        ticket = encoder.encode(decodedST)
        credential.ticket = CountedOctetString()
        credential.ticket["data"] = encoder.encode(
            decodedST["ticket"].clone(tagSet=Ticket.tagSet, cloneValueFlag=True)
        )
        credential.ticket["length"] = len(credential.ticket["data"])
        ccache.credentials[0] = credential
        ccache.credentials[0]["server"].fromPrincipal(
            Principal(new_service, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        )
        ticket_filename = f"/tmp/ticket_naeH2TeT.ccache"
        ccache.saveFile(ticket_filename)
        os.chmod(ticket_filename, 0o600)