from gpoParser.core.utils import stream_items
from gpoParser.core.ldap import LDAP

WELL_KNOWN_SIDS = {
    "S-1-1-0":"Everyone",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-19":"NT Authority (LocalService)",
    "S-1-5-20": "Network Service",
    "S-1-5-32-544": r"BUILTIN\Administrators",
    "S-1-5-32-545": r"BUILTIN\Users",
    "S-1-5-32-546": r"BUILTIN\Guests",
    "S-1-5-32-547": r"BUILTIN\Power Users",
    "S-1-5-32-548": r"BUILTIN\Account Operators",
    "S-1-5-32-549": r"BUILTIN\Server Operators",
    "S-1-5-32-550": r"BUILTIN\Print Operators",
    "S-1-5-32-551": r"BUILTIN\Backup Operators",
    "S-1-5-32-552": r"BUILTIN\Replicators",
    "S-1-5-32-568": r"BUILTIN\IIS_IUSRS",
    "S-1-5-64-10": r"BUILTIN\NTLM Authentication",
    "S-1-5-64-14": r"BUILTIN\SChannel Authentication",
    "S-1-5-64-21": r"BUILTIN\Digest Authentication",
    "S-1-5-90-0": r"BUILTIN\Windows Manager Group",
    "S-1-5-113": "Local account",
    "S-1-5-114": "Local account and member of Administrators group",
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


def resolv_sid(args, sid, sid_cache):
    if sid.startswith("S-1-"):
        # try to resolve builtin SID first
        if sid in WELL_KNOWN_SIDS:
            sid = f"{WELL_KNOWN_SIDS[sid]}"
        else:
            if sid in sid_cache:
                sid = f"{sid_cache[sid]}"
    return sid

def build_sid_cache_remotely(args):
    # init LDAP connection
    lm_hash = ""
    if args.kerberos:
        nt_hash = ""
        try:
            original_ticket_filename = os.environ["KRB5CCNAME"]
            if not os.path.isfile(original_ticket_filename):
                print(f"Can't find {original_ticket_filename} file")
                exit(1)
        except KeyError:
            print("KRB5CCNAME env not defined")
            exit(1)
        ldap = LDAP(
            args.server,
            args.domain,
            args.user,
            args.password,
            lm_hash,
            nt_hash,
            args.kerberos,
        )
        os.environ["KRB5CCNAME"] = original_ticket_filename
        try:
            os.remove("/tmp/ticket_naeH2TeT.ccache")
        except:
            # no file created when using a TGT
            pass
    else:
        nt_hash = args.hash
        ldap = LDAP(
            args.server,
            args.domain,
            args.user,
            args.password,
            lm_hash,
            nt_hash,
            args.kerberos,
        )

    # fetch DNs
    target_filter = f"(|(objectClass=user)(objectClass=group)(objectClass=computer))"
    attributes = ["objectSid", "sAMAccountName"]
    res = ldap.query(target_filter, attributes)
    sid_map = {}
    for item in res:
        if "objectSid" in item.keys() and "sAMAccountName" in item.keys():
            sid_map[item.get("objectSid")] = item.get("sAMAccountName")
    return sid_map

def build_sid_cache_locally(args):
    sid_map = {}
    suffixes = [
        "_users.json",
        "_gmsa.json",
        "_groups.json",
        "_machines.json"
        ]

    for suffix in suffixes:
        for obj in stream_items(args.ldap_folder, suffix):
            sid = obj.get("objectSid")
            name = obj.get("sAMAccountName")
            if sid and name:
                sid_map[sid] = name
    return sid_map
