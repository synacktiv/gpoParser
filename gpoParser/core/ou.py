import os, glob
import ijson
from gpoParser.core.ldap import LDAP


class OU:
    def __init__(self, dn):
        self.dn = dn
        self.gpos_guids = []
        self.enforced_gpos_guids = []
        self.effective_gpos_guids = []
        self.gplink = ""
        self.block_inheritance = False

    @classmethod
    def from_dict(cls, d):
        ou = cls(d["dn"])
        ou.gpos_guids = d.get("gpos_guids", [])
        ou.enforced_gpos_guids = d.get("enforced_gpos_guids", [])
        ou.effective_gpos_guids = d.get("effective_gpos_guids", [])
        ou.gplink = d.get("gplink", "")
        ou.block_inheritance = d.get("block_inheritance", False)
        return ou

def load_ous(args):
    if args.mode == "local":
        return load_local(args.ldap_folder, args.format)
    elif args.mode == "remote":
        return load_remote(args)
    else:
        raise ValueError(f"Unsupported mode: {args.mode}")

def load_local(ldap_folder, data_format):
    ou_objects = []
    if data_format == "ldeep":
        for entry in stream_items(path=ldap_folder, suffix="_ou.json"):
            ou_dn = entry.get("distinguishedName").upper()
            ou = OU(ou_dn)
            ou.block_inheritance = True if entry.get("gPOptions") == 1 else False
            ou.gplink = entry.get("gPLink", "")
            ou_objects.append(ou)

    return ou_objects

def load_remote(args):
    # check args
    if args.server is None:
        print("Please specify LDAP server (IP or FQDN)")
        exit(1)
    if args.password is None and args.hash is None and args.kerberos is None:
        print("You must specify a password, a NTLM hash or use Kerberos authentication")
        exit(1)
    
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

    # fetch OUs
    ou_objects = []
    search_filter = "(&(|(objectClass=OrganizationalUnit)(objectClass=domain))(gplink=*))"
    attributes = ["distinguishedName", "gPLink", "gPOptions"]
    ous = ldap.query(search_filter, attributes)
    for entry in ous:
        ou_dn = entry.get("distinguishedName").upper()
        ou = OU(ou_dn)
        ou.block_inheritance = True if entry.get("gPOptions") == 1 else False
        ou.gplink = entry.get("gPLink", "")
        ou_objects.append(ou)
    return ou_objects

def stream_items(path, suffix):
    try:
        full_path = os.path.join(path, f"*{suffix}")
        file = glob.glob(full_path)[0]
        with open(file, 'rb') as f:
            for obj in ijson.items(f, 'item'):
                yield obj
    except:
        print(f"Can't find {path}*{suffix} file")
        exit()