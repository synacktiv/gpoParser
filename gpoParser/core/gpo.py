from gpoParser.core.ldap import LDAP
import os, glob
import ijson


class GPO:
    def __init__(self, guid):
        self.guid = guid
        self.name = None
        self.flags = None
        self.raw_gpttmpl = ""
        self.raw_computer_groups = ""
        self.raw_computer_registry = ""
        self.raw_user_groups = ""
        self.raw_user_registry = ""
        self.dn = []
        self.computers = []
        self.content = {
            "computer": {
                "groups":[],
                "users": [],
                "registry": [],
                "privileges": [],
            },
            "user": {
                "groups":[],
                "users": [],
                "registry": [],
                "privileges": [],
            }
        }

    @classmethod
    def from_dict(cls, d):
        gpo = cls(d["guid"])
        gpo.name = d.get("name")
        gpo.flags = d.get("flags")
        gpo.raw_gpttmpl = d.get("raw_gpttmpl", "")
        gpo.raw_computer_groups = d.get("raw_computer_groups", "")
        gpo.raw_computer_registry = d.get("raw_computer_registry", "")
        gpo.raw_user_groups = d.get("raw_user_groups", "")
        gpo.raw_user_registry = d.get("raw_user_registry", "")
        gpo.dn = d.get("dn", [])
        gpo.computers = d.get("computers", [])
        gpo.content = d.get("content", gpo.content)
        return gpo


def load_gpos(args):
    if args.mode == "local":
        return load_local(args.ldap_folder, args.format)
    elif args.mode == "remote":
        return load_remote(args)
    else:
        raise ValueError(f"Unsupported mode: {args.mode}")


def load_local(ldap_folder, data_format):
    gpo_objects = []
    if data_format == "ldeep":
        for entry in stream_items(path=ldap_folder, suffix="_gpo.json"):
            gpo = GPO(entry.get("cn", "").upper())
            gpo.name = entry.get("displayName", "")
            gpo.flags = entry.get("flags", 0)
            gpo_objects.append(gpo)
    return gpo_objects

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

    # fetch GPOs
    gpo_objects = []
    search_filter = "(objectCategory=groupPolicyContainer)"
    attributes = ["cn", "displayName", "flags"]
    gpos = ldap.query(search_filter, attributes)
    for entry in gpos:
        gpo = GPO(entry.get("cn", "").upper())
        gpo.name = entry.get("displayName", "")
        gpo.flags = entry.get("flags", 0)
        gpo_objects.append(gpo)
    return gpo_objects

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