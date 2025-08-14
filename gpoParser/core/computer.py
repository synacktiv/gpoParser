from gpoParser.core.processor import get_parent_dn
from gpoParser.core.ldap import LDAP
import os, glob
import ijson

def load_computers(args):
    if args.mode == "local":
        return load_local(args.ldap_folder, args.format)
    elif args.mode == "remote":
        return load_remote(args)
    else:
        raise ValueError(f"Unsupported mode: {args.mode}")

def load_local(ldap_folder, data_format):
    computers_dns = []
    if data_format == "ldeep":
        for entry in stream_items(path=ldap_folder, suffix="_machines.json"):
            computers_dns.append(entry.get("distinguishedName").upper())
    return computers_dns

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

    # fetch DNs
    computers_dns = []
    search_filter = "(&(objectClass=computer)(!(objectClass=msDS-GroupManagedServiceAccount)))"
    attributes = ["distinguishedName"]
    computers_generator = ldap.query(search_filter, attributes)
    for entry in computers_generator:
        computers_dns.append(entry.get("distinguishedName").upper())
    return computers_dns

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