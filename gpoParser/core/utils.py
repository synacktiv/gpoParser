from gpoParser.core.ldap import LDAP
import ijson
import os, glob
import re

def stream_items(path, suffix):
    try:
        full_path = os.path.join(path, f"*{suffix}")
        file = glob.glob(full_path)[0]
        with open(file, 'rb') as f:
            for obj in ijson.items(f, 'item'):
                yield obj
    except:
        # file not found
        pass

def build_dn_cache_locally(args, ou_objects):
    dn_map = {}

    suffixes = [
        "_machines.json",
        ]

    for ou in ou_objects:
        dn_map[ou.dn] = []

    for suffix in suffixes:
        for obj in stream_items(args.ldap_folder, suffix):
            parent = get_parent_dn(obj.get("distinguishedName"))
            if parent:
                if parent.upper() in dn_map.keys():
                    dn_map[parent.upper()].append(obj.get("distinguishedName"))
    return dn_map


def build_dn_cache_remotely(args, ou_objects):
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

    dn_map = {}

    for ou in ou_objects:
        dn_map[ou.dn] = []

    # fetch principals DNs
    target_filter = f"(|(objectClass=group)(objectClass=computer))"
    attributes = ["distinguishedName"]
    res = ldap.query(target_filter, attributes)
    for item in res:
        if "distinguishedName" in item.keys():
            parent_ou = get_parent_dn(item.get("distinguishedName"))
            if parent_ou:
                if parent_ou.upper() in dn_map.keys():
                    dn_map[parent_ou.upper()].append(item.get("distinguishedName"))
    return dn_map

def get_parent_dn(dn):
    parts = re.split(r'(?<!\\),', dn)
    return ','.join(parts[1:]) if len(parts) > 1 else None