from pathlib import Path
import re
import chardet
import configparser
from xml.dom import minidom
from impacket.smbconnection import SMBConnection
from io import BytesIO
from impacket.krb5.ccache import CCache

GPO_FILES = {
        "raw_gpttmpl": "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf",
        "raw_computer_groups": "Machine/Preferences/Groups/Groups.xml",
        "raw_computer_registry": "Machine/Preferences/Registry/Registry.xml",
        "raw_user_groups": "User/Preferences/Groups/Groups.xml",
        "raw_user_registry": "User/Preferences/Registry/Registry.xml",
}

GUID_PATTERN = re.compile(r"\{[A-F0-9\-]{36}\}", re.IGNORECASE)

class SMB:
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
        self.server = server.split("//")[-1] if "//" in server else server
        self.domain = domain
        self.username = username if username else ""
        self.password = password
        self.nt_hash = nt_hash if nt_hash else ""
        self.lm_hash = "aad3b435b51404eeaad3b435b51404ee" if not lm_hash else lm_hash
        self.aesKey = None
        self.kerberos = kerberos
        self.base_dn = []
        self.connection = self.init_smb_connection()

    def init_smb_connection(self):
        conn = SMBConnection(self.server, self.server, sess_port=445)
        if self.kerberos:
            domain = ".".join(self.server.split(".")[1:])
            domain, user, TGT, TGS = CCache.parseFile(
                domain, self.username, f"cifs/{conn.getRemoteName()}"
            )
            try:
                conn.kerberosLogin(
                    user,
                    "",
                    domain,
                    self.lm_hash,
                    self.nt_hash,
                    self.aesKey,
                    self.server,
                    TGT,
                    TGS,
                )
            except Exception:
                print(f"Please provide a TGT or a service ticket for {self.server}")
                sys.exit(1)
        else:
            if not self.password:
                conn.login(self.username, self.password, nthash=self.nt_hash)
            else:
                conn.login(self.username, self.password)
        return conn


def retrieve_sysvol_content_local(sysvol_folder, gpo_objects):
    sysvol_path = Path(sysvol_folder).resolve()
    policies_path = None
    for path in sysvol_path.rglob("*"):
        if path.is_dir() and path.name.lower() == "policies":
            policies_path = path.resolve()
            break

    if not policies_path or not policies_path.is_dir():
        print("Can't find Policies folder")
        exit()

    # lookup table
    gpo_map = {gpo.guid.upper(): gpo for gpo in gpo_objects}

    for gpo_dir in policies_path.iterdir():
        if not gpo_dir.is_dir() or not GUID_PATTERN.fullmatch(gpo_dir.name):
            continue
        guid = gpo_dir.name.upper()
        gpo = gpo_map.get(guid)
        if not gpo:
            continue  # GUID not found within the LDAP, skip

        for attr, relative_path in GPO_FILES.items():
            relative_parts = relative_path.split('/')
            file_path = resolve_case_insensitive(gpo_dir, *relative_parts)
            if file_path and file_path.is_file():
                try:
                    with open(file_path, "rb") as f:
                        file_content = f.read()
                    encoding = chardet.detect(file_content)["encoding"]
                    setattr(gpo, attr, file_content.decode(encoding))
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")

def retrieve_sysvol_content_remote(args, gpo_objects):
    # create SMB connection
    if "ldap" in args.server:
        server = args.server.split("/")[-1]
    lm_hash = ""
    nt_hash = args.hash
    smb = SMB(
        args.server,
        args.domain,
        args.user,
        args.password,
        lm_hash,
        nt_hash,
        args.kerberos,
    )

    # list all GUIDs from SYSVOL
    files = smb.connection.listPath(f"SYSVOL", "\\*")
    for f in files:
        # look for directories
        if f.get_filesize() == 0 and f.get_longname() not in (".", ".."):
            try:
                domain_fqdn = f.get_longname()
                newfiles = smb.connection.listPath("SYSVOL", f"\\{domain_fqdn}\\Policies\\*")
                break
            except:
                pass

    guids = [f.get_longname() for f in newfiles if f.get_longname() not in (".", "..")]

    # lookup table
    gpo_map = {gpo.guid.upper(): gpo for gpo in gpo_objects}

    # fetch content
    for guid in guids:
        gpo = gpo_map.get(guid.upper())
        if not gpo:
            continue  # GUID not found within the LDAP, skip

        for attr, relative_path in GPO_FILES.items():
            try:
                fh = BytesIO()
                print(f"Retrieving \\{domain_fqdn}\\Policies\\{guid}\\{relative_path}")
                smb.connection.getFile(
                    "SYSVOL",
                    f"\\{domain_fqdn}\\Policies\\{guid}\\{relative_path}",
                    fh.write,
                )
                file_content = fh.getvalue()
                if file_content:
                    encoding = chardet.detect(file_content)["encoding"]
                    setattr(gpo, attr, file_content.decode(encoding))
                fh.close()
            except:
                # File not found
                fh.close()


def parse_sysvol_content(gpo_objects):
    parse_gpttmpl(gpo_objects)
    parse_groups(gpo_objects)
    parse_registry(gpo_objects)

def parse_gpttmpl(gpo_objects):
    # parse GptTmpl.inf files
    for gpo in gpo_objects:
        if gpo.raw_gpttmpl:
            # preserve case
            class CaseSensitiveConfigParser(configparser.ConfigParser):
                def optionxform(self, option):
                    return option

            config = CaseSensitiveConfigParser(allow_no_value=True, strict=False)
            config.read_string(gpo.raw_gpttmpl)
            # groups information
            if "Group Membership" in config.sections():
                for item in config.items("Group Membership"):
                    group = {
                        "group_name": "",
                        "group_sid": "",
                        "action": "ADD",
                        "members_added": [],
                        "properties":{}
                    }
                    if item[1]:
                        if "__members" in item[0].lower():
                            sid = item[0].lower().removesuffix("__members").strip("*").upper()
                            members = [s.strip("*") for s in item[1].split(",")]
                        else:
                            members = item[0].lower().removesuffix("__memberof").strip("*").upper()
                            sid = [s.strip("*") for s in item[1].split(",")]
                        if isinstance(sid, list) and len(sid) == 1:
                            sid = sid[0]
                        group["group_sid"] = sid
                        if isinstance(members, list):
                            for member in members:
                                group["members_added"].append({"name": "", "sid": member})
                        else:
                            group["members_added"] = members
                        gpo.content["computer"]["groups"].append(group)

            # registry information
            if "Registry Values" in config.sections():
                registry_keys = []
                for item in config.items("Registry Values"):
                    registry = {
                        "path": "",
                        "value": ""
                    }
                    if item[1]:
                        registry["path"] = item[0]
                        registry["value"] = item[1]
                        gpo.content["computer"]["registry"].append(registry)

            # privilege information
            if "Privilege Rights" in config.sections():
                for item in config.items("Privilege Rights"):
                    privilege = {
                        "privilege_name": "",
                        "members": []
                    }
                    if item[1]:
                        members = [s.strip("*") for s in item[1].split(",")]
                        privilege["privilege_name"] = item[0]
                        privilege["members"].extend(members)
                        gpo.content["computer"]["privileges"].append(privilege)


def parse_groups(gpo_objects):
    # parse Groups.xml files
    for gpo in gpo_objects:
        # machine config
        if gpo.raw_computer_groups:
            data = minidom.parseString(gpo.raw_computer_groups)
            groups = data.getElementsByTagName("Group")
            users = data.getElementsByTagName("User")
            if groups:
                for item in groups:
                    group = {
                        "group_name": "",
                        "group_sid": "",
                        "new_name": "",
                        "description": "",
                        "delete_all_users": False,
                        "delete_all_groups": False,
                        "members_added": [],
                        "members_removed": [],
                        "changed": ""
                    }

                    properties = item.getElementsByTagName("Properties")
                    group["group_name"] = properties[0].getAttribute("groupName")
                    group["group_sid"] = properties[0].getAttribute("groupSid")
                    group["changed"] = item.getAttribute("changed")
                    group["new_name"] = properties[0].getAttribute("newName")
                    group["description"] = properties[0].getAttribute("description")
                    group["delete_all_users"] = True if properties[0].getAttribute("deleteAllUsers") == 1 else False
                    group["delete_all_groups"] = True if properties[0].getAttribute("deleteAllGroups") == 1 else False
                    
                    group_member = item.getElementsByTagName("Member")
                    for principal in group_member:
                        if principal.attributes["action"].value == "ADD":
                            group["members_added"].append({
                                "sid": principal.attributes["sid"].value,
                                "name":  principal.attributes["name"].value
                            })
                        elif principal.attributes["action"].value == "REMOVE":
                            group["members_removed"].append({
                                "sid": principal.attributes["sid"].value,
                                "name":  principal.attributes["name"].value
                            })
                        else:
                            print(f"Unsupported action on Groups.xml: {principal.attributes['action'].value}")

                    # add to the gpo object
                    gpo.content["computer"]["groups"].append(group)

            if users:
                for item in users:
                    user = {
                        "action": "",
                        "new_name": "",
                        "fullname": "",
                        "description": "",
                        "cpassword": "",
                        "change_logon": "",
                        "no_change": "",
                        "never_expire": False,
                        "account_disable": False,
                        "username": ""
                    }

                    properties = item.getElementsByTagName("Properties")
                    user["action"] = properties[0].getAttribute("action")
                    user["new_name"] = properties[0].getAttribute("newName")
                    user["fullname"] = item.getAttribute("fullName")
                    user["description"] = properties[0].getAttribute("description")
                    user["cpassword"] = properties[0].getAttribute("cpassword")
                    user["change_logon"] = True if properties[0].getAttribute("changeLogon") == 1 else False
                    user["no_change"] = True if properties[0].getAttribute("noChange") == 1 else False
                    user["never_expire"] = True if properties[0].getAttribute("neverExpires") == 1 else False
                    user["account_disable"] = True if properties[0].getAttribute("acctDisabled") == 1 else False
                    user["username"] = properties[0].getAttribute("userName")

                    # add to the gpo object
                    gpo.content["computer"]["users"].append(user)

        if gpo.raw_user_groups:
            data = minidom.parseString(gpo.raw_user_groups)
            groups = data.getElementsByTagName("Group")
            users = data.getElementsByTagName("User")
            if groups:
                for item in groups:
                    group = {
                        "action": "",
                        "group_name": "",
                        "group_sid": "",
                        "new_name": "",
                        "description": "",
                        "delete_all_users": False,
                        "delete_all_groups": False,
                        "members_added": [],
                        "members_removed": [],
                        "changed": ""
                    }

                    properties = item.getElementsByTagName("Properties")
                    group["action"] = properties[0].getAttribute("action")
                    group["user_action"] = properties[0].getAttribute("userAction")
                    group["group_name"] = properties[0].getAttribute("groupName")
                    group["group_sid"] = properties[0].getAttribute("groupSid")
                    group["changed"] = item.getAttribute("changed")
                    group["new_name"] = properties[0].getAttribute("newName")
                    group["description"] = properties[0].getAttribute("description")
                    group["delete_all_users"] = True if properties[0].getAttribute("deleteAllUsers") == 1 else False
                    group["delete_all_groups"] = True if properties[0].getAttribute("deleteAllGroups") == 1 else False

                    group_member = item.getElementsByTagName("Member")
                    for principal in group_member:
                        if principal.attributes["action"].value == "ADD":
                            group["members_added"].append({
                                "sid": principal.attributes["sid"].value,
                                "name":  principal.attributes["name"].value
                            })
                        elif principal.attributes["action"].value == "REMOVE":
                            group["members_removed"].append({
                                "sid": principal.attributes["sid"].value,
                                "name":  principal.attributes["name"].value
                            })
                        else:
                            print(f"Unsupported action on Groups.xml: {principal.attributes['action'].value}")
                    
                    # add to the gpo object
                    gpo.content["user"]["groups"].append(group)

            if users:
                for item in users:
                    user = {
                        "action": "",
                        "new_name": "",
                        "fullname": "",
                        "description": "",
                        "cpassword": "",
                        "change_logon": "",
                        "no_change": "",
                        "never_expire": False,
                        "account_disable": False,
                        "username": ""
                    }

                    properties = item.getElementsByTagName("Properties")
                    user["action"] = properties[0].getAttribute("action")
                    user["new_name"] = properties[0].getAttribute("newName")
                    user["fullname"] = item.getAttribute("fullName")
                    user["description"] = properties[0].getAttribute("description")
                    user["cpassword"] = properties[0].getAttribute("cpassword")
                    user["change_logon"] = True if properties[0].getAttribute("changeLogon") == 1 else False
                    user["no_change"] = True if properties[0].getAttribute("noChange") == 1 else False
                    user["never_expire"] = True if properties[0].getAttribute("neverExpires") == 1 else False
                    user["account_disable"] = True if properties[0].getAttribute("acctDisabled") == 1 else False
                    user["username"] = properties[0].getAttribute("userName")

                    # add to the gpo object
                    gpo.content["user"]["users"].append(user)

def parse_registry(gpo_objects):
    # parse Registry.xml files
    for gpo in gpo_objects:
        # machine config
        if gpo.raw_computer_registry:
            data = minidom.parseString(gpo.raw_computer_registry)
            registries = data.getElementsByTagName("Registry")
            if registries:
                for item in registries:
                    registry = {
                        "action": "",
                        "hive": "",
                        "path": "",
                        "name":  "",
                        "type": "",
                        "value": "",
                        "changed": "",
                    }
                    properties = item.getElementsByTagName("Properties")
                    registry["action"] = properties[0].getAttribute("action")
                    registry["hive"] = properties[0].getAttribute("hive")
                    registry["path"] = properties[0].getAttribute("key")
                    registry["name"] = properties[0].getAttribute("name")
                    registry["type"] = properties[0].getAttribute("type")
                    registry["value"] = properties[0].getAttribute("value")
                    registry["changed"] = properties[0].getAttribute("value")
                    gpo.content["computer"]["registry"].append(registry)

        if gpo.raw_user_registry:
            data = minidom.parseString(gpo.raw_user_registry)
            registries = data.getElementsByTagName("Registry")
            if registries:
                for item in registries:
                    registry = {
                        "action": "",
                        "hive": "",
                        "path": "",
                        "name":  "",
                        "type": "",
                        "value": "",
                        "changed": "",
                    }
                    properties = item.getElementsByTagName("Properties")
                    registry["action"] = properties[0].getAttribute("action")
                    registry["hive"] = properties[0].getAttribute("hive")
                    registry["path"] = properties[0].getAttribute("key")
                    registry["name"] = properties[0].getAttribute("name")
                    registry["type"] = properties[0].getAttribute("type")
                    registry["value"] = properties[0].getAttribute("value")
                    registry["changed"] = properties[0].getAttribute("value")
                    gpo.content["user"]["registry"].append(registry)

def resolve_case_insensitive(base_path, *parts):
    current = base_path
    for part in parts:
        try:
            entries = {entry.name.lower(): entry for entry in current.iterdir()}
        except FileNotFoundError:
            # not found
            return None

        match = entries.get(part.lower())
        if not match:
            # not found
            return None
        current = match
    return current