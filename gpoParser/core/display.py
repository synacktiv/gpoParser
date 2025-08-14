from gpoParser.core.computer import load_computers
from gpoParser.core.processor import get_parent_dn
from gpoParser.core.resolver import resolv_sid, build_sid_cache_remotely, build_sid_cache_locally
import json

def format_group(args, gpo, sid_cache):
    """
    Format raw group information from the JSON.
    """
    lines = []

    action_map = {
        "A": "Create",
        "U": "Update",
        "R": "Replace",
        "D": "Delete"
    }

    computer_groups_settings = gpo.content.get("computer", {}).get("groups", [])
    computer_users_settings = gpo.content.get("computer", {}).get("users", [])
    user_groups_settings = gpo.content.get("user", {}).get("groups", [])
    user_users_settings = gpo.content.get("user", {}).get("users", [])

    if computer_groups_settings:
        lines.append("Computer configuration")
        lines.append("   Groups")

        for group in computer_groups_settings:
            if isinstance(group.get("group_sid"), list):
                # This group is a member of multiple groups
                # aka BUILTIN\administrators is member of domain users and domain admin
                for item in group.get("group_sid"):
                    item = resolv_sid(args, item, sid_cache)
                    member = resolv_sid(args, group.get('members_added'), sid_cache)
                    lines.append(f"      The following principals are added to {item}")
                    lines.append(f"         {member}")
            else:
                # most common case
                if not group.get('group_sid'):
                    current_group = group.get("group_name")
                else:
                    current_group = resolv_sid(args, group.get('group_sid'), sid_cache)
                lines.append(f"      The following principals are added to {current_group}")
                if isinstance(group.get('members_added'), list):
                    for item in group.get('members_added'):
                        if item.get('name'):
                            lines.append(f"         {item.get('name')}")
                        else:
                            sid = resolv_sid(args, item.get('sid'), sid_cache)
                            lines.append(f"         {sid}")
                else:
                    member = resolv_sid(args, group.get('members_added'), sid_cache)
                    lines.append(f"         {member}")

    if computer_users_settings:
        lines.append("Computer configuration")
        lines.append("   Users")

        fields = [
            ('username', "User name"),
            ('new_name', "New name"),
            ('fullname', "Full name"),
            ('description', "Description"),
            ('cpassword', "Cpassword"),
            ('change_logon', "User must change password at next logon"),
            ('no_change', "User cannot change password"),
            ('never_expire', "Password never expires"),
            ('account_disable', "Account is disabled")
        ]

        for user in computer_users_settings:
            lines.append(f"      The following changes to users have been made:")
            lines.append(f"      Action: {action_map[user.get('action')]}")
            for key, label in fields:
                if user.get(key):
                    lines.append(f"      {label}: {user.get(key)}")

    if user_groups_settings:
        lines.append("User configuration")
        lines.append("   Groups")

        for group in user_groups_settings:
            if isinstance(group.get("group_sid"), list):
                # This group is a member of multiple groups
                # aka BUILTIN\administrators is member of domain users and domain admin
                for item in group.get("group_sid"):
                    item = resolv_sid(args, item, sid_cache)
                    member = resolv_sid(args, group.get('members_added'), sid_cache)
                    lines.append(f"      The following principals are added to {item}")
                    lines.append(f"         {member}")
            else:
                current_group = resolv_sid(args, group.get('group_sid'), sid_cache)
                lines.append(f"      The following principals are added to {current_group}")
                if group.get('user_action') == "ADD":
                    lines.append(f"         %LogonUser%")
                if isinstance(group.get('members_added'), list):
                    for item in group.get('members_added'):
                        if item.get('name'):
                            lines.append(f"         {item.get('name')}")
                        else:
                            sid = resolv_sid(args, item.get('sid'), sid_cache)
                            lines.append(f"         {sid}")
                else:
                    member = resolv_sid(args, group.get('members_added'), sid_cache)
                    lines.append(f"         {member}")

    if user_users_settings:
        lines.append("User configuration")
        lines.append("   Users")

        fields = [
            ('username', "User name"),
            ('new_name', "New name"),
            ('fullname', "Full name"),
            ('description', "Description"),
            ('cpassword', "Cpassword"),
            ('change_logon', "User must change password at next logon"),
            ('no_change', "User cannot change password"),
            ('never_expire', "Password never expires"),
            ('account_disable', "Account is disabled")
        ]

        for user in user_users_settings:
            lines.append(f"      The following changes to users have been made:")
            lines.append(f"      Action: {action_map[user.get('action')]}")
            for key, label in fields:
                if user.get(key):
                    lines.append(f"      {label}: {user.get(key)}")

    lines = "\n".join(lines) + "\n"
    return lines if lines != "\n" else ""

def format_privilege(args, gpo, sid_cache):
    """
    Format raw privilege information from the JSON.
    """
    lines = []

    computer_privileges = gpo.content.get("computer", {}).get("privileges", [])
    if computer_privileges:
        lines.append("Computer configuration")
        lines.append("   Privileges")

        for privilege in computer_privileges:
            lines.append(f"      The following principals own the following privilege {privilege.get('privilege_name')}")
            if isinstance(privilege.get('members'), list):
                for item in privilege.get('members'):
                    item = resolv_sid(args, item, sid_cache)
                    lines.append(f"         {item}")

        return "\n".join(lines) + "\n"
    else:
        return ""

def format_registry(args, gpo, sid_cache):
    """
    Format raw registry information from the JSON.
    """
    lines = []

    action_map = {
        "C": "Create",
        "U": "Update",
        "R": "Replace",
        "D": "Delete"
    }

    fields = [
        ('action', "Action"),
        ('hive', 'Hive'),
        ('path', "Path"),
        ('new_name', "New name"),
        ('name', "Name"),
        ('value', "Value")
    ]

    computer_registry = gpo.content.get("computer", {}).get("registry", [])
    if computer_registry:
        lines.append("Computer configuration")
        lines.append("   Registry")

        for reg in computer_registry:
            lines.append(f"      The following registry key changes have been made")
            for key, label in fields:
                if key == "action":
                    if reg.get(key) is None:
                        value = "Create"
                    else:
                        value = action_map[reg.get('action')]
                else:
                    value = reg.get(key)
                if value:
                    lines.append(f"      {label}: {value}")

    user_registry = gpo.content.get("user", {}).get("registry", [])
    if user_registry:
        lines.append("User configuration")
        lines.append("   Registry")

        for reg in user_registry:
            lines.append(f"      The following registry key changes have been made")
            for key, label in fields:
                if key == "action":
                    if reg.get(key) is None:
                        value = "Create"
                    else:
                        value = action_map[reg.get('action')]
                else:
                    value = reg.get(key)
                if value:
                    lines.append(f"      {label}: {value}")

    lines = "\n".join(lines) + "\n"
    return lines if lines != "\n" else ""

def display_gpos(args, ou_objects, gpo_objects, sid_cache=None, dn_cache=None):
    """
    Display GPO application data.
    """
    if not sid_cache:
        # build the SID cache
        if args.mode == "remote":
            sid_cache = build_sid_cache_remotely(args)
        else:
            sid_cache = build_sid_cache_locally(args)

    if args.target is not None:
        found = False
        # filter on a specific computer
        if not dn_cache:
            # retrieve computers dns
            computer_dns = load_computers(args)
            # find parent OU to this computer
            for computer in computer_dns:
                if args.target.upper() in computer.upper():
                    found = True
                    parent_ou = get_parent_dn(computer)
                    break
        else:
            for container,items in dn_cache.items():
                for item in items:
                    if args.target.upper() in item.upper():
                        found = True
                        parent_ou = container.upper()
                        break

        # display GPOs
        if not found:
            print(f"Can't find computer {args.target} or his parent container")
        else:
            effective_gpos_guids = []
            for ou in ou_objects:
                if ou.dn.upper() == parent_ou.upper():
                    effective_gpos_guids = [guid for guid,_ in ou.effective_gpos_guids]
            for gpo in gpo_objects:
                if gpo.guid in effective_gpos_guids:
                    if args.output_format == "pretty":
                        # user friendly output
                        if has_nested_values(gpo.content):
                            print(f"{gpo.guid}: {gpo.name}")
                            group_output = format_group(args, gpo, sid_cache)
                            privilege_output = format_privilege(args, gpo, sid_cache)
                            registry_output = format_registry(args, gpo, sid_cache)
                            output = group_output + privilege_output + registry_output
                            print(output)

    else:
        # display all GPOs
        for gpo in gpo_objects:
            if args.output_format == "pretty":
                # user friendly output
                if has_nested_values(gpo.content):
                    print(f"{gpo.guid}: {gpo.name}")
                    group_output = format_group(args, gpo, sid_cache)
                    privilege_output = format_privilege(args, gpo, sid_cache)
                    registry_output = format_registry(args, gpo, sid_cache)
                    output = group_output + privilege_output + registry_output
                    print(output)

            else:
                # json output, TODO
                print("Not implemented yet :(")
                print("Maybe cache file can help")

def display_affected_computers(args, ou_objects, gpo_objects, sid_cache, dn_cache):
    for gpo in gpo_objects:
        affected_ous = []
        for ou in ou_objects:
            for guid in ou.effective_gpos_guids:
                if gpo.guid.upper() == guid[0].upper():
                    affected_ous.append(ou.dn)

        affected_computers = []
        for ou in affected_ous:
            if ou in dn_cache.keys():
                if dn_cache[ou]:
                    affected_computers.append(dn_cache[ou])

        flat_affected_computers = [item for sublist in affected_computers for item in sublist]
        if flat_affected_computers:
            if args.name or args.guid:
                if gpo.name == args.name or args.guid is not None and args.guid.upper() in gpo.guid.upper():
                    print(f"{gpo.guid}: {gpo.name}")
                    print("This GPO affects the following computers:")
                    print("\n".join(flat_affected_computers))
                    print()
            else:
                print(f"{gpo.guid}: {gpo.name}")
                print("This GPO affects the following computers:")
                print("\n".join(flat_affected_computers))
                print()

def has_nested_values(d):
    if isinstance(d, dict):
        return any(has_nested_values(v) for v in d.values())
    if isinstance(d, list):
        return any(has_nested_values(v) for v in d)
    return bool(d)
