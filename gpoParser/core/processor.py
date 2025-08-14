import re

def process_gpos(ou_objects, gpo_objects):
    """
    Assign effective GPOs to each OU.
    Only linked GPO are taken into consideration.
    Enforced GPOs will be present even if OU is disabling inheritance.
    """

    pattern = r"(\{[A-F0-9\-]{36}\}).*?;(\d)\]"
    for ou in ou_objects:
        results = re.findall(pattern, ou.gplink, re.IGNORECASE)
        if len(results) == 1:
            # only 1 GPO applied
            guid = results[0][0]
            status = int(results[0][1])
            if not bool(status & 1) and bool(status & 2):
                # if the GPO is not disabled and enforced
                ou.enforced_gpos_guids.append((guid, status))
            elif not bool(status & 1) and not bool(status & 2):
                # if the GPO is not disabled and not enforced
                ou.gpos_guids.append((guid, status))
        else:
            # multiple GPOs linked to the OU
            for res in results:
                guid = res[0]
                status = int(res[1])
                if not bool(status & 1) and bool(status & 2):
                    # if the GPO is not disabled and enforced
                    ou.enforced_gpos_guids.append((guid, status))
                elif not bool(status & 1) and not bool(status & 2):
                    # if the GPO is not disabled and not enforced
                    ou.gpos_guids.append((guid, status))

    # parse the OU from the root to child containers
    ou_objects_sorted = sorted(ou_objects, key=lambda ou: dn_depth(ou.dn))
    dn_lookup = {ou.dn.upper(): ou for ou in ou_objects}
    for ou in ou_objects_sorted:
        parent_ou = get_parent_dn(ou.dn)
        if is_domain_root(ou.dn):
            ou.effective_gpos_guids = ou.gpos_guids + ou.enforced_gpos_guids
        if ou.block_inheritance is False:
            if parent_ou.upper() in dn_lookup.keys():
                # inherit GPO from parent container
                ou.effective_gpos_guids.extend(dn_lookup[parent_ou].effective_gpos_guids)
        if parent_ou in dn_lookup.keys():
            # always inherit enforced GPOs
            ou.effective_gpos_guids.extend(dn_lookup[parent_ou].enforced_gpos_guids)
            ou.enforced_gpos_guids.extend(dn_lookup[parent_ou].enforced_gpos_guids)
        # add GPO to this specific container
        ou.effective_gpos_guids.extend(ou.gpos_guids)
    
        # remove duplicate GUIDs
        ou.effective_gpos_guids = set(ou.effective_gpos_guids)

def get_parent_dn(dn):
    parts = re.split(r'(?<!\\),', dn)
    return ','.join(parts[1:]) if len(parts) > 1 else None

def is_domain_root(dn):
    # Match components that are only DC=
    components = re.split(r'(?<!\\),', dn)
    return all(part.strip().upper().startswith("DC=") for part in components)

def safe_dn_split(dn):
    # Split on commas that are not escaped
    return re.split(r'(?<!\\),', dn)

def dn_depth(dn):
    return len(safe_dn_split(dn))