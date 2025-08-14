from neo4j import GraphDatabase

class BloodHoundConnector:
    """
    A class to connect to the BloodHound Neo4j database
    and execute Cypher queries.
    """
    def __init__(self, uri, user, password):
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
        except Exception as e:
            print(f"Failed to connect to Neo4j: {e}")
            self.driver = None

    def close(self):
        if self.driver is not None:
            self.driver.close()

    def run_query(self, query, parameters=None):
        if self.driver is None:
            print("Cannot run query, no active driver.")
            return None

        with self.driver.session() as session:
            try:
                result = session.run(query, parameters)
                return [record for record in result]
            except Exception as e:
                print(f"Query failed: {e}")
                return None

def create_edges(args, ou_objects, gpo_objects, sid_cache, dn_cache):
    bh_connector = BloodHoundConnector(args.server, args.user, args.password)
    for gpo in gpo_objects:
        if gpo.content:
            if gpo.content.get("computer").get("groups"):
                groups = gpo.content.get("computer").get("groups")
                target_principals = []
                for ou in ou_objects:
                    # check for each OU if this current GPO applies
                    for guid in ou.effective_gpos_guids:
                        if gpo.guid.upper() == guid[0].upper():
                            # current GPO applies to this OU
                            if ou.dn in dn_cache.keys():
                                if dn_cache[ou.dn]:
                                    # a computer is within this OU
                                    target_principals.append(dn_cache[ou.dn])

                flat_target_principals = [item for sublist in target_principals for item in sublist]
                for group in groups:
                    if group.get("group_name") == "Administrators (built-in)":
                        source_principals = []
                        for member in group.get("members_added"):
                            if "sid" in member.keys():
                                if member.get("sid"):
                                    source_principals.append((member.get("sid"), "sid"))
                                else:
                                    source_principals.append((member.get("name"), "name"))
                        for source_principal in source_principals:
                            for target_principal in flat_target_principals:
                                print(f"Creating AdminTo edge between {source_principal[0]} and {target_principal}")
                                create_admin_edges(bh_connector, source_principal, target_principal)

                    if group.get("group_name") == "Remote Desktop Users (built-in)":
                        source_principals = []
                        for member in group.get("members_added"):
                            if "sid" in member.keys():
                                if member.get("sid"):
                                    source_principals.append((member.get("sid"), "sid"))
                                else:
                                    source_principals.append((member.get("name"), "name"))
                        for source_principal in source_principals:
                            for target_principal in flat_target_principals:
                                print(f"Creating CanRDP edge between {source_principal[0]} and {target_principal}")
                                create_rdp_edges(bh_connector, source_principal, target_principal)

                    if "REMOTE MANAGEMENT USERS" in group.get("group_name").upper():
                        source_principals = []
                        for member in group.get("members_added"):
                            if "sid" in member.keys():
                                if member.get("sid"):
                                    source_principals.append((member.get("sid"), "sid"))
                                else:
                                    source_principals.append((member.get("name"), "name"))
                        for source_principal in source_principals:
                            for target_principal in flat_target_principals:
                                print(f"Creating CanPSRemote edge between {source_principal[0]} and {target_principal}")
                                create_winrm_edges(bh_connector, source_principal, target_principal)

def create_admin_edges(bh_connector, source_principal, target_principal):
    if source_principal[1] == "sid":
        source = f'objectid: "{source_principal[0].upper()}"'
    else:
        source = f'samaccountname: "{source_principal[0]}"'
    target = f'distinguishedname: "{target_principal.upper()}"'

    cypher_query = (
        'MATCH (a{{{}}})\n'
        'MATCH (b{{{}}})\n'
        'CREATE (a)-[:AdminTo]->(b)\n'
        'RETURN a, b'
    ).format(source, target)
    bh_connector.run_query(cypher_query)


def create_rdp_edges(bh_connector, source_principal, target_principal):
    if source_principal[1] == "sid":
        source = f'objectid: "{source_principal[0].upper()}"'
    else:
        source = f'samaccountname: "{source_principal[0]}"'
    target = f'distinguishedname: "{target_principal.upper()}"'

    cypher_query = (
        'MATCH (a{{{}}})\n'
        'MATCH (b{{{}}})\n'
        'CREATE (a)-[:CanRDP]->(b)\n'
        'RETURN a, b'
    ).format(source, target)
    bh_connector.run_query(cypher_query)

def create_winrm_edges(bh_connector, source_principal, target_principal):
    if source_principal[1] == "sid":
        source = f'objectid: "{source_principal[0].upper()}"'
    else:
        source = f'samaccountname: "{source_principal[0]}"'
    target = f'distinguishedname: "{target_principal.upper()}"'

    cypher_query = (
        'MATCH (a{{{}}})\n'
        'MATCH (b{{{}}})\n'
        'CREATE (a)-[:CanPSRemote]->(b)\n'
        'RETURN a, b'
    ).format(source, target)
    bh_connector.run_query(cypher_query)