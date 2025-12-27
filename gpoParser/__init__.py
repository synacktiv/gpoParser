#!/usr/bin/env python3

# pip3 install ldap3-bleeding-edge==2.10.1.1337 chardet impacket ijson neo4j

from gpoParser.core.ou import load_ous
from gpoParser.core.gpo import load_gpos
from gpoParser.core.sysvol import retrieve_sysvol_content, parse_sysvol_content
from gpoParser.core.processor import process_gpos
from gpoParser.core.exporter import load_cache, save_cache
from gpoParser.core.display import display_gpos, display_computers_affected_by_gpo, display_gpos_affecting_computer
from gpoParser.core.enrich import create_edges
import argparse
import sys
import time

def main():
    parser = argparse.ArgumentParser(description="GPO Analysis Tool")
    subparsers = parser.add_subparsers(dest="mode", help="Choose mode")

    # Local parsing
    parser_local = subparsers.add_parser("local", help="Parse GPOs locally")
    parser_local.add_argument("sysvol_folder", help="SYSVOL folder containing the policies")
    parser_local.add_argument("ldap_folder", help="Folder with LDAP dump in ldeep format")
    parser_local.add_argument("-f", "--format", help="JSON files input format (default ldeep)", choices=["ldeep", "adexplorer"], default="ldeep")
    parser_local.add_argument("-o", "--output", help="Output filename and location (default ./cache_gpoParser_<timestamp>.json)", default=f"cache_gpoParser_{int(time.time())}.json")

    # Remote parsing
    parser_remote = subparsers.add_parser("remote", help="Parse GPOs via remote LDAP/SYSVOL")
    parser_remote.add_argument("-s", "--server", help="LDAP server IP or FQDN")
    parser_remote.add_argument("-d", "--domain", help="Domain name")
    parser_remote.add_argument("-u", "--user", help="Username")
    parser_remote.add_argument("-p", "--password", help="Password")
    parser_remote.add_argument("-H", "--hash", help="NTLM authentication, format is [LM:]NT")
    parser_remote.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication")
    parser_remote.add_argument("-o", "--output", help="Output filename and location (default ./cache_gpoParser_<timestamp>.json)", default=f"cache_gpoParser_{int(time.time())}.json")

    # Display GPO content
    parser_display = subparsers.add_parser("display", help="Display parsed GPO contents")
    parser_display.add_argument("-g", "--gpo", help="Filter by GPO name or GUID")
    parser_display.add_argument("-c", "--cache", help="Cache file location (default: ./cache_gpoParser_<timestamp>.json)", default="./cache_gpoParser_*.json")

    # Filter on results
    parser_query = subparsers.add_parser("query", help="Query GPO parser results in order to display affected computers")
    parser_query.add_argument("-g", "--gpo", help="Filter by GPO name or GUID")
    parser_query.add_argument("-C", "--computer", help="Computer name or distinguishedName to filter on")
    parser_query.add_argument("-c", "--cache", help="Cache file location (default: ./cache_gpoParser_<timestamp>.json)", default="./cache_gpoParser_*.json")

    # Enrich BloodHound
    parser_enrich = subparsers.add_parser("enrich", help="Enrich BloodHound with new edges")
    parser_enrich.add_argument("-u", "--user", help="Username for neo4j authentication (default: neo4j)", default="neo4j")
    parser_enrich.add_argument("-p", "--password", help="Password for neo4j authentication (default: bloodhoundcommunityedition)", default="bloodhoundcommunityedition")
    parser_enrich.add_argument("-s", "--server", help="Neo4j server URI (default: bolt://localhost:7687)", default="bolt://localhost:7687")
    parser_enrich.add_argument("-c", "--cache", help="Cache file location (default: ./cache_gpoParser_<timestamp>.json)", default="./cache_gpoParser_*.json")

    args = parser.parse_args()
    is_cached = False

    if args.mode == "local" or args.mode == "remote":
        # fetch OUs
        ou_objects = load_ous(args)
        # fetch GPOs
        gpo_objects = load_gpos(args)
        # fetch SYSVOL content
        retrieve_sysvol_content(args, gpo_objects)
        # parse SYSVOL content
        parse_sysvol_content(gpo_objects)
        # process GPO
        process_gpos(ou_objects, gpo_objects)
        # save to cache
        save_cache(args, ou_objects, gpo_objects)
        print("Information saved to cache, now use display / query features")

    elif args.mode == "display":
        is_cached, ou_objects, gpo_objects, sid_cache, dn_cache = load_cache(args)
        if is_cached:
            print("Cache file found, using it")
            display_gpos(args, gpo_objects, sid_cache)
        else:
            print("Cache file not found, please run local or remote parsing once before")

    elif args.mode == "query":
        is_cached, ou_objects, gpo_objects, sid_cache, dn_cache = load_cache(args)
        if is_cached:
            print("Cache file found, using it")
            if args.computer:
                display_gpos_affecting_computer(args, ou_objects, gpo_objects, sid_cache, dn_cache)
            else:
                display_computers_affected_by_gpo(args, ou_objects, gpo_objects, dn_cache)
        else:
            print("Cache file not found, please run gpoParser once before query")

    elif args.mode == "enrich":
        is_cached, ou_objects, gpo_objects, sid_cache, dn_cache = load_cache(args)
        if is_cached:
            print("Cache file found, using it")
            create_edges(args, ou_objects, gpo_objects, sid_cache, dn_cache)
        else:
            print("Cache file not found, please run gpoParser once before enrich")

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
