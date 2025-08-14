#!/usr/bin/env python3

# pip3 install ldap3-bleeding-edge==2.10.1.1337 chardet impacket ijson neo4j

from gpoParser.core.ou import load_ous
from gpoParser.core.gpo import load_gpos
from gpoParser.core.sysvol import retrieve_sysvol_content_local, retrieve_sysvol_content_remote, parse_sysvol_content
from gpoParser.core.processor import process_gpos
from gpoParser.core.exporter import load_cache, save_cache, save_output
from gpoParser.core.display import display_gpos, display_affected_computers
from gpoParser.core.enrich import create_edges
import argparse
import sys
import time

def main():
    parser = argparse.ArgumentParser(description="GPO Analysis Tool")
    subparsers = parser.add_subparsers(dest="mode", help="Choose local, remote or enrich mode")

    # Local
    parser_local = subparsers.add_parser("local", help="Parse GPOs locally")
    parser_local.add_argument("sysvol_folder", help="SYSVOL folder containing the policies", nargs='?')
    parser_local.add_argument("ldap_folder", help="Folder with LDAP dump in ldeep format", nargs='?')
    parser_local.add_argument("-f", "--format", help="JSON files input format (default ldeep)", choices=["ldeep", "bloodhound-legacy", "bloodhound"], default="ldeep")
    parser_local.add_argument("-of", "--output-format", help="Output format", choices=["pretty", "json"], default="pretty")
    parser_local.add_argument("-t", "--target", help="Filter target computer by name")
    parser_local.add_argument("-o", "--output", help="Output filename and location (default ./gpoParser_<timestamp>.out)", default=f"gpoParser_{int(time.time())}.out")
    parser_local.add_argument("-c", "--cache", help="Cache file location (default current folder)", default=".")
    parser_local.add_argument("-dr", "--dry-run", help="Ignore cache file", action='store_true')


    # Remote
    parser_remote = subparsers.add_parser("remote", help="Parse GPOs via remote LDAP/SYSVOL")
    parser_remote.add_argument("-s", "--server", help="LDAP server IP or FQDN")
    parser_remote.add_argument("-d", "--domain", help="Domain name")
    parser_remote.add_argument("-u", "--user", help="Username")
    parser_remote.add_argument("-p", "--password", help="Password")
    parser_remote.add_argument("-H", "--hash", help="NTLM authentication, format is [LM:]NT")
    parser_remote.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication")
    parser_remote.add_argument("-t", "--target", help="Filter target computer or OU by name")
    parser_remote.add_argument("-of", "--output-format", help="Output format", choices=["pretty"], default="pretty")
    parser_remote.add_argument("-o", "--output", help="Output filename and location (default ./gpoParser_<timestamp>.out)", default=f"gpoParser_{int(time.time())}.out")
    parser_remote.add_argument("-c", "--cache", help="Cache file location (default current folder)", default=".")
    parser_remote.add_argument("-dr", "--dry-run", help="Ignore cache file", action='store_true')

    # Enrich BloodHound
    parser_enrich = subparsers.add_parser("enrich", help="Enrich BloodHound with new edges")
    parser_enrich.add_argument("-u", "--user", help="Username for neo4j authentication (default: neo4j)", default="neo4j")
    parser_enrich.add_argument("-p", "--password", help="Password for neo4j authentication (default: bloodhoundcommunityedition)", default="bloodhoundcommunityedition")
    parser_enrich.add_argument("-s", "--server", help="Neo4j server URI (default: bolt://localhost:7687)", default="bolt://localhost:7687")
    parser_enrich.add_argument("-c", "--cache", help="Cache file location (default current folder)", default=f".")

    # Query results
    parser_query = subparsers.add_parser("query", help="Query GPO parser results in order to display affected computers")
    parser_query.add_argument("-n", "--name", help="GPO name to filter on")
    parser_query.add_argument("-g", "--guid", help="GPO GUID to filter on")
    parser_query.add_argument("-c", "--cache", help="Cache file location (default current folder)", default=f".")


    args = parser.parse_args()
    is_cached = False

    if args.mode == "local":
        if not args.dry_run:
            is_cached, ou_objects, gpo_objects, sid_cache, dn_cache  = load_cache(args)
        if is_cached:
            print("Cache file found, using it")
            # display content
            display_gpos(args, ou_objects, gpo_objects, sid_cache, dn_cache)
        else:
            print("Cache file not found, processing")
            if args.sysvol_folder is None or args.ldap_folder is None:
                print("Please specify sysvol_folder and ldap_folder")
                exit()
            # fetch OUs
            ou_objects = load_ous(args)
            # fetch GPOs
            gpo_objects = load_gpos(args)
            # fetch SYSVOL content
            sysvol_content = retrieve_sysvol_content_local(args.sysvol_folder, gpo_objects)
            # parse SYSVOL content
            parse_sysvol_content(gpo_objects)
            # process GPO
            process_gpos(ou_objects, gpo_objects)
            # save to cache
            save_cache(args, ou_objects, gpo_objects)
            # display content
            display_gpos(args, ou_objects, gpo_objects)

    elif args.mode == "remote":
        if not args.dry_run:
            is_cached, ou_objects, gpo_objects, sid_cache, dn_cache = load_cache(args)
        if is_cached:
            print("Cache file found, using it")
            # display content
            display_gpos(args, ou_objects, gpo_objects, sid_cache, dn_cache)
        else:
            print("Cache file not found, processing")
            # fetch OUs
            ou_objects = load_ous(args)
            # fetch GPOs
            gpo_objects = load_gpos(args)
            # fetch SYSVOL content
            sysvol_content = retrieve_sysvol_content_remote(args, gpo_objects)
            # parse SYSVOL content
            parse_sysvol_content(gpo_objects)
            # process GPO
            process_gpos(ou_objects, gpo_objects)
            # save to cache
            save_cache(args, ou_objects, gpo_objects)
            # display content
            display_gpos(args, ou_objects, gpo_objects)

    elif args.mode == "enrich":
        is_cached, ou_objects, gpo_objects, sid_cache, dn_cache = load_cache(args)
        if is_cached:
            print("Cache file found, using it")
            create_edges(args, ou_objects, gpo_objects, sid_cache, dn_cache)
        else:
            print("Cache file not found, please run gpoParser once before enrich")

    elif args.mode == "query":
        is_cached, ou_objects, gpo_objects, sid_cache, dn_cache = load_cache(args)
        if is_cached:
            print("Cache file found, using it")
            display_affected_computers(args, ou_objects, gpo_objects, sid_cache, dn_cache)
        else:
            print("Cache file not found, please run gpoParser once before query")

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
