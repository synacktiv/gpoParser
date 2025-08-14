from gpoParser.core.resolver import build_sid_cache_remotely, build_sid_cache_locally
from gpoParser.core.utils import build_dn_cache_locally, build_dn_cache_remotely
from gpoParser.core.ou import OU
from gpoParser.core.gpo import GPO
import json
import os, glob
import time


def save_cache(args, ou_objects, gpo_objects):
    # create cache json file
    data = {}
    data["ous"] = []
    data["gpos"] = []
    for obj in ou_objects:
        data["ous"].append(obj.__dict__)
    for obj in gpo_objects:
        data["gpos"].append(obj.__dict__)

    for ou in data["ous"]:
        for key in ("gpos_guids", "effective_gpos_guids", "enforced_gpos_guids"):
            if isinstance(ou.get(key), set):
                ou[key] = list(ou[key])

    # create SID mapping with sAMAccountName
    if args.mode == "remote":
        sid_cache = build_sid_cache_remotely(args)
    elif args.mode == "local":
        sid_cache = build_sid_cache_locally(args)
    data["sid_cache"] = sid_cache

    # cache OUs and associated computers
    if args.mode == "remote":
        dn_cache = build_dn_cache_remotely(args, ou_objects)
    elif args.mode == "local":
        dn_cache = build_dn_cache_locally(args, ou_objects)
    data["dn_cache"] = dn_cache

    try:
        with open(f"{args.cache}/cache_gpoParser_{int(time.time())}.json", "w") as f:
            json.dump(data, f, indent=4, default=default_serializer)
    except Exception as e:
        print(f"Failed to save cache: {e}")

def load_cache(args):
    is_cached = False
    ou_objects = []
    gpo_objects = []
    sid_cache = {}
    dn_cache = {}
    pattern = os.path.join(args.cache, "cache_gpoParser_*.json")
    matching_files = glob.glob(pattern)
    if matching_files:
        is_cached = True
        latest_file = max(matching_files, key=os.path.getmtime)
        with open(latest_file) as f:
            data = json.load(f)
        ou_objects = [OU.from_dict(ou) for ou in data.get("ous", [])]
        gpo_objects = [GPO.from_dict(gpo) for gpo in data.get("gpos", [])]
        sid_cache = data.get("sid_cache", {})
        dn_cache = data.get("dn_cache", {})

    return is_cached, ou_objects, gpo_objects, sid_cache, dn_cache

def save_output(args, full_output):
    return

def default_serializer(o):
    if isinstance(o, set):
        return list(o)
    return str(o)