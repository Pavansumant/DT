import requests
import os
import json
import argparse
import sys
from pathlib import Path
from dotenv import load_dotenv
import re
import asyncio
import aiohttp

# CONFIG
CONTAINER_PATTERN = re.compile(r'^([a-f0-9]{12})\s+\S+\s+\((.+):([^)]+)\)$', re.IGNORECASE)

env_path = Path(".env")
load_dotenv(env_path)
API_KEY = os.getenv("DT_API_KEY")
DT_URL = os.getenv("DT_URL")
BASE_URL = f"{DT_URL.rstrip('/')}/api/v1" if DT_URL else None

HEADERS = {
    "X-Api-Key": API_KEY,
    "Content-Type": "application/json"
}

PERMISSIONS = ["VIEW_PORTFOLIO", "BOM_UPLOAD", "VIEW_VULNERABILITY", "VIEW_POLICY_VIOLATION"]
CONCURRENT_REQUESTS = 5
PAGE_SIZE = 500

# Create or lookup project

def get_or_create_project(name, version=None, parent_uuid=None, collection_logic=None,family=None):

    headers= {
        "X-Api-Key": API_KEY
    }

    resp = requests.get(
        f"{BASE_URL}/project/lookup",
        headers=headers,
        params={"name": name, "version": version}
    )
    
    if resp.status_code == 401:
        print("Login failed. Please check your API key.", file=sys.stderr)
        sys.exit(1)

    if resp.status_code == 200:
        project_uuid = resp.json()["uuid"]
        print(f"Project '{name}' (version {version}) exists: UUID = {project_uuid}")
    
        parent_resp = requests.get(
            f"{BASE_URL}/project/{project_uuid}",
            headers=headers
        )

        if parent_resp.status_code == 200:
            existing_parent = parent_resp.json().get("parent", {}).get("uuid")
    
            if parent_uuid is None or existing_parent == parent_uuid:
                return project_uuid,name
            
            else:
                print(f"Project '{name}' exists under different parent")
                name = f"{family}-{name}"

                resp = requests.get(
                        f"{BASE_URL}/project/lookup",
                        headers=headers,
                        params={"name": name, "version": version}
                    )
                
                if resp.status_code == 200:
                    project_uuid = resp.json()["uuid"]
                    print(f"Project '{name}' (version {version}) exists: UUID = {project_uuid}")
                    return project_uuid,name
        
        else:
            print(f"Failed to fetch project details: {parent_resp.text}", file=sys.stderr)
            sys.exit(1)

    payload = {"name": name}
    if version:
        payload["version"] = version
    if parent_uuid:
        payload["parent"] = {"uuid": parent_uuid}
    if collection_logic:
        payload["collectionLogic"] = collection_logic

    create_resp = requests.put(
        f"{BASE_URL}/project",
        headers=headers,
        json=payload
    )
    
    if create_resp.status_code in (200, 201):
        project_uuid = create_resp.json()["uuid"]
        print(f"Project '{name}' (version {version}) created: UUID = {project_uuid}")
        return project_uuid,name
    else:
        print(f"Failed to create project '{name}': Status {create_resp.status_code} - {create_resp.reason}", file=sys.stderr)
        sys.exit(1)

# Upload SBOM

def upload_sbom(sbom_path, project_name, project_version,parent_uuid,project_tags=None):

    headers_bom = {
        "X-Api-Key": API_KEY
    }

    with open(sbom_path, "rb") as f:
        files = {"bom": (os.path.basename(sbom_path), f, "application/json")}
        data = {
            "projectName": project_name,
            "autoCreate": "true",
            "parentUUID": parent_uuid
        }

        if project_version:
            data["projectVersion"] = project_version  # Add tags to the SBOM upload

        if project_tags:
            if isinstance(project_tags, list):
                data["projectTags"] = ",".join(project_tags)
            else:
                data["projectTags"] = project_tags

        r = requests.post(
            f"{BASE_URL}/bom",
            headers=headers_bom,
            files=files,
            data=data
        )
    
    if r.status_code not in (200, 201):
        return None, r.text
    else:
        print(f"Uploaded: {sbom_path}")

        # Look up the created/updated project UUID because POST /bom only returns a token
        lookup_resp = requests.get(
            f"{BASE_URL}/project/lookup",
            headers=headers_bom,
            params={"name": project_name, "version": project_version}
        )

        if lookup_resp.status_code == 200:
            return lookup_resp.json().get("uuid"), None
        else:
            print(f"Successfully uploaded, but failed to fetch project UUID via lookup: {lookup_resp.text}", file=sys.stderr)
            return None, lookup_resp.text

# Extract project name from SBOM

def get_project_name_from_sbom(sbom_path,product_version):
    """
    Project name -> SBOM metadata.component.name
    """

    with open(sbom_path, "r", encoding="utf-8") as f:
        sbom = json.load(f)

    name = (sbom.get("metadata", {}).get("component", {}).get("name"))

    if not name:
        raise ValueError(f"SBOM file '{sbom_path}' is missing 'metadata.component.name'")

    match = CONTAINER_PATTERN.match(name)
    
    if not match:
        return name, product_version, None
    
    project_name    = match.group(2)  # repository name
    project_tag     = [match.group(1), match.group(3)]  # tag

    return project_name, product_version, project_tag


# Process SBOM files

async def process_sbom_files(sbom_files, family, product, product_version):

    failed_sboms = []

    family_uuid, _ = get_or_create_project(
        name=family,
        collection_logic="AGGREGATE_DIRECT_CHILDREN"
    )

    product_uuid,final_product_name = get_or_create_project(
        name=product,
        parent_uuid=family_uuid,
        collection_logic="AGGREGATE_DIRECT_CHILDREN",
        family=family
    )

    product_version_uuid, _ = get_or_create_project(
        name=final_product_name,
        version=product_version,
        parent_uuid=product_uuid,
        collection_logic="AGGREGATE_DIRECT_CHILDREN"
    )

    # List to collect target project UUIDs
    uploaded_project_uuids = []

    if family_uuid: uploaded_project_uuids.append(family_uuid)
    if product_uuid: uploaded_project_uuids.append(product_uuid)
    if product_version_uuid: uploaded_project_uuids.append(product_version_uuid)
    
    mend_project_uuids = []

    for sbom_path in sbom_files:
        if not os.path.isfile(sbom_path):
            print(f"File not found: {sbom_path}", file=sys.stderr)
            continue

        if not str(sbom_path).endswith(".json"):
            print(f"Skipping non JSON file: {sbom_path}", file=sys.stderr)
            continue

        project_name,project_version,project_tag = get_project_name_from_sbom(sbom_path,product_version)

        project_name = f"{product}-{project_name}"

        project_uuid, error_message = upload_sbom(
            sbom_path=sbom_path,
            project_name=project_name,
            project_version=project_version,
            parent_uuid=product_version_uuid,
            project_tags=project_tag
        )

        if project_uuid:
            uploaded_project_uuids.append(project_uuid)
            mend_project_uuids.append(str(Path(sbom_path).stem))
        else:
            failed_sboms.append((project_name, error_message))

    if uploaded_project_uuids:
        team_uuid = await setup_team_and_oidc(family)
        if team_uuid:
            await add_acl_mapping(uploaded_project_uuids, team_uuid)
    else:
        print("No projects were successfully uploaded. Skipping team assignment.", file=sys.stderr)
        
    return uploaded_project_uuids, mend_project_uuids, failed_sboms

# ---------------- GET TEAM FUNCTION ----------------

async def fetch_team_page(session, page, semaphore):
    async with semaphore:
        params = {
            "pageNumber": str(page),
            "pageSize": str(PAGE_SIZE)
        }

        async with session.get(
            f"{BASE_URL}/team",
            headers=HEADERS,
            params=params
        ) as resp:

            if resp.status == 403:
                print(f"Failed to fetch: Status {resp.status} - {resp.reason}", file=sys.stderr)
                sys.exit(1)

            if resp.status != 200:
                print(f"Failed to fetch: Status {resp.status} - {resp.reason}", file=sys.stderr)
                return []
            
            return await resp.json()
        
async def get_team_uuid_by_name(team_name):
    print(f"Searching for team '{team_name}'...")

    semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS)

    async with aiohttp.ClientSession() as session:

        # First page
        first_page = await fetch_team_page(session, 1, semaphore)

        if not first_page:
            return None

        # Search first page
        for team in first_page:
            if team.get("name", "").lower() == team_name.lower():
                return team["uuid"]

        # If there are no more pages
        if len(first_page) < PAGE_SIZE:
            return None

        page = 2

        while True:

            tasks = [
                fetch_team_page(session, page + i, semaphore)
                for i in range(CONCURRENT_REQUESTS)
            ]

            results = await asyncio.gather(*tasks)

            last_page = False

            for index, teams in enumerate(results):

                for team in teams:
                    if team.get("name", "").lower() == team_name.lower():
                        return team["uuid"]

                if len(teams) < PAGE_SIZE:
                    last_page = True

            if last_page:
                break

            page += CONCURRENT_REQUESTS

    return None

# ================= TEAM and OIDC =================
async def setup_team_and_oidc(team_name):

    OIDC_GROUPS = [f"DT_{team_name}"]

    # ---------------- GET OR CREATE TEAM ----------------
    team_uuid = await get_team_uuid_by_name(team_name)

    if team_uuid:
        print(f"Team '{team_name}' already exists")
    else:
        print(f"Team not found. Creating team: {team_name}...")
        r = requests.put(
            f"{BASE_URL}/team",
            headers=HEADERS,
            json={"name": team_name}
        )

        if r.status_code not in (200, 201):
            print(f"Team creation failed: {r.status_code} - {r.reason}", file=sys.stderr)
            sys.exit(1)

        team_uuid = r.json()["uuid"]
        print(f"Team created: {team_name}")

    # ---------------- PERMISSIONS ----------------
    for perm in PERMISSIONS:
        r = requests.post(
            f"{BASE_URL}/permission/{perm}/team/{team_uuid}",
            headers=HEADERS
        )

        if r.status_code == 200:
            print(f"Permission added: {perm} to team '{team_name}'")
        elif r.status_code == 304:
            print(f"Permission already exists: {perm} to team '{team_name}'")
        else:
            print(f"Failed to add permission {perm} to team '{team_name}': {r.status_code} - {r.reason}", file=sys.stderr)
            sys.exit(1)

    # ---------------- OIDC GROUP (GET OR CREATE) ----------------
    def get_or_create_group_uuid(group_name):

        r = requests.get(f"{BASE_URL}/oidc/group", headers=HEADERS)

        if r.status_code != 200:
            print("Failed OIDC fetch:", r.text, file=sys.stderr)
            sys.exit(1)

        for g in r.json():
            if g.get("name", "").lower() == group_name.lower():
                print(f"OIDC group '{group_name}' already exists")
                return g["uuid"]

        print(f"Group not found: {group_name}.creating Group...")

        r = requests.put(
            f"{BASE_URL}/oidc/group",
            headers=HEADERS,
            json={"name": group_name}
        )

        if r.status_code != 201:
            print(f"Failed group create: {r.status_code} - {r.reason}", file=sys.stderr)
            sys.exit(1)
        
        print(f"Group created: {group_name}")
        return r.json()["uuid"]

    # ---------------- CHECK MAPPING ----------------
    def is_mapped(group_uuid, team_uuid):

        r = requests.get(
            f"{BASE_URL}/oidc/group/{group_uuid}/team",
            headers=HEADERS
        )

        if r.status_code == 404:
            return False

        if r.status_code != 200:
            print("Failed to check mapping:", r.reason, file=sys.stderr)
            sys.exit(1)

        return any(t.get("uuid") == team_uuid for t in r.json())

    # ---------------- MAP OIDC GROUP ----------------
    for group_name in OIDC_GROUPS:
        group_uuid = get_or_create_group_uuid(group_name)

        if not group_uuid:
            return

        if is_mapped(group_uuid, team_uuid):
            print(f"OIDC group '{group_name}' is already mapped to team '{team_name}'")
            continue
            

        r = requests.put(
            f"{BASE_URL}/oidc/mapping",
            headers=HEADERS,
            json={
                "group": group_uuid,
                "team": team_uuid
            }
        )

        if r.status_code == 200:
            print(f"OIDC Group: {group_name} mapped to team '{team_name}'")
        else:
            print(f"OIDC mapping failed: {r.status_code} - {r.reason}", file=sys.stderr)
            sys.exit(1)
    
    return team_uuid

async def add_acl_mapping(project_uuids, team_uuid):

    if not project_uuids or not team_uuid:
        return

    print(f"Mapping {len(project_uuids)} projects to team {team_uuid}...")

    semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS)

    async with aiohttp.ClientSession() as session:

        async def map_project(project_uuid):
            async with semaphore:

                async with session.put(
                    f"{BASE_URL}/acl/mapping",
                    headers=HEADERS,
                    json={
                        "project": project_uuid,
                        "team": team_uuid
                    }
                ) as resp:

                    if resp.status == 200:
                        pass
                    elif resp.status == 409:
                        print(f"ACL mapping already exists: project={project_uuid}")
                    else:
                        print(f"Failed ACL mapping for project {project_uuid}: {resp.status}", file=sys.stderr)
                        sys.exit(1)
                        
        tasks = [
            map_project(p)
            for p in project_uuids
        ]

        await asyncio.gather(*tasks)

# Main

async def main():
    parser = argparse.ArgumentParser(
        description="SBOM Import with Family Product SBOM hierarchy"
    )

    parser.add_argument("--url",required=False,help="Dependency Track base URL")
    parser.add_argument("--api-key", required=False, help="Dependency Track API Key")
    parser.add_argument("--family", required=True, help="Product family name")
    parser.add_argument("--product", required=True, help="Product name")
    parser.add_argument("--version", required=True, help="Product version")

    parser.add_argument(
       "files",
        nargs="+",
        help="One or more SBOM JSON files"
    )

    args = parser.parse_args()

    global API_KEY, DT_URL, BASE_URL
    API_KEY = args.api_key or API_KEY
    DT_URL = args.url or DT_URL

    if not DT_URL:
        print("Missing DT_URL! Please provide it using --url or set DT_URL in the .env file.", file=sys.stderr)
        sys.exit(1)

    BASE_URL = f"{DT_URL.rstrip('/')}/api/v1"

    if not API_KEY:
        print("Missing DT_API_KEY! Please provide it using --api-key or set DT_API_KEY in the .env file.", file=sys.stderr)
        sys.exit(1)

    uploaded_uuids, mend_uuids, failed_sboms = await process_sbom_files(
        sbom_files=args.files,
        family=args.family,
        product=args.product,
        product_version=args.version
    )

    if failed_sboms:
        print("\nSBOM UPLOAD FAILURES", file=sys.stderr)
        
        for name, error in failed_sboms:
            print(f"Failed to upload: {name} | Reason: {error}", file=sys.stderr)
        sys.exit(1)

# -------------------- Run --------------------
def run():
    asyncio.run(main())

if __name__ == "__main__":
    run()
