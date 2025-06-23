"""
login <A6> # for demo, just 1 passcode which we called <A6>
create --group --name <group.name> --location <cluster.id:server.id>
create --member --name <member.name> --group <group.id>
create --role <profile.permit_profiles_file> --credentials <profile.permit_file> # including quorum setting, e.g. k of N

set_feeds --subscribe <URIs>
set --resource <diagnostics|logging|backup|> --state <activate> --settings <>

get --status <connected>
“””
Admin: setting,  no ops
Officers: profile and roles setting, audit, no ops (curator, auditor, etc)
Users: Ops
“””

Do this 1st to create the permit:

```
%%writefile permit_profile.yaml
# permit_profile.yaml
login: "A6"

group:
  name: "alpha-team"
  location: "cluster42:server03"

member:
  name: "alice"

role:
  profile_file: "officer_profile.json"
  credentials_file: "officer_creds.json"
  quorum: "2-of-3"

feeds:
  subscribe:
    - "uri://metrics"
    - "uri://alerts"

resources:
  diagnostics:
    state: "activate"
    settings: {"level": "debug"}

  logging:
    state: "activate"
    settings: {"retention_days": 14}

  backup:
    state: "activate"
    settings: {"frequency": "daily"}

```
"""
import uuid
import yaml

# Simulated in-memory database
DATABASE = {
    'users': {},
    'groups': {},
    'members': {},
    'roles': {},
    'subscriptions': [],
    'resources': {},
    'status': "disconnected"
}

ROLE_MATRIX = {
    'Admin': ['setting'],
    'Officer': ['profile', 'roles', 'audit'],
    'User': ['ops']
}

# Simulate login
def login(key):
    if key == "A6":
        DATABASE['status'] = "connected"
        return True
    return False

def create_group(name, location):
    group_id = str(uuid.uuid4())
    DATABASE['groups'][group_id] = {'name': name, 'location': location}
    return group_id

def create_member(name, group_id):
    member_id = str(uuid.uuid4())
    DATABASE['members'][member_id] = {'name': name, 'group': group_id}
    return member_id

def create_role(profile_file, credentials_file, quorum):
    role_id = str(uuid.uuid4())
    DATABASE['roles'][role_id] = {
        'profile': profile_file,
        'credentials': credentials_file,
        'quorum': quorum
    }
    return role_id

def set_feeds_subscribe(uris):
    DATABASE['subscriptions'].extend(uris)

def set_resource(resource_type, state, settings):
    DATABASE['resources'][resource_type] = {
        'state': state,
        'settings': settings
    }

def get_status():
    return DATABASE['status']

# Main runner
def simulate_from_profile(profile_path):
    with open(profile_path, 'r') as f:
        config = yaml.safe_load(f)

    # 1. Login
    if not login(config['login']):
        print("Login failed")
        return
    print("Login successful")

    # 2. Group creation
    group_cfg = config['group']
    group_id = create_group(group_cfg['name'], group_cfg['location'])
    print(f"Group created [{group_cfg['name']}] at {group_cfg['location']} -> ID: {group_id}")

    # 3. Member creation
    member_cfg = config['member']
    member_id = create_member(member_cfg['name'], group_id)
    print(f"Member created [{member_cfg['name']}] in group {group_id} -> ID: {member_id}")

    # 4. Role creation
    role_cfg = config['role']
    role_id = create_role(role_cfg['profile_file'], role_cfg['credentials_file'], role_cfg['quorum'])
    print(f"Role created with quorum {role_cfg['quorum']} -> ID: {role_id}")

    # 5. Set feeds
    set_feeds_subscribe(config['feeds']['subscribe'])
    print("Feeds subscribed:", config['feeds']['subscribe'])

    # 6. Set resources
    for rtype, rdata in config['resources'].items():
        set_resource(rtype, rdata['state'], rdata['settings'])
        print(f"Resource [{rtype}] set to [{rdata['state']}] with settings {rdata['settings']}")

    # 7. Final status
    print("System status:", get_status())


# Run the simulation
if __name__ == "__main__":
    simulate_from_profile("permit_profile.yaml")

"""
Login successful
Group created [alpha-team] at cluster42:server03 -> ID: 8d08c281-03c3-465c-a890-ddbeee013338
Member created [alice] in group 8d08c281-03c3-465c-a890-ddbeee013338 -> ID: ca615d8f-ab86-42c0-a6c9-3e0d8c1e0d78
Role created with quorum 2-of-3 -> ID: c957563b-0414-4795-a683-605768691239
Feeds subscribed: ['uri://metrics', 'uri://alerts']
Resource [diagnostics] set to [activate] with settings {'level': 'debug'}
Resource [logging] set to [activate] with settings {'retention_days': 14}
Resource [backup] set to [activate] with settings {'frequency': 'daily'}
System status: connected
"""