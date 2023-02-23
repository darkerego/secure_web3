import json


def load_networks() -> list:
    networks = []
    with open('data/networks.json', 'r') as f:
        network_map = json.load(f)

    for network in network_map.get('networks'):
        networks.append(network.get('name'))
    return networks
