from enum import Enum


class AssetType(Enum):
    EXPOSED_PANEL = "exposed_panel"
    DOMAIN = "domain"
    IP = "ip"

    OPEN_PORT = "open_port"

    CMS = "cms"
    CMS_PLUGIN = "cms_plugin"

    VPN = "vpn"

    TECHNOLOGY = "technology"
