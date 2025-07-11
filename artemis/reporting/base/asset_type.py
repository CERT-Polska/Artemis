from enum import Enum


class AssetType(Enum):
    EXPOSED_PANEL = "exposed_panel"
    DOMAIN = "domain"
    IP = "ip"

    CMS = "cms"
    CMS_PLUGIN = "cms_plugin"

    VPN = "vpn"

    TECHNOLOGY = "technology"
