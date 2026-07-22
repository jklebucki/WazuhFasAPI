"""Bootstrap manifest models."""

from datetime import datetime

from pydantic import Field

from app.models.common import ApiModel


class TargetAgent(ApiModel):
    version: str
    package_revision: str
    full_package_version: str
    msi_file_name: str
    download_url: str
    sha256: str | None = None


class ManagerManifest(ApiModel):
    version: str
    address: str
    communication_port: int
    registration_address: str
    registration_port: int
    compatible: bool


class WindowsManifest(ApiModel):
    service_name: str = "WazuhSvc"
    install_directories: list[str] = Field(
        default_factory=lambda: [
            r"C:\Program Files (x86)\ossec-agent",
            r"C:\Program Files\ossec-agent",
        ]
    )
    key_file_name: str = "client.keys"
    config_file_name: str = "ossec.conf"
    executable_name: str = "wazuh-agent.exe"


class Manifest(ApiModel):
    schema_version: int = 1
    target_agent: TargetAgent
    manager: ManagerManifest
    windows: WindowsManifest
    generated_at: datetime
    data_as_of: datetime
    stale: bool
