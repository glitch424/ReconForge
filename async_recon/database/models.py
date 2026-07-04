from pydantic import BaseModel, ConfigDict
from typing import Optional


class SubdomainRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    target: str
    subdomain: str
    source: str
    resolved: bool = False
    is_wildcard: bool = False


class DNSRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    subdomain_id: int
    record_type: str
    value: str
