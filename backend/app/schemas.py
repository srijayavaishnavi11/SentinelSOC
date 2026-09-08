from pydantic import BaseModel
from typing import Optional


class SecurityEventCreate(BaseModel):
    event_type: str
    source_ip: str
    username: Optional[str] = None
    destination_port: Optional[int] = None
    severity: str
    message: str