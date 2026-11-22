from datetime import datetime, timezone
from typing import Literal, Any
from pydantic import BaseModel, Field, field_validator

IndicatorType=Literal['ip','domain','url','hash']
class Indicator(BaseModel):
    type: IndicatorType
    value: str = Field(min_length=1,max_length=2048)
    @field_validator('value')
    @classmethod
    def normalize(cls,v): return v.strip().lower()
class EnrichRequest(BaseModel):
    indicators: list[Indicator] = Field(min_length=1,max_length=100)
    correlation_id: str = Field(default='auto',max_length=128)
    requested_by: str = Field(default='api',max_length=128)
class Reputation(BaseModel):
    score:int=Field(ge=0,le=100)
    malicious:bool
    confidence:float=Field(ge=0,le=1)
    sources:list[str]=[]
class Geo(BaseModel):
    country:str|None=None
    asn:str|None=None
    organization:str|None=None
class EvidenceItem(BaseModel):
    indicator:Indicator
    reputation:Reputation
    geo:Geo
    techniques:list[str]=[]
    history:list[dict[str,Any]]=[]
    freshness:dict[str,Any]
    provenance:list[dict[str,Any]]=[]
    errors:list[str]=[]
class EvidenceBundle(BaseModel):
    correlation_id:str
    generated_at:datetime
    items:list[EvidenceItem]
