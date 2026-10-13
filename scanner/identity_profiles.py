"""Operator-reviewed read-only identity parsers; no executable profile code."""
import json
import os
import re
from pathlib import Path
from typing import Literal
from xml.etree import ElementTree

from pydantic import BaseModel, ConfigDict, Field

IdentityField = Literal['manufacturer', 'model', 'firmware', 'device_type']


class IdentityProfile(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(pattern=r'^[a-z0-9-]{1,64}$')
    reviewed: bool = False
    source_url: str = Field(pattern=r'^https://[^\s]+$', max_length=500)
    path: str = Field(pattern=r'^/[A-Za-z0-9/_-]*$', max_length=150)
    format: Literal['json', 'xml']
    manufacturer: str = Field(min_length=2, max_length=100)
    fields: dict[IdentityField, str] = Field(min_length=2, max_length=4)


def load_profiles() -> list[IdentityProfile]:
    filename = os.getenv('DEVICE_IDENTITY_PROFILE_FILE', '')
    if not filename:
        return []
    with Path(filename).open('rb') as stream:
        data = stream.read(100_001)
    if len(data) > 100_000:
        raise ValueError('Identity profile file exceeds size limit.')
    rows = json.loads(data)
    if not isinstance(rows, list) or len(rows) > 100:
        raise ValueError('Expected at most 100 identity profiles.')
    profiles = [IdentityProfile.model_validate(row) for row in rows]
    for profile in profiles:
        if not {'manufacturer', 'model'} <= profile.fields.keys():
            raise ValueError('Manufacturer and model selectors are required.')
        if any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*(/[A-Za-z_][A-Za-z0-9_-]*){0,7}', p)
               for p in profile.fields.values()):
            raise ValueError('Only simple field paths are supported.')
    if len({p.id for p in profiles}) != len(profiles):
        raise ValueError('Duplicate identity profile IDs.')
    return [p for p in profiles if p.reviewed]


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field.')
        result[key] = value
    return result


def extract(body: str, profile: IdentityProfile) -> dict:
    if not profile.reviewed or len(body.encode('utf-8')) > 65_536:
        raise ValueError('Unreviewed profile or oversized body.')
    if profile.format == 'json':
        document = json.loads(body, object_pairs_hook=_unique_object)
    else:
        if re.search(r'<!\s*(DOCTYPE|ENTITY)', body, re.I):
            raise ValueError('XML declarations are unsupported.')
        document = ElementTree.fromstring(body)
    result = dict.fromkeys(('manufacturer', 'model', 'firmware', 'device_type'), 'Unknown')
    evidence = {}
    for field, path in profile.fields.items():
        parts = path.split('/')
        if profile.format == 'json':
            value = document
            for part in parts:
                value = value.get(part) if isinstance(value, dict) else None
            values = [value]
        else:
            nodes = [document]
            if document.tag.rsplit('}', 1)[-1] != parts[0]:
                nodes = []
            for part in parts[1:]:
                nodes = [child for node in nodes for child in node
                         if child.tag.rsplit('}', 1)[-1] == part]
            values = [node.text for node in nodes if not len(node)]
        clean = {v.strip() for v in values if isinstance(v, str)
                 and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._()/+-]{0,99}', v.strip())}
        if len(clean) == 1:
            result[field] = clean.pop()
            evidence[field] = {'path': path, 'value': result[field], 'source': profile.path}
    if result['manufacturer'] != profile.manufacturer:
        return {'status': 'profile_mismatch', **dict.fromkeys(result, 'Unknown'), 'evidence': {}}
    return {'status': 'observed', **result, 'evidence': evidence,
            'profile_id': profile.id, 'profile_source': profile.source_url,
            'source': profile.path, 'confidence': 'Device-reported; not independently verified'}
