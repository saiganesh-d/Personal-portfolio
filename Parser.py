import json
import yaml
import xml.etree.ElementTree as ET
import re
from typing import List, Dict, Optional, Union, Any
from pathlib import Path
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

@dataclass
class ComponentInfo:
    """Standard component information structure"""
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    purl: Optional[str] = None

class UniversalSBOMParser:
    """Universal parser for SBOM files (NVD, CycloneDX, SPDX, PURL, OSV, SWID)"""
    
    def __init__(self):
        self.supported_formats = ['nvd', 'cyclonedx', 'spdx', 'purl', 'osv', 'swid']
    
    def detect_sbom_type(self, file_path: str) -> Optional[str]:
        """
        Detect SBOM type from file content
        Returns: 'nvd', 'cyclonedx', 'spdx', 'purl', 'osv', 'swid', or None
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            
            # Check for PURL list file first (simple text format)
            if self._is_purl_list(content):
                return 'purl'
            
            # Try JSON first
            if content.startswith('{') or content.startswith('['):
                try:
                    data = json.loads(content)
                    return self._detect_json_type(data)
                except json.JSONDecodeError:
                    pass
            
            # Try XML
            if content.startswith('<?xml') or '<' in content[:100]:
                try:
                    root = ET.fromstring(content)
                    return self._detect_xml_type(root)
                except ET.ParseError:
                    pass
            
            # Try YAML
            try:
                data = yaml.safe_load(content)
                if data:
                    return self._detect_yaml_type(data, content)
            except yaml.YAMLError:
                pass
            
            # Try tag-value format (SPDX)
            if self._is_spdx_tag_value(content):
                return 'spdx'
                
        except Exception as e:
            print(f"Error detecting SBOM type: {e}")
        
        return None
    
    def _is_purl_list(self, content: str) -> bool:
        """Check if content is a PURL list file"""
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        if not lines:
            return False
        
        # Check if most lines start with pkg: scheme
        purl_lines = sum(1 for line in lines if line.startswith('pkg:'))
        return purl_lines > 0 and (purl_lines / len(lines)) > 0.5
    
    def _detect_json_type(self, data: Any) -> Optional[str]:
        """Detect SBOM type from JSON data"""
        if isinstance(data, dict):
            # Check for OSV format
            if self._is_osv_format(data):
                return 'osv'
            
            # Check for NVD SBOM
            if 'CVE_Items' in data or 'cve_items' in data or 'vulnerabilities' in data:
                return 'nvd'
            
            # Check for CycloneDX
            if 'bomFormat' in data and data.get('bomFormat') == 'CycloneDX':
                return 'cyclonedx'
            if 'components' in data and 'metadata' in data:
                return 'cyclonedx'
            
            # Check for SPDX
            if 'spdxVersion' in data and 'SPDXID' in data:
                return 'spdx'
            if 'packages' in data and 'creationInfo' in data:
                return 'spdx'
            
            # Check for PURL-based formats
            if self._has_purl_components(data):
                return 'purl'
        
        elif isinstance(data, list):
            if not data:
                return None
            
            first_item = data[0] if data else {}
            
            # Check for OSV vulnerability list
            if self._is_osv_format(first_item):
                return 'osv'
            
            # Check for PURL list
            if isinstance(first_item, str) and first_item.startswith('pkg:'):
                return 'purl'
            
            # Could be NVD format with array of CVE items
            if isinstance(first_item, dict):
                if 'cve' in first_item or 'CVE_data_meta' in str(first_item):
                    return 'nvd'
        
        return None
    
    def _is_osv_format(self, data: dict) -> bool:
        """Check if data follows OSV schema"""
        # OSV required fields
        if 'id' in data and ('summary' in data or 'details' in data):
            return True
        
        # Check for OSV-specific fields
        osv_fields = ['schema_version', 'modified', 'published', 'affected', 'references']
        return sum(1 for field in osv_fields if field in data) >= 2
    
    def _has_purl_components(self, data: dict) -> bool:
        """Check if data contains PURL components"""
        if isinstance(data, dict):
            # Direct PURL field
            if 'purl' in data or 'purls' in data:
                return True
            
            # Components with PURL
            if 'components' in data:
                components = data['components']
                if isinstance(components, list) and components:
                    return any('purl' in comp for comp in components if isinstance(comp, dict))
        
        return False
    
    def _detect_xml_type(self, root) -> Optional[str]:
        """Detect SBOM type from XML root element"""
        tag = root.tag.lower()
        
        # SWID Tags
        if 'softwareidentity' in tag or 'swid' in tag:
            return 'swid'
        
        # CycloneDX XML
        if 'bom' in tag or 'cyclonedx' in tag:
            return 'cyclonedx'
        
        # SPDX XML
        if 'spdx' in tag or tag.endswith('spdxdocument'):
            return 'spdx'
        
        # NVD XML (less common but possible)
        if 'nvd' in tag or 'cve' in tag:
            return 'nvd'
        
        # Check namespaces
        if root.tag.startswith('{'):
            namespace = root.tag.split('}')[0][1:]
            if 'swid' in namespace.lower() or 'iso19770' in namespace.lower():
                return 'swid'
        
        # Check child elements
        children_tags = [child.tag.lower() for child in root]
        if any('component' in tag for tag in children_tags):
            return 'cyclonedx'
        if any('package' in tag for tag in children_tags):
            return 'spdx'
        if any('entity' in tag or 'evidence' in tag for tag in children_tags):
            return 'swid'
        
        return None
    
    def _detect_yaml_type(self, data: Any, raw_content: str) -> Optional[str]:
        """Detect SBOM type from YAML data"""
        if not isinstance(data, dict):
            return None
        
        # Check for OSV format
        if self._is_osv_format(data):
            return 'osv'
        
        # Check for CycloneDX YAML
        if data.get('bomFormat') == 'CycloneDX' or 'components' in data:
            return 'cyclonedx'
        
        # Check for SPDX YAML
        if 'spdxVersion' in data or 'packages' in data:
            return 'spdx'
        
        # Check for PURL-based YAML
        if self._has_purl_components(data):
            return 'purl'
        
        # Check raw content for hints
        if 'bomFormat:' in raw_content and 'CycloneDX' in raw_content:
            return 'cyclonedx'
        if 'spdxVersion:' in raw_content:
            return 'spdx'
        
        return None
    
    def _is_spdx_tag_value(self, content: str) -> bool:
        """Check if content is SPDX tag-value format"""
        lines = content.split('\n')[:50]  # Check first 50 lines
        spdx_tags = ['SPDXVersion:', 'SPDXID:', 'DocumentName:', 'PackageName:']
        return any(any(line.strip().startswith(tag) for tag in spdx_tags) for line in lines)
    
    def parse_sbom(self, file_path: str) -> Dict[str, Any]:
        """
        Parse SBOM file and return components
        Returns dict with 'type', 'format', and either 'cpe_items' or 'components'
        """
        sbom_type = self.detect_sbom_type(file_path)
        
        if not sbom_type:
            raise ValueError("Unknown or unsupported SBOM format")
        
        result = {
            'type': sbom_type,
            'format': self._detect_file_format(file_path),
            'components': [],
            'cpe_items': []
        }
        
        if sbom_type == 'nvd':
            result['cpe_items'] = self._parse_nvd_sbom(file_path)
        elif sbom_type == 'cyclonedx':
            result['components'] = self._parse_cyclonedx_sbom(file_path)
        elif sbom_type == 'spdx':
            result['components'] = self._parse_spdx_sbom(file_path)
        elif sbom_type == 'purl':
            result['components'] = self._parse_purl_sbom(file_path)
        elif sbom_type == 'osv':
            result['components'] = self._parse_osv_sbom(file_path)
        elif sbom_type == 'swid':
            result['components'] = self._parse_swid_sbom(file_path)
        
        return result
    
    def _detect_file_format(self, file_path: str) -> str:
        """Detect file format (json, xml, yaml, tag-value, text)"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
        
        if content.startswith('{') or content.startswith('['):
            return 'json'
        elif content.startswith('<?xml') or content.startswith('<'):
            return 'xml'
        elif self._is_purl_list(content):
            return 'text'
        elif ':' in content and not content.startswith('<'):
            # Could be YAML or tag-value
            try:
                yaml.safe_load(content)
                return 'yaml'
            except:
                return 'tag-value'
        
        return 'unknown'
    
    def _parse_purl_sbom(self, file_path: str) -> List[Dict[str, str]]:
        """Parse PURL-based SBOM and extract components"""
        format_type = self._detect_file_format(file_path)
        components = []
        
        if format_type == 'text':
            # Simple PURL list file
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if line.startswith('pkg:'):
                    comp = self._parse_purl_string(line)
                    if comp:
                        components.append(comp)
        
        elif format_type == 'json':
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            components = self._extract_purls_from_json(data)
        
        elif format_type == 'yaml':
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            components = self._extract_purls_from_json(data)  # Same structure
        
        return components
    
    def _parse_purl_string(self, purl: str) -> Optional[Dict[str, str]]:
        """Parse a single PURL string into component info"""
        try:
            # PURL format: pkg:type/namespace/name@version?qualifiers#subpath
            if not purl.startswith('pkg:'):
                return None
            
            # Remove pkg: prefix
            purl_part = purl[4:]
            
            # Split by # to separate subpath
            if '#' in purl_part:
                purl_part = purl_part.split('#')[0]
            
            # Split by ? to separate qualifiers
            if '?' in purl_part:
                purl_part = purl_part.split('?')[0]
            
            # Split by @ to separate version
            version = None
            if '@' in purl_part:
                purl_part, version = purl_part.rsplit('@', 1)
                version = unquote(version)
            
            # Split by / to get type, namespace, name
            parts = purl_part.split('/')
            if len(parts) < 2:
                return None
            
            pkg_type = parts[0]
            name = unquote(parts[-1])
            
            # Namespace (vendor) can be multiple parts
            namespace = None
            if len(parts) > 2:
                namespace = '/'.join(parts[1:-1])
                namespace = unquote(namespace)
            
            # Map package type to vendor when namespace is missing
            vendor = namespace
            if not vendor:
                vendor = self._map_purl_type_to_vendor(pkg_type)
            
            return {
                'vendor': vendor,
                'product': name,
                'version': version,
                'purl': purl
            }
        
        except Exception as e:
            print(f"Error parsing PURL {purl}: {e}")
            return None
    
    def _map_purl_type_to_vendor(self, pkg_type: str) -> Optional[str]:
        """Map PURL package type to likely vendor"""
        type_to_vendor = {
            'npm': 'npmjs',
            'pypi': 'python',
            'maven': 'apache',
            'nuget': 'microsoft',
            'gem': 'rubygems',
            'cargo': 'rust',
            'composer': 'packagist',
            'cocoapods': 'apple',
            'swift': 'apple',
            'golang': 'golang',
            'alpine': 'alpine',
            'debian': 'debian',
            'rpm': 'redhat',
            'docker': 'docker'
        }
        return type_to_vendor.get(pkg_type.lower())
    
    def _extract_purls_from_json(self, data: Any) -> List[Dict[str, str]]:
        """Extract PURLs from JSON/YAML structure"""
        components = []
        
        def extract_recursive(obj):
            if isinstance(obj, dict):
                # Direct PURL field
                if 'purl' in obj:
                    comp = self._parse_purl_string(obj['purl'])
                    if comp:
                        components.append(comp)
                
                # Components array
                if 'components' in obj and isinstance(obj['components'], list):
                    for comp in obj['components']:
                        extract_recursive(comp)
                
                # Recurse into other dict values
                for value in obj.values():
                    if isinstance(value, (dict, list)):
                        extract_recursive(value)
            
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, str) and item.startswith('pkg:'):
                        comp = self._parse_purl_string(item)
                        if comp:
                            components.append(comp)
                    elif isinstance(item, (dict, list)):
                        extract_recursive(item)
        
        extract_recursive(data)
        return components
    
    def _parse_osv_sbom(self, file_path: str) -> List[Dict[str, str]]:
        """Parse OSV format and extract affected components"""
        format_type = self._detect_file_format(file_path)
        components = []
        
        if format_type == 'json':
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle single OSV record or list
            osv_records = data if isinstance(data, list) else [data]
            
            for record in osv_records:
                affected = record.get('affected', [])
                for affected_item in affected:
                    comp = self._extract_osv_component(affected_item)
                    if comp:
                        components.append(comp)
        
        elif format_type == 'yaml':
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            osv_records = data if isinstance(data, list) else [data]
            
            for record in osv_records:
                affected = record.get('affected', [])
                for affected_item in affected:
                    comp = self._extract_osv_component(affected_item)
                    if comp:
                        components.append(comp)
        
        return components
    
    def _extract_osv_component(self, affected_item: Dict) -> Optional[Dict[str, str]]:
        """Extract component info from OSV affected item"""
        try:
            package = affected_item.get('package', {})
            
            name = package.get('name')
            ecosystem = package.get('ecosystem')
            purl = package.get('purl')
            
            # Extract version info from ranges or versions
            version = None
            if 'versions' in affected_item:
                versions = affected_item['versions']
                if versions:
                    version = versions[0]  # Take first version
            
            elif 'ranges' in affected_item:
                ranges = affected_item['ranges']
                for range_item in ranges:
                    events = range_item.get('events', [])
                    for event in events:
                        if 'introduced' in event:
                            version = event['introduced']
                            break
                    if version:
                        break
            
            # Map ecosystem to vendor
            vendor = ecosystem
            if ecosystem:
                vendor = self._map_ecosystem_to_vendor(ecosystem)
            
            comp_info = {
                'vendor': vendor,
                'product': name,
                'version': version
            }
            
            if purl:
                comp_info['purl'] = purl
            
            return comp_info
        
        except Exception as e:
            print(f"Error extracting OSV component: {e}")
            return None
    
    def _map_ecosystem_to_vendor(self, ecosystem: str) -> str:
        """Map OSV ecosystem to vendor name"""
        ecosystem_mapping = {
            'npm': 'npmjs',
            'PyPI': 'python',
            'Maven': 'apache',
            'NuGet': 'microsoft',
            'RubyGems': 'rubygems',
            'crates.io': 'rust',
            'Packagist': 'packagist',
            'Go': 'golang',
            'Debian': 'debian',
            'Alpine': 'alpine',
            'Ubuntu': 'canonical'
        }
        return ecosystem_mapping.get(ecosystem, ecosystem.lower())
    
    def _parse_swid_sbom(self, file_path: str) -> List[Dict[str, str]]:
        """Parse SWID tags and extract software identity"""
        components = []
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Handle different SWID structures
            software_identities = []
            
            # Direct SoftwareIdentity elements
            if 'softwareidentity' in root.tag.lower():
                software_identities.append(root)
            else:
                # Find all SoftwareIdentity elements
                for elem in root.iter():
                    if 'softwareidentity' in elem.tag.lower():
                        software_identities.append(elem)
            
            for swid_elem in software_identities:
                comp = self._extract_swid_component(swid_elem)
                if comp:
                    components.append(comp)
        
        except Exception as e:
            print(f"Error parsing SWID file: {e}")
        
        return components
    
    def _extract_swid_component(self, swid_elem) -> Optional[Dict[str, str]]:
        """Extract component info from SWID SoftwareIdentity element"""
        try:
            # Get attributes from SoftwareIdentity element
            name = swid_elem.get('name')
            version = swid_elem.get('version') or swid_elem.get('versionScheme')
            
            # Try to get vendor from various sources
            vendor = None
            
            # Check attributes
            vendor = (swid_elem.get('publisher') or 
                     swid_elem.get('creator') or 
                     swid_elem.get('licensor'))
            
            # Check Entity elements
            if not vendor:
                for entity in swid_elem.findall('.//*[contains(local-name(), "Entity")]'):
                    role = entity.get('role', '').lower()
                    if any(r in role for r in ['publisher', 'creator', 'licensor', 'vendor']):
                        vendor = entity.get('name')
                        break
            
            # Check Meta elements
            if not vendor:
                for meta in swid_elem.findall('.//*[contains(local-name(), "Meta")]'):
                    if meta.get('generator'):
                        vendor = meta.get('generator')
                        break
            
            return {
                'vendor': vendor,
                'product': name,
                'version': version
            }
        
        except Exception as e:
            print(f"Error extracting SWID component: {e}")
            return None
    
    # Keep all existing methods from previous version
    def _parse_nvd_sbom(self, file_path: str) -> List[str]:
        """Parse NVD SBOM and extract CPE items"""
        format_type = self._detect_file_format(file_path)
        cpe_items = []
        
        if format_type == 'json':
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Handle different NVD JSON structures
            if 'CVE_Items' in data:
                for item in data['CVE_Items']:
                    cpes = self._extract_cpes_from_cve_item(item)
                    cpe_items.extend(cpes)
            elif 'vulnerabilities' in data:
                for vuln in data['vulnerabilities']:
                    cpes = self._extract_cpes_from_vulnerability(vuln)
                    cpe_items.extend(cpes)
            elif isinstance(data, list):
                for item in data:
                    cpes = self._extract_cpes_from_cve_item(item)
                    cpe_items.extend(cpes)
        
        return list(set(cpe_items))  # Remove duplicates
    
    def _extract_cpes_from_cve_item(self, item: Dict) -> List[str]:
        """Extract CPE strings from CVE item"""
        cpes = []
        
        # CVE 4.0 format
        if 'configurations' in item:
            for config in item['configurations']:
                cpes.extend(self._extract_cpes_from_nodes(config.get('nodes', [])))
        
        # CVE 5.0 format
        if 'cve' in item and 'configurations' in item['cve']:
            for config in item['cve']['configurations']:
                cpes.extend(self._extract_cpes_from_nodes(config.get('nodes', [])))
        
        return cpes
    
    def _extract_cpes_from_vulnerability(self, vuln: Dict) -> List[str]:
        """Extract CPE strings from vulnerability object"""
        cpes = []
        
        if 'configurations' in vuln:
            for config in vuln['configurations']:
                cpes.extend(self._extract_cpes_from_nodes(config.get('nodes', [])))
        
        return cpes
    
    def _extract_cpes_from_nodes(self, nodes: List) -> List[str]:
        """Recursively extract CPE strings from configuration nodes"""
        cpes = []
        
        for node in nodes:
            if 'cpeMatch' in node:
                for cpe_match in node['cpeMatch']:
                    if 'cpe23Uri' in cpe_match:
                        cpes.append(cpe_match['cpe23Uri'])
                    elif 'cpe_name' in cpe_match:
                        cpes.append(cpe_match['cpe_name'])
            
            # Recursively check children
            if 'children' in node:
                cpes.extend(self._extract_cpes_from_nodes(node['children']))
        
        return cpes
    
    def _parse_cyclonedx_sbom(self, file_path: str) -> List[Dict[str, str]]:
        """Parse CycloneDX SBOM and extract components"""
        format_type = self._detect_file_format(file_path)
        components = []
        
        if format_type == 'json':
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            components = self._extract_cyclonedx_components_json(data)
        
        elif format_type == 'xml':
            tree = ET.parse(file_path)
            root = tree.getroot()
            components = self._extract_cyclonedx_components_xml(root)
        
        elif format_type == 'yaml':
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            components = self._extract_cyclonedx_components_json(data)  # Same structure as JSON
        
        return components
    
    def _extract_cyclonedx_components_json(self, data: Dict) -> List[Dict[str, str]]:
        """Extract components from CycloneDX JSON/YAML"""
        components = []
        
        for component in data.get('components', []):
            comp_info = {
                'vendor': component.get('publisher') or component.get('supplier', {}).get('name'),
                'product': component.get('name'),
                'version': component.get('version')
            }
            
            # Add PURL if present
            if 'purl' in component:
                comp_info['purl'] = component['purl']
            
            # Clean up vendor field
            if comp_info['vendor']:
                comp_info['vendor'] = str(comp_info['vendor']).strip()
            
            components.append(comp_info)
        
        return components
    
    def _extract_cyclonedx_components_xml(self, root) -> List[Dict[str, str]]:
        """Extract components from CycloneDX XML"""
        components = []
        
        # Handle namespace
        ns = {'': ''}
        if root.tag.startswith('{'):
            ns_uri = root.tag.split('}')[0][1:]
            ns = {'ns': ns_uri}
        
        component_elements = root.findall('.//ns:component' if ns.get('ns') else './/component', ns)
        
        for comp in component_elements:
            name_elem = comp.find('ns:name' if ns.get('ns') else 'name', ns)
            version_elem = comp.find('ns:version' if ns.get('ns') else 'version', ns)
            publisher_elem = comp.find('ns:publisher' if ns.get('ns') else 'publisher', ns)
            purl_elem = comp.find('ns:purl' if ns.get('ns') else 'purl', ns)
            
            comp_info = {
                'vendor': publisher_elem.text if publisher_elem is not None else None,
                'product': name_elem.text if name_elem is not None else None,
                'version': version_elem.text if version_elem is not None else None
            }
            
            if purl_elem is not None:
                comp_info['purl'] = purl_elem.text
            
            components.append(comp_info)
        
        return components
    
    def _parse_spdx_sbom(self, file_path: str) -> List[Dict[str, str]]:
        """Parse SPDX SBOM and extract components"""
        format_type = self._detect_file_format(file_path)
        components = []
        
        if format_type == 'json':
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            components = self._extract_spdx_components_json(data)
        
        elif format_type == 'xml':
            tree = ET.parse(file_path)
            root = tree.getroot()
            components = self._extract_spdx_components_xml(root)
        
        elif format_type == 'yaml':
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            components = self._extract_spdx_components_json(data)
        
        elif format_type == 'tag-value':
            components = self._extract_spdx_components_tag_value(file_path)
        
        return components
    
    def _extract_spdx_components_json(self, data: Dict) -> List[Dict[str, str]]:
        """Extract components from SPDX JSON/YAML"""
        components = []
        
        for package in data.get('packages', []):
            vendor = package.get('supplier', '')
            if vendor:
                vendor = vendor.replace('Organization: ', '').replace('Person: ', '').strip()
            
            comp_info = {
                'vendor': vendor or None,
                'product': package.get('name'),
                'version': package.get('versionInfo') or self._extract_version_from_url(package.get('downloadLocation'))
            }
            
            # Add external refs (may contain PURL)
            external_refs = package.get('externalRefs', [])
            for ref in external_refs:
                if ref.get('referenceType') == 'purl':
                    comp_info['purl'] = ref.get('referenceLocator')
                    break
            
            components.append(comp_info)
        
        return components
    
    def _extract_spdx_components_xml(self, root) -> List[Dict[str, str]]:
        """Extract components from SPDX XML"""
        components = []
        
        # Find all package elements (handle namespaces)
        packages = []
        for elem in root.iter():
            if 'package' in elem.tag.lower() and elem.tag.lower() != 'packages':
                packages.append(elem)
        
        for package in packages:
            name = None
            version = None
            vendor = None
            purl = None
            
            for child in package.iter():
                tag = child.tag.lower()
                if 'name' in tag and not any(x in tag for x in ['filename', 'pathname']):
                    name = child.text
                elif 'version' in tag:
                    version = child.text
                elif 'supplier' in tag:
                    vendor = child.text
                    if vendor:
                        vendor = vendor.replace('Organization: ', '').replace('Person: ', '').strip()
                elif 'externalref' in tag:
                    # Check for PURL in external references
                    ref_type = None
                    ref_locator = None
                    for ref_child in child:
                        if 'referencetype' in ref_child.tag.lower():
                            ref_type = ref_child.text
                        elif 'referencelocator' in ref_child.tag.lower():
                            ref_locator = ref_child.text
                    
                    if ref_type == 'purl' and ref_locator:
                        purl = ref_locator
            
            comp_info = {
                'vendor': vendor,
                'product': name,
                'version': version
            }
            
            if purl:
                comp_info['purl'] = purl
            
            components.append(comp_info)
        
        return components
    
    def _extract_spdx_components_tag_value(self, file_path: str) -> List[Dict[str, str]]:
        """Extract components from SPDX tag-value format"""
        components = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Split by PackageName to get individual packages
        package_blocks = content.split('PackageName:')[1:]
        
        for block in package_blocks:
            lines = block.strip().split('\n')
            
            name = lines[0].strip() if lines else None
            version = None
            vendor = None
            purl = None
            
            for line in lines[1:]:
                line = line.strip()
                if line.startswith('PackageVersion:'):
                    version = line.split(':', 1)[1].strip()
                elif line.startswith('PackageSupplier:'):
                    vendor = line.split(':', 1)[1].strip()
                    vendor = vendor.replace('Organization: ', '').replace('Person: ', '').strip()
                elif line.startswith('ExternalRef:') and 'purl' in line.lower():
                    # Extract PURL from external reference
                    parts = line.split()
                    for part in parts:
                        if part.startswith('pkg:'):
                            purl = part
                            break
            
            comp_info = {
                'vendor': vendor,
                'product': name,
                'version': version
            }
            
            if purl:
                comp_info['purl'] = purl
            
            components.append(comp_info)
        
        return components
    
    def _extract_version_from_url(self, url: str) -> Optional[str]:
        """Extract version from download URL"""
        if not url:
            return None
        
        # Version patterns
        patterns = [
            r'v?(\d+\.\d+\.\d+)',
            r'v?(\d+\.\d+)',
            r'(\d+\.\d+\.\d+[-_]\w+)',
            r'/(\d+\.\d+\.\d+)/',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        
        return None

# Example usage and utilities
class ComponentNormalizer:
    """Utility class to normalize and clean component data"""
    
    @staticmethod
    def normalize_vendor(vendor: str) -> Optional[str]:
        """Normalize vendor names"""
        if not vendor:
            return None
        
        vendor = vendor.strip().lower()
        
        # Common vendor name mappings
        vendor_mappings = {
            'apache software foundation': 'apache',
            'the apache software foundation': 'apache',
            'microsoft corporation': 'microsoft',
            'google inc': 'google',
            'google llc': 'google',
            'oracle corporation': 'oracle',
            'red hat inc': 'redhat',
            'canonical ltd': 'canonical',
            'nodejs': 'node.js',
            'npmjs': 'npm'
        }
        
        return vendor_mappings.get(vendor, vendor)
    
    @staticmethod
    def normalize_product(product: str) -> Optional[str]:
        """Normalize product names"""
        if not product:
            return None
        
        product = product.strip()
        
        # Remove common prefixes/suffixes
        prefixes_to_remove = ['lib', 'package-', 'npm-', 'python-']
        suffixes_to_remove = ['.js', '.py', '-js', '-python']
        
        product_lower = product.lower()
        for prefix in prefixes_to_remove:
            if product_lower.startswith(prefix):
                product = product[len(prefix):]
                break
        
        for suffix in suffixes_to_remove:
            if product_lower.endswith(suffix):
                product = product[:-len(suffix)]
                break
        
        return product.strip()
    
    @staticmethod
    def normalize_version(version: str) -> Optional[str]:
        """Normalize version strings"""
        if not version:
            return None
        
        version = version.strip()
        
        # Remove common prefixes
        if version.lower().startswith('v'):
            version = version[1:]
        
        # Remove build metadata (everything after +)
        if '+' in version:
            version = version.split('+')[0]
        
        return version.strip() if version.strip() else None

# Enhanced example usage
def main():
    """Example usage of the universal SBOM parser"""
    parser = UniversalSBOMParser()
    normalizer = ComponentNormalizer()
    
    # Example file path
    file_path = "example_sbom.json"  # Replace with your file
    
    try:
        # Detect SBOM type
        sbom_type = parser.detect_sbom_type(file_path)
        print(f"Detected SBOM type: {sbom_type}")
        
        if sbom_type:
            # Parse the SBOM
            result = parser.parse_sbom(file_path)
            print(f"Format: {result['format']}")
            print(f"Type: {result['type']}")
            
            if result['cpe_items']:
                print(f"\nFound {len(result['cpe_items'])} CPE items:")
                for cpe in result['cpe_items'][:10]:  # Show first 10
                    print(f"  {cpe}")
            
            if result['components']:
                print(f"\nFound {len(result['components'])} components:")
                for comp in result['components'][:10]:  # Show first 10
                    # Normalize component data
                    normalized_vendor = normalizer.normalize_vendor(comp.get('vendor'))
                    normalized_product = normalizer.normalize_product(comp.get('product'))
                    normalized_version = normalizer.normalize_version(comp.get('version'))
                    
                    print(f"  Vendor: {normalized_vendor}")
                    print(f"  Product: {normalized_product}")
                    print(f"  Version: {normalized_version}")
                    if comp.get('purl'):
                        print(f"  PURL: {comp['purl']}")
                    print("  ---")
        else:
            print("Unknown or unsupported SBOM format")
        
    except Exception as e:
        print(f"Error: {e}")

# Utility function to convert components to CPE format
def components_to_cpe(components: List[Dict[str, str]]) -> List[str]:
    """Convert component list to CPE 2.3 format for CVE database queries"""
    normalizer = ComponentNormalizer()
    cpes = []
    
    for comp in components:
        vendor = normalizer.normalize_vendor(comp.get('vendor')) or '*'
        product = normalizer.normalize_product(comp.get('product')) or '*'
        version = normalizer.normalize_version(comp.get('version')) or '*'
        
        # Sanitize for CPE format
        vendor = re.sub(r'[^a-zA-Z0-9._-]', '_', vendor)
        product = re.sub(r'[^a-zA-Z0-9._-]', '_', product)
        version = re.sub(r'[^a-zA-Z0-9._-]', '_', version)
        
        cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        cpes.append(cpe)
    
    return cpes

# Batch processing function
def process_sbom_directory(directory_path: str) -> Dict[str, Dict]:
    """Process all SBOM files in a directory"""
    parser = UniversalSBOMParser()
    results = {}
    
    directory = Path(directory_path)
    sbom_extensions = ['.json', '.xml', '.yaml', '.yml', '.spdx', '.txt']
    
    for file_path in directory.iterdir():
        if file_path.suffix.lower() in sbom_extensions:
            try:
                result = parser.parse_sbom(str(file_path))
                results[file_path.name] = {
                    'status': 'success',
                    'type': result['type'],
                    'format': result['format'],
                    'component_count': len(result['components']),
                    'cpe_count': len(result['cpe_items']),
                    'components': result['components'],
                    'cpe_items': result['cpe_items']
                }
            except Exception as e:
                results[file_path.name] = {
                    'status': 'error',
                    'error': str(e)
                }
    
    return results

if __name__ == "__main__":
    main()
