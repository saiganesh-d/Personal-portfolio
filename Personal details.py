import json
import yaml
import xml.etree.ElementTree as ET
import re
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path

class SPDXComponent:
    """Represents a software component extracted from SPDX SBOM"""
    def __init__(self, name: str, version: str = None, vendor: str = None, 
                 download_location: str = None, package_id: str = None):
        self.name = name
        self.version = version
        self.vendor = vendor
        self.download_location = download_location
        self.package_id = package_id
    
    def __repr__(self):
        return f"SPDXComponent(name='{self.name}', version='{self.version}', vendor='{self.vendor}')"

class SPDXParser:
    """Parser for SPDX SBOM files in multiple formats"""
    
    @staticmethod
    def detect_spdx_format(file_path: str) -> Optional[str]:
        """
        Detect if file is SPDX SBOM and return format type
        Returns: 'json', 'yaml', 'xml', 'tag-value', or None
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                
            # Check for JSON format
            if content.startswith('{'):
                try:
                    data = json.loads(content)
                    if SPDXParser._is_spdx_json(data):
                        return 'json'
                except:
                    pass
            
            # Check for YAML format
            if any(line.strip().startswith(('spdxVersion:', 'SPDXID:', 'documentName:', 'creationInfo:')) 
                   for line in content.split('\n')[:20]):
                try:
                    data = yaml.safe_load(content)
                    if SPDXParser._is_spdx_yaml(data):
                        return 'yaml'
                except:
                    pass
            
            # Check for XML format
            if content.startswith('<?xml') or '<spdx:' in content[:200]:
                try:
                    root = ET.fromstring(content)
                    if SPDXParser._is_spdx_xml(root):
                        return 'xml'
                except:
                    pass
            
            # Check for tag-value format
            if any(line.strip().startswith(('SPDXVersion:', 'SPDXID:', 'DocumentName:', 'CreationInfo:'))
                   for line in content.split('\n')[:50]):
                return 'tag-value'
                
        except Exception as e:
            print(f"Error detecting SPDX format: {e}")
            
        return None
    
    @staticmethod
    def _is_spdx_json(data: dict) -> bool:
        """Check if JSON data represents SPDX document"""
        required_fields = ['spdxVersion', 'SPDXID', 'creationInfo']
        return all(field in data for field in required_fields)
    
    @staticmethod
    def _is_spdx_yaml(data: dict) -> bool:
        """Check if YAML data represents SPDX document"""
        if not isinstance(data, dict):
            return False
        required_fields = ['spdxVersion', 'SPDXID', 'creationInfo']
        return all(field in data for field in required_fields)
    
    @staticmethod
    def _is_spdx_xml(root) -> bool:
        """Check if XML represents SPDX document"""
        # Check for SPDX namespace or common SPDX elements
        return (root.tag.endswith('SpdxDocument') or 
                'spdx' in root.tag.lower() or
                any(child.tag.endswith(('creationInfo', 'packages')) for child in root))
    
    @staticmethod
    def parse_spdx_file(file_path: str) -> List[SPDXComponent]:
        """
        Parse SPDX file and extract software components
        """
        format_type = SPDXParser.detect_spdx_format(file_path)
        
        if not format_type:
            raise ValueError("File is not a valid SPDX SBOM")
        
        if format_type == 'json':
            return SPDXParser._parse_json(file_path)
        elif format_type == 'yaml':
            return SPDXParser._parse_yaml(file_path)
        elif format_type == 'xml':
            return SPDXParser._parse_xml(file_path)
        elif format_type == 'tag-value':
            return SPDXParser._parse_tag_value(file_path)
        else:
            raise ValueError(f"Unsupported SPDX format: {format_type}")
    
    @staticmethod
    def _parse_json(file_path: str) -> List[SPDXComponent]:
        """Parse JSON SPDX format"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        components = []
        packages = data.get('packages', [])
        
        for package in packages:
            name = package.get('name')
            if not name:
                continue
                
            version = package.get('versionInfo')
            vendor = package.get('supplier', '').replace('Organization: ', '').replace('Person: ', '')
            download_location = package.get('downloadLocation')
            package_id = package.get('SPDXID')
            
            # Extract version from download URL if not explicitly provided
            if not version and download_location:
                version = SPDXParser._extract_version_from_url(download_location)
            
            components.append(SPDXComponent(
                name=name,
                version=version,
                vendor=vendor,
                download_location=download_location,
                package_id=package_id
            ))
        
        return components
    
    @staticmethod
    def _parse_yaml(file_path: str) -> List[SPDXComponent]:
        """Parse YAML SPDX format"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        components = []
        packages = data.get('packages', [])
        
        for package in packages:
            name = package.get('name')
            if not name:
                continue
                
            version = package.get('versionInfo')
            vendor = package.get('supplier', '').replace('Organization: ', '').replace('Person: ', '')
            download_location = package.get('downloadLocation')
            package_id = package.get('SPDXID')
            
            if not version and download_location:
                version = SPDXParser._extract_version_from_url(download_location)
            
            components.append(SPDXComponent(
                name=name,
                version=version,
                vendor=vendor,
                download_location=download_location,
                package_id=package_id
            ))
        
        return components
    
    @staticmethod
    def _parse_xml(file_path: str) -> List[SPDXComponent]:
        """Parse XML SPDX format"""
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        components = []
        
        # Handle different XML structures
        packages = []
        if root.tag.endswith('SpdxDocument'):
            packages = root.findall('.//*[contains(local-name(), "Package")]')
        else:
            packages = root.findall('.//Package') or root.findall('.//package')
        
        for package in packages:
            name_elem = package.find('.//*[contains(local-name(), "name")]')
            name = name_elem.text if name_elem is not None else None
            
            if not name:
                continue
            
            version_elem = package.find('.//*[contains(local-name(), "versionInfo")]')
            version = version_elem.text if version_elem is not None else None
            
            supplier_elem = package.find('.//*[contains(local-name(), "supplier")]')
            vendor = supplier_elem.text if supplier_elem is not None else None
            if vendor:
                vendor = vendor.replace('Organization: ', '').replace('Person: ', '')
            
            download_elem = package.find('.//*[contains(local-name(), "downloadLocation")]')
            download_location = download_elem.text if download_elem is not None else None
            
            spdxid_elem = package.find('.//*[contains(local-name(), "SPDXID")]')
            package_id = spdxid_elem.text if spdxid_elem is not None else None
            
            if not version and download_location:
                version = SPDXParser._extract_version_from_url(download_location)
            
            components.append(SPDXComponent(
                name=name,
                version=version,
                vendor=vendor,
                download_location=download_location,
                package_id=package_id
            ))
        
        return components
    
    @staticmethod
    def _parse_tag_value(file_path: str) -> List[SPDXComponent]:
        """Parse tag-value SPDX format"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        components = []
        packages = content.split('PackageName:')[1:]  # Split by package sections
        
        for package_block in packages:
            lines = package_block.strip().split('\n')
            
            name = lines[0].strip() if lines else None
            if not name:
                continue
            
            version = None
            vendor = None
            download_location = None
            package_id = None
            
            for line in lines:
                line = line.strip()
                if line.startswith('PackageVersion:'):
                    version = line.split(':', 1)[1].strip()
                elif line.startswith('PackageSupplier:'):
                    vendor = line.split(':', 1)[1].strip()
                    vendor = vendor.replace('Organization: ', '').replace('Person: ', '')
                elif line.startswith('PackageDownloadLocation:'):
                    download_location = line.split(':', 1)[1].strip()
                elif line.startswith('SPDXID:'):
                    package_id = line.split(':', 1)[1].strip()
            
            if not version and download_location:
                version = SPDXParser._extract_version_from_url(download_location)
            
            components.append(SPDXComponent(
                name=name,
                version=version,
                vendor=vendor,
                download_location=download_location,
                package_id=package_id
            ))
        
        return components
    
    @staticmethod
    def _extract_version_from_url(url: str) -> Optional[str]:
        """Extract version from download URL using regex patterns"""
        if not url:
            return None
        
        # Common version patterns
        patterns = [
            r'v?(\d+\.\d+\.\d+)',  # x.y.z
            r'v?(\d+\.\d+)',       # x.y
            r'(\d+\.\d+\.\d+[-_]\w+)',  # x.y.z-alpha
            r'/(\d+\.\d+\.\d+)/',  # version in path
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        
        return None

# Example usage and CPE generation helper
class CPEGenerator:
    """Helper class to generate CPE identifiers from SPDX components"""
    
    @staticmethod
    def generate_cpe23_uri(component: SPDXComponent) -> str:
        """
        Generate CPE 2.3 URI format from SPDX component
        Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        """
        vendor = CPEGenerator._sanitize_cpe_component(component.vendor) if component.vendor else "*"
        product = CPEGenerator._sanitize_cpe_component(component.name) if component.name else "*"
        version = CPEGenerator._sanitize_cpe_component(component.version) if component.version else "*"
        
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    
    @staticmethod
    def _sanitize_cpe_component(value: str) -> str:
        """Sanitize component for CPE format"""
        if not value:
            return "*"
        
        # Convert to lowercase and replace special characters
        sanitized = value.lower()
        sanitized = re.sub(r'[^a-z0-9._-]', '_', sanitized)
        sanitized = re.sub(r'_+', '_', sanitized)  # Collapse multiple underscores
        sanitized = sanitized.strip('_')
        
        return sanitized if sanitized else "*"

# Example usage
def main():
    """Example usage of the SPDX parser"""
    file_path = "example.spdx"  # Replace with your file path
    
    # Detect if file is SPDX
    format_type = SPDXParser.detect_spdx_format(file_path)
    if format_type:
        print(f"Detected SPDX format: {format_type}")
        
        # Parse the file
        try:
            components = SPDXParser.parse_spdx_file(file_path)
            print(f"Found {len(components)} components:")
            
            for component in components:
                print(f"  {component}")
                # Generate CPE for CVE lookup
                cpe = CPEGenerator.generate_cpe23_uri(component)
                print(f"    CPE: {cpe}")
                
        except Exception as e:
            print(f"Error parsing SPDX file: {e}")
    else:
        print("File is not a valid SPDX SBOM")

if __name__ == "__main__":
    main()
