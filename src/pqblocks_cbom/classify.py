"""classify_component and canonicalize_property - PQ algorithm classification."""

from typing import Any, Dict, Iterable


def classify_component(name: str, version: str, imports: Iterable[str]) -> Dict[str, str]:
    """Classify a component by its PQC algorithm family.

    Args:
        name: Component name.
        version: Component version.
        imports: Iterable of import/dependency hints.

    Returns:
        Dict with family, classification, key_size, std_reference, vendor_id.
    """
    name_lower = name.lower()
    imports_list = list(imports)
    result = {
        'family': 'UNKNOWN',
        'classification': 'UNKNOWN',
        'key_size': '',
        'std_reference': '',
        'vendor_id': '',
    }

    # liboqs detection (PQ algorithms: ML-KEM / Kyber)
    if any('liboqs' in imp or imp == 'oqs' for imp in imports_list) \
            or 'liboqs' in name_lower or 'oqs' in name_lower:
        result['family'] = 'ML-KEM'
        result['classification'] = 'SAFE'
        result['key_size'] = '768'
        result['std_reference'] = 'FIPS 203'
        result['vendor_id'] = 'IAOE'
        return result

    # OpenSSL detection
    if 'openssl' in name_lower or any('openssl' in imp for imp in imports_list):
        result['family'] = 'X25519Kyber768'
        result['classification'] = 'TRANSITIONAL'
        result['key_size'] = '768'
        result['std_reference'] = 'FIPS 203'
        result['vendor_id'] = 'OSSL'
        return result

    # pyca/cryptography detection
    if 'cryptography' in name_lower or any('cryptography' in imp for imp in imports_list):
        result['family'] = 'ML-DSA'
        result['classification'] = 'SAFE'
        result['key_size'] = '65'
        result['std_reference'] = 'FIPS 204'
        result['vendor_id'] = 'PyCA'
        return result

    # ML-DSA / Dilithium direct
    if 'dilithium' in name_lower or 'ml-dsa' in name_lower or 'mldsa' in name_lower:
        result['family'] = 'ML-DSA'
        result['classification'] = 'SAFE'
        result['key_size'] = '65'
        result['std_reference'] = 'FIPS 204'
        result['vendor_id'] = 'NIST'
        return result

    # SLH-DSA / SPHINCS+
    if 'sphincs' in name_lower or 'slh-dsa' in name_lower or 'slhdsa' in name_lower:
        result['family'] = 'SLH-DSA'
        result['classification'] = 'SAFE'
        result['key_size'] = '128s'
        result['std_reference'] = 'FIPS 205'
        result['vendor_id'] = 'NIST'
        return result

    # Falcon
    if 'falcon' in name_lower:
        result['family'] = 'FN-DSA'
        result['classification'] = 'SAFE'
        result['key_size'] = '512'
        result['std_reference'] = 'FIPS 206 (draft)'
        result['vendor_id'] = 'NIST'
        return result

    # Classical RSA (legacy)
    if 'rsa' in name_lower:
        result['family'] = 'RSA'
        result['classification'] = 'UNSAFE'
        result['key_size'] = '2048'
        result['std_reference'] = ''
        result['vendor_id'] = ''
        return result

    # Classical ECC
    if 'ecdsa' in name_lower or 'ec' in name_lower.split('-'):
        result['family'] = 'ECDSA'
        result['classification'] = 'UNSAFE'
        result['key_size'] = '256'
        result['std_reference'] = ''
        result['vendor_id'] = ''
        return result

    return result


def canonicalize_property(name: str, value: str) -> str:
    """Canonicalize a property name/value pair to the standard CBOM form.

    Args:
        name: Property name (e.g. 'appliedquantum:algorithm:family').
        value: Property value.

    Returns:
        Canonicalized "name=value" string using dot separators.
    """
    # Replace colon separators with dots
    canonical_name = name.replace(':', '.')
    return f"{canonical_name}={value}"
