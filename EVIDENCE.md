# Cryptographic Evidence: pqblocks-cbom

## Standards & Specifications

1. **OWASP CycloneDX v1.5 Standard**:
   - Bill of materials format for components, services, and cryptographic assets.
   - Property taxonomy: key-value pairs assigned under component attributes.
2. **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard
   - Table 3: ML-KEM Parameter Sets (ML-KEM-512, ML-KEM-768, ML-KEM-1024).
   - Table 4: Key and Ciphertext Lengths.
3. **NIST FIPS 204**: Module-Lattice-Based Digital Signature Standard
   - Table 2: ML-DSA Parameter Sets (ML-DSA-44, ML-DSA-65, ML-DSA-87).
4. **NIST FIPS 205**: Stateless Hash-Based Digital Signature Standard
   - Table 2: SLH-DSA Parameter Sets (SHA-2 and SHAKE instantiations).
5. **NSA CNSA 2.0 Advisory**:
   - Mandates ML-KEM-1024 and ML-DSA-87 / SLH-DSA for national security systems.

## Property Taxonomy

Properties injected into CycloneDX components follow standard namespace conventions:

| Property Name | Allowed Values / Format | Description |
|---|---|---|
| `appliedquantum.algorithm.family` | `ML-KEM`, `ML-DSA`, `SLH-DSA`, `X25519Kyber768` | Cryptographic algorithm family |
| `appliedquantum.algorithm.classification` | `SAFE`, `TRANSITIONAL`, `VULNERABLE`, `UNKNOWN` | Post-quantum safety assessment |
| `appliedquantum.algorithm.key_size` | Integer string (e.g., `768`, `1024`, `65`) | Algorithm parameter size |
| `appliedquantum.algorithm.std_reference` | `FIPS 203`, `FIPS 204`, `FIPS 205` | Formal standard citation |
| `appliedquantum.algorithm.vendor_id` | `IAOE`, `OSSL`, `PYCA` | Vendor or library implementation tag |
