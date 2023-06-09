# -*- coding: UTF-8 -*-

TLS_CLIENTCERTIFICATETYPE_IDENTIFIERS_REGISTRY = {
    0x00: 'Unassigned',
    0x01: 'rsa_sign',
    0x02: 'dss_sign',
    0x03: 'rsa_fixed_dh',
    0x04: 'dss_fixed_dh',
    0x05: 'rsa_ephemeral_dh_RESERVED',
    0x06: 'dss_ephemeral_dh_RESERVED',
    0x14: 'fortezza_dms_RESERVED',
    0x40: 'ecdsa_sign',
    0x41: 'rsa_fixed_ecdh',
    0x42: 'ecdsa_fixed_ecdh',
    }
TLS_CIPHER_SUITE_REGISTRY = {
    0x0000: 'NULL_WITH_NULL_NULL',
    0x0001: 'RSA_WITH_NULL_MD5',
    0x0002: 'RSA_WITH_NULL_SHA',
    0x0003: 'RSA_EXPORT_WITH_RC4_40_MD5',
    0x0004: 'RSA_WITH_RC4_128_MD5',
    0x0005: 'RSA_WITH_RC4_128_SHA',
    0x0006: 'RSA_EXPORT_WITH_RC2_CBC_40_MD5',
    0x0007: 'RSA_WITH_IDEA_CBC_SHA',
    0x0008: 'RSA_EXPORT_WITH_DES40_CBC_SHA',
    0x0009: 'RSA_WITH_DES_CBC_SHA',
    0x000a: 'RSA_WITH_3DES_EDE_CBC_SHA',
    0x000b: 'DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
    0x000c: 'DH_DSS_WITH_DES_CBC_SHA',
    0x000d: 'DH_DSS_WITH_3DES_EDE_CBC_SHA',
    0x000e: 'DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
    0x000f: 'DH_RSA_WITH_DES_CBC_SHA',
    0x0010: 'DH_RSA_WITH_3DES_EDE_CBC_SHA',
    0x0011: 'DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
    0x0012: 'DHE_DSS_WITH_DES_CBC_SHA',
    0x0013: 'DHE_DSS_WITH_3DES_EDE_CBC_SHA',
    0x0014: 'DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
    0x0015: 'DHE_RSA_WITH_DES_CBC_SHA',
    0x0016: 'DHE_RSA_WITH_3DES_EDE_CBC_SHA',
    0x0017: 'DH_anon_EXPORT_WITH_RC4_40_MD5',
    0x0018: 'DH_anon_WITH_RC4_128_MD5',
    0x0019: 'DH_anon_EXPORT_WITH_DES40_CBC_SHA',
    0x001a: 'DH_anon_WITH_DES_CBC_SHA',
    0x001b: 'DH_anon_WITH_3DES_EDE_CBC_SHA',
    0x001e: 'KRB5_WITH_DES_CBC_SHA',
    0x001f: 'KRB5_WITH_3DES_EDE_CBC_SHA',
    0x0020: 'KRB5_WITH_RC4_128_SHA',
    0x0021: 'KRB5_WITH_IDEA_CBC_SHA',
    0x0022: 'KRB5_WITH_DES_CBC_MD5',
    0x0023: 'KRB5_WITH_3DES_EDE_CBC_MD5',
    0x0024: 'KRB5_WITH_RC4_128_MD5',
    0x0025: 'KRB5_WITH_IDEA_CBC_MD5',
    0x0026: 'KRB5_EXPORT_WITH_DES_CBC_40_SHA',
    0x0027: 'KRB5_EXPORT_WITH_RC2_CBC_40_SHA',
    0x0028: 'KRB5_EXPORT_WITH_RC4_40_SHA',
    0x0029: 'KRB5_EXPORT_WITH_DES_CBC_40_MD5',
    0x002a: 'KRB5_EXPORT_WITH_RC2_CBC_40_MD5',
    0x002b: 'KRB5_EXPORT_WITH_RC4_40_MD5',
    0x002c: 'PSK_WITH_NULL_SHA',
    0x002d: 'DHE_PSK_WITH_NULL_SHA',
    0x002e: 'RSA_PSK_WITH_NULL_SHA',
    0x002f: 'RSA_WITH_AES_128_CBC_SHA',
    0x0030: 'DH_DSS_WITH_AES_128_CBC_SHA',
    0x0031: 'DH_RSA_WITH_AES_128_CBC_SHA',
    0x0032: 'DHE_DSS_WITH_AES_128_CBC_SHA',
    0x0033: 'DHE_RSA_WITH_AES_128_CBC_SHA',
    0x0034: 'DH_anon_WITH_AES_128_CBC_SHA',
    0x0035: 'RSA_WITH_AES_256_CBC_SHA',
    0x0036: 'DH_DSS_WITH_AES_256_CBC_SHA',
    0x0037: 'DH_RSA_WITH_AES_256_CBC_SHA',
    0x0038: 'DHE_DSS_WITH_AES_256_CBC_SHA',
    0x0039: 'DHE_RSA_WITH_AES_256_CBC_SHA',
    0x003a: 'DH_anon_WITH_AES_256_CBC_SHA',
    0x003b: 'RSA_WITH_NULL_SHA256',
    0x003c: 'RSA_WITH_AES_128_CBC_SHA256',
    0x003d: 'RSA_WITH_AES_256_CBC_SHA256',
    0x003e: 'DH_DSS_WITH_AES_128_CBC_SHA256',
    0x003f: 'DH_RSA_WITH_AES_128_CBC_SHA256',
    0x0040: 'DHE_DSS_WITH_AES_128_CBC_SHA256',
    0x0041: 'RSA_WITH_CAMELLIA_128_CBC_SHA',
    0x0042: 'DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
    0x0043: 'DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
    0x0044: 'DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
    0x0045: 'DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
    0x0046: 'DH_anon_WITH_CAMELLIA_128_CBC_SHA',
    0x0067: 'DHE_RSA_WITH_AES_128_CBC_SHA256',
    0x0068: 'DH_DSS_WITH_AES_256_CBC_SHA256',
    0x0069: 'DH_RSA_WITH_AES_256_CBC_SHA256',
    0x006a: 'DHE_DSS_WITH_AES_256_CBC_SHA256',
    0x006b: 'DHE_RSA_WITH_AES_256_CBC_SHA256',
    0x006c: 'DH_anon_WITH_AES_128_CBC_SHA256',
    0x006d: 'DH_anon_WITH_AES_256_CBC_SHA256',
    0x0084: 'RSA_WITH_CAMELLIA_256_CBC_SHA',
    0x0085: 'DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
    0x0086: 'DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
    0x0087: 'DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
    0x0088: 'DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
    0x0089: 'DH_anon_WITH_CAMELLIA_256_CBC_SHA',
    0x008a: 'PSK_WITH_RC4_128_SHA',
    0x008b: 'PSK_WITH_3DES_EDE_CBC_SHA',
    0x008c: 'PSK_WITH_AES_128_CBC_SHA',
    0x008d: 'PSK_WITH_AES_256_CBC_SHA',
    0x008e: 'DHE_PSK_WITH_RC4_128_SHA',
    0x008f: 'DHE_PSK_WITH_3DES_EDE_CBC_SHA',
    0x0090: 'DHE_PSK_WITH_AES_128_CBC_SHA',
    0x0091: 'DHE_PSK_WITH_AES_256_CBC_SHA',
    0x0092: 'RSA_PSK_WITH_RC4_128_SHA',
    0x0093: 'RSA_PSK_WITH_3DES_EDE_CBC_SHA',
    0x0094: 'RSA_PSK_WITH_AES_128_CBC_SHA',
    0x0095: 'RSA_PSK_WITH_AES_256_CBC_SHA',
    0x0096: 'RSA_WITH_SEED_CBC_SHA',
    0x0097: 'DH_DSS_WITH_SEED_CBC_SHA',
    0x0098: 'DH_RSA_WITH_SEED_CBC_SHA',
    0x0099: 'DHE_DSS_WITH_SEED_CBC_SHA',
    0x009a: 'DHE_RSA_WITH_SEED_CBC_SHA',
    0x009b: 'DH_anon_WITH_SEED_CBC_SHA',
    0x009c: 'RSA_WITH_AES_128_GCM_SHA256',
    0x009d: 'RSA_WITH_AES_256_GCM_SHA384',
    0x009e: 'DHE_RSA_WITH_AES_128_GCM_SHA256',
    0x009f: 'DHE_RSA_WITH_AES_256_GCM_SHA384',
    0x00a0: 'DH_RSA_WITH_AES_128_GCM_SHA256',
    0x00a1: 'DH_RSA_WITH_AES_256_GCM_SHA384',
    0x00a2: 'DHE_DSS_WITH_AES_128_GCM_SHA256',
    0x00a3: 'DHE_DSS_WITH_AES_256_GCM_SHA384',
    0x00a4: 'DH_DSS_WITH_AES_128_GCM_SHA256',
    0x00a5: 'DH_DSS_WITH_AES_256_GCM_SHA384',
    0x00a6: 'DH_anon_WITH_AES_128_GCM_SHA256',
    0x00a7: 'DH_anon_WITH_AES_256_GCM_SHA384',
    0x00a8: 'PSK_WITH_AES_128_GCM_SHA256',
    0x00a9: 'PSK_WITH_AES_256_GCM_SHA384',
    0x00aa: 'DHE_PSK_WITH_AES_128_GCM_SHA256',
    0x00ab: 'DHE_PSK_WITH_AES_256_GCM_SHA384',
    0x00ac: 'RSA_PSK_WITH_AES_128_GCM_SHA256',
    0x00ad: 'RSA_PSK_WITH_AES_256_GCM_SHA384',
    0x00ae: 'PSK_WITH_AES_128_CBC_SHA256',
    0x00af: 'PSK_WITH_AES_256_CBC_SHA384',
    0x00b0: 'PSK_WITH_NULL_SHA256',
    0x00b1: 'PSK_WITH_NULL_SHA384',
    0x00b2: 'DHE_PSK_WITH_AES_128_CBC_SHA256',
    0x00b3: 'DHE_PSK_WITH_AES_256_CBC_SHA384',
    0x00b4: 'DHE_PSK_WITH_NULL_SHA256',
    0x00b5: 'DHE_PSK_WITH_NULL_SHA384',
    0x00b6: 'RSA_PSK_WITH_AES_128_CBC_SHA256',
    0x00b7: 'RSA_PSK_WITH_AES_256_CBC_SHA384',
    0x00b8: 'RSA_PSK_WITH_NULL_SHA256',
    0x00b9: 'RSA_PSK_WITH_NULL_SHA384',
    0x00ba: 'RSA_WITH_CAMELLIA_128_CBC_SHA256',
    0x00bb: 'DH_DSS_WITH_CAMELLIA_128_CBC_SHA256',
    0x00bc: 'DH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
    0x00bd: 'DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256',
    0x00be: 'DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
    0x00bf: 'DH_anon_WITH_CAMELLIA_128_CBC_SHA256',
    0x00c0: 'RSA_WITH_CAMELLIA_256_CBC_SHA256',
    0x00c1: 'DH_DSS_WITH_CAMELLIA_256_CBC_SHA256',
    0x00c2: 'DH_RSA_WITH_CAMELLIA_256_CBC_SHA256',
    0x00c3: 'DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256',
    0x00c4: 'DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256',
    0x00c5: 'DH_anon_WITH_CAMELLIA_256_CBC_SHA256',
    0x00ff: 'EMPTY_RENEGOTIATION_INFO_SCSV',
    0x5600: 'FALLBACK_SCSV',
    0xc001: 'ECDH_ECDSA_WITH_NULL_SHA',
    0xc002: 'ECDH_ECDSA_WITH_RC4_128_SHA',
    0xc003: 'ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
    0xc004: 'ECDH_ECDSA_WITH_AES_128_CBC_SHA',
    0xc005: 'ECDH_ECDSA_WITH_AES_256_CBC_SHA',
    0xc006: 'ECDHE_ECDSA_WITH_NULL_SHA',
    0xc007: 'ECDHE_ECDSA_WITH_RC4_128_SHA',
    0xc008: 'ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
    0xc009: 'ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
    0xc00a: 'ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
    0xc00b: 'ECDH_RSA_WITH_NULL_SHA',
    0xc00c: 'ECDH_RSA_WITH_RC4_128_SHA',
    0xc00d: 'ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
    0xc00e: 'ECDH_RSA_WITH_AES_128_CBC_SHA',
    0xc00f: 'ECDH_RSA_WITH_AES_256_CBC_SHA',
    0xc010: 'ECDHE_RSA_WITH_NULL_SHA',
    0xc011: 'ECDHE_RSA_WITH_RC4_128_SHA',
    0xc012: 'ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
    0xc013: 'ECDHE_RSA_WITH_AES_128_CBC_SHA',
    0xc014: 'ECDHE_RSA_WITH_AES_256_CBC_SHA',
    0xc015: 'ECDH_anon_WITH_NULL_SHA',
    0xc016: 'ECDH_anon_WITH_RC4_128_SHA',
    0xc017: 'ECDH_anon_WITH_3DES_EDE_CBC_SHA',
    0xc018: 'ECDH_anon_WITH_AES_128_CBC_SHA',
    0xc019: 'ECDH_anon_WITH_AES_256_CBC_SHA',
    0xc01a: 'SRP_SHA_WITH_3DES_EDE_CBC_SHA',
    0xc01b: 'SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA',
    0xc01c: 'SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA',
    0xc01d: 'SRP_SHA_WITH_AES_128_CBC_SHA',
    0xc01e: 'SRP_SHA_RSA_WITH_AES_128_CBC_SHA',
    0xc01f: 'SRP_SHA_DSS_WITH_AES_128_CBC_SHA',
    0xc020: 'SRP_SHA_WITH_AES_256_CBC_SHA',
    0xc021: 'SRP_SHA_RSA_WITH_AES_256_CBC_SHA',
    0xc022: 'SRP_SHA_DSS_WITH_AES_256_CBC_SHA',
    0xc023: 'ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
    0xc024: 'ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    0xc025: 'ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
    0xc026: 'ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
    0xc027: 'ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    0xc028: 'ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    0xc029: 'ECDH_RSA_WITH_AES_128_CBC_SHA256',
    0xc02a: 'ECDH_RSA_WITH_AES_256_CBC_SHA384',
    0xc02b: 'ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    0xc02c: 'ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    0xc02d: 'ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
    0xc02e: 'ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
    0xc02f: 'ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    0xc030: 'ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    0xc031: 'ECDH_RSA_WITH_AES_128_GCM_SHA256',
    0xc032: 'ECDH_RSA_WITH_AES_256_GCM_SHA384',
    0xc033: 'ECDHE_PSK_WITH_RC4_128_SHA',
    0xc034: 'ECDHE_PSK_WITH_3DES_EDE_CBC_SHA',
    0xc035: 'ECDHE_PSK_WITH_AES_128_CBC_SHA',
    0xc036: 'ECDHE_PSK_WITH_AES_256_CBC_SHA',
    0xc037: 'ECDHE_PSK_WITH_AES_128_CBC_SHA256',
    0xc038: 'ECDHE_PSK_WITH_AES_256_CBC_SHA384',
    0xc039: 'ECDHE_PSK_WITH_NULL_SHA',
    0xc03a: 'ECDHE_PSK_WITH_NULL_SHA256',
    0xc03b: 'ECDHE_PSK_WITH_NULL_SHA384',
    0xc03c: 'RSA_WITH_ARIA_128_CBC_SHA256',
    0xc03d: 'RSA_WITH_ARIA_256_CBC_SHA384',
    0xc03e: 'DH_DSS_WITH_ARIA_128_CBC_SHA256',
    0xc03f: 'DH_DSS_WITH_ARIA_256_CBC_SHA384',
    0xc040: 'DH_RSA_WITH_ARIA_128_CBC_SHA256',
    0xc041: 'DH_RSA_WITH_ARIA_256_CBC_SHA384',
    0xc042: 'DHE_DSS_WITH_ARIA_128_CBC_SHA256',
    0xc043: 'DHE_DSS_WITH_ARIA_256_CBC_SHA384',
    0xc044: 'DHE_RSA_WITH_ARIA_128_CBC_SHA256',
    0xc045: 'DHE_RSA_WITH_ARIA_256_CBC_SHA384',
    0xc046: 'DH_anon_WITH_ARIA_128_CBC_SHA256',
    0xc047: 'DH_anon_WITH_ARIA_256_CBC_SHA384',
    0xc048: 'ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256',
    0xc049: 'ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384',
    0xc04a: 'ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256',
    0xc04b: 'ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384',
    0xc04c: 'ECDHE_RSA_WITH_ARIA_128_CBC_SHA256',
    0xc04d: 'ECDHE_RSA_WITH_ARIA_256_CBC_SHA384',
    0xc04e: 'ECDH_RSA_WITH_ARIA_128_CBC_SHA256',
    0xc04f: 'ECDH_RSA_WITH_ARIA_256_CBC_SHA384',
    0xc050: 'RSA_WITH_ARIA_128_GCM_SHA256',
    0xc051: 'RSA_WITH_ARIA_256_GCM_SHA384',
    0xc052: 'DHE_RSA_WITH_ARIA_128_GCM_SHA256',
    0xc053: 'DHE_RSA_WITH_ARIA_256_GCM_SHA384',
    0xc054: 'DH_RSA_WITH_ARIA_128_GCM_SHA256',
    0xc055: 'DH_RSA_WITH_ARIA_256_GCM_SHA384',
    0xc056: 'DHE_DSS_WITH_ARIA_128_GCM_SHA256',
    0xc057: 'DHE_DSS_WITH_ARIA_256_GCM_SHA384',
    0xc058: 'DH_DSS_WITH_ARIA_128_GCM_SHA256',
    0xc059: 'DH_DSS_WITH_ARIA_256_GCM_SHA384',
    0xc05a: 'DH_anon_WITH_ARIA_128_GCM_SHA256',
    0xc05b: 'DH_anon_WITH_ARIA_256_GCM_SHA384',
    0xc05c: 'ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256',
    0xc05d: 'ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384',
    0xc05e: 'ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256',
    0xc05f: 'ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384',
    0xc060: 'ECDHE_RSA_WITH_ARIA_128_GCM_SHA256',
    0xc061: 'ECDHE_RSA_WITH_ARIA_256_GCM_SHA384',
    0xc062: 'ECDH_RSA_WITH_ARIA_128_GCM_SHA256',
    0xc063: 'ECDH_RSA_WITH_ARIA_256_GCM_SHA384',
    0xc064: 'PSK_WITH_ARIA_128_CBC_SHA256',
    0xc065: 'PSK_WITH_ARIA_256_CBC_SHA384',
    0xc066: 'DHE_PSK_WITH_ARIA_128_CBC_SHA256',
    0xc067: 'DHE_PSK_WITH_ARIA_256_CBC_SHA384',
    0xc068: 'RSA_PSK_WITH_ARIA_128_CBC_SHA256',
    0xc069: 'RSA_PSK_WITH_ARIA_256_CBC_SHA384',
    0xc06a: 'PSK_WITH_ARIA_128_GCM_SHA256',
    0xc06b: 'PSK_WITH_ARIA_256_GCM_SHA384',
    0xc06c: 'DHE_PSK_WITH_ARIA_128_GCM_SHA256',
    0xc06d: 'DHE_PSK_WITH_ARIA_256_GCM_SHA384',
    0xc06e: 'RSA_PSK_WITH_ARIA_128_GCM_SHA256',
    0xc06f: 'RSA_PSK_WITH_ARIA_256_GCM_SHA384',
    0xc070: 'ECDHE_PSK_WITH_ARIA_128_CBC_SHA256',
    0xc071: 'ECDHE_PSK_WITH_ARIA_256_CBC_SHA384',
    0xc072: 'ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
    0xc073: 'ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
    0xc074: 'ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
    0xc075: 'ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
    0xc076: 'ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
    0xc077: 'ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384',
    0xc078: 'ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
    0xc079: 'ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384',
    0xc07a: 'RSA_WITH_CAMELLIA_128_GCM_SHA256',
    0xc07b: 'RSA_WITH_CAMELLIA_256_GCM_SHA384',
    0xc07c: 'DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
    0xc07d: 'DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
    0xc07e: 'DH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
    0xc07f: 'DH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
    0xc080: 'DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256',
    0xc081: 'DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384',
    0xc082: 'DH_DSS_WITH_CAMELLIA_128_GCM_SHA256',
    0xc083: 'DH_DSS_WITH_CAMELLIA_256_GCM_SHA384',
    0xc084: 'DH_anon_WITH_CAMELLIA_128_GCM_SHA256',
    0xc085: 'DH_anon_WITH_CAMELLIA_256_GCM_SHA384',
    0xc086: 'ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
    0xc087: 'ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
    0xc088: 'ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
    0xc089: 'ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
    0xc08a: 'ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
    0xc08b: 'ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
    0xc08c: 'ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
    0xc08d: 'ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
    0xc08e: 'PSK_WITH_CAMELLIA_128_GCM_SHA256',
    0xc08f: 'PSK_WITH_CAMELLIA_256_GCM_SHA384',
    0xc090: 'DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256',
    0xc091: 'DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384',
    0xc092: 'RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256',
    0xc093: 'RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384',
    0xc094: 'PSK_WITH_CAMELLIA_128_CBC_SHA256',
    0xc095: 'PSK_WITH_CAMELLIA_256_CBC_SHA384',
    0xc096: 'DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
    0xc097: 'DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
    0xc098: 'RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256',
    0xc099: 'RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384',
    0xc09a: 'ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
    0xc09b: 'ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
    0xc09c: 'RSA_WITH_AES_128_CCM',
    0xc09d: 'RSA_WITH_AES_256_CCM',
    0xc09e: 'DHE_RSA_WITH_AES_128_CCM',
    0xc09f: 'DHE_RSA_WITH_AES_256_CCM',
    0xc0a0: 'RSA_WITH_AES_128_CCM_8',
    0xc0a1: 'RSA_WITH_AES_256_CCM_8',
    0xc0a2: 'DHE_RSA_WITH_AES_128_CCM_8',
    0xc0a3: 'DHE_RSA_WITH_AES_256_CCM_8',
    0xc0a4: 'PSK_WITH_AES_128_CCM',
    0xc0a5: 'PSK_WITH_AES_256_CCM',
    0xc0a6: 'DHE_PSK_WITH_AES_128_CCM',
    0xc0a7: 'DHE_PSK_WITH_AES_256_CCM',
    0xc0a8: 'PSK_WITH_AES_128_CCM_8',
    0xc0a9: 'PSK_WITH_AES_256_CCM_8',
    0xc0aa: 'PSK_DHE_WITH_AES_128_CCM_8',
    0xc0ab: 'PSK_DHE_WITH_AES_256_CCM_8',
    0xc0ac: 'ECDHE_ECDSA_WITH_AES_128_CCM',
    0xc0ad: 'ECDHE_ECDSA_WITH_AES_256_CCM',
    0xc0ae: 'ECDHE_ECDSA_WITH_AES_128_CCM_8',
    0xc0af: 'ECDHE_ECDSA_WITH_AES_256_CCM_8',
    0xc0b0: 'ECCPWD_WITH_AES_128_GCM_SHA256',
    0xc0b1: 'ECCPWD_WITH_AES_256_GCM_SHA384',
    0xc0b2: 'ECCPWD_WITH_AES_128_CCM_SHA256',
    0xc0b3: 'ECCPWD_WITH_AES_256_CCM_SHA384',
    0xcca8: 'ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    0xcca9: 'ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    0xccaa: 'DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    0xccab: 'PSK_WITH_CHACHA20_POLY1305_SHA256',
    0xccac: 'ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
    0xccad: 'DHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
    0xccae: 'RSA_PSK_WITH_CHACHA20_POLY1305_SHA256',
    0xd000: 'Unassigned',
    0xd001: 'ECDHE_PSK_WITH_AES_128_GCM_SHA256',
    0xd002: 'ECDHE_PSK_WITH_AES_256_GCM_SHA384',
    0xd003: 'ECDHE_PSK_WITH_AES_128_CCM_8_SHA256',
    0xd004: 'Unassigned',
    0xd005: 'ECDHE_PSK_WITH_AES_128_CCM_SHA256',
    }
TLS_CONTENTTYPE_REGISTRY = {
    0x14: 'change_cipher_spec',
    0x15: 'alert',
    0x16: 'handshake',
    0x17: 'application_data',
    0x18: 'heartbeat',
    }
TLS_ALERT_REGISTRY = {
    0x00: 'close_notify',
    0x0a: 'unexpected_message',
    0x14: 'bad_record_mac',
    0x15: 'decryption_failed',
    0x16: 'record_overflow',
    0x1e: 'decompression_failure',
    0x28: 'handshake_failure',
    0x29: 'no_certificate_RESERVED',
    0x2a: 'bad_certificate',
    0x2b: 'unsupported_certificate',
    0x2c: 'certificate_revoked',
    0x2d: 'certificate_expired',
    0x2e: 'certificate_unknown',
    0x2f: 'illegal_parameter',
    0x30: 'unknown_ca',
    0x31: 'access_denied',
    0x32: 'decode_error',
    0x33: 'decrypt_error',
    0x3c: 'export_restriction_RESERVED',
    0x46: 'protocol_version',
    0x47: 'insufficient_security',
    0x50: 'internal_error',
    0x56: 'inappropriate_fallback',
    0x5a: 'user_canceled',
    0x64: 'no_renegotiation',
    0x6e: 'unsupported_extension',
    0x6f: 'certificate_unobtainable',
    0x70: 'unrecognized_name',
    0x71: 'bad_certificate_status_response',
    0x72: 'bad_certificate_hash_value',
    0x73: 'unknown_psk_identity',
    }
TLS_HANDSHAKETYPE_REGISTRY = {
    0x00: 'hello_request',
    0x01: 'client_hello',
    0x02: 'server_hello',
    0x03: 'hello_verify_request',
    0x04: 'NewSessionTicket',
    0x0b: 'certificate',
    0x0c: 'server_key_exchange',
    0x0d: 'certificate_request',
    0x0e: 'server_hello_done',
    0x0f: 'certificate_verify',
    0x10: 'client_key_exchange',
    0x14: 'finished',
    0x15: 'certificate_url',
    0x16: 'certificate_status',
    0x17: 'supplemental_data',
    }
TLS_SUPPORTED_GROUPS_REGISTRY = {
    0x00: 'Unassigned',
    0x01: 'sect163k1',
    0x02: 'sect163r1',
    0x03: 'sect163r2',
    0x04: 'sect193r1',
    0x05: 'sect193r2',
    0x06: 'sect233k1',
    0x07: 'sect233r1',
    0x08: 'sect239k1',
    0x09: 'sect283k1',
    0x0a: 'sect283r1',
    0x0b: 'sect409k1',
    0x0c: 'sect409r1',
    0x0d: 'sect571k1',
    0x0e: 'sect571r1',
    0x0f: 'secp160k1',
    0x10: 'secp160r1',
    0x100: 'ffdhe2048',
    0x101: 'ffdhe3072',
    0x102: 'ffdhe4096',
    0x103: 'ffdhe6144',
    0x104: 'ffdhe8192',
    0x11: 'secp160r2',
    0x12: 'secp192k1',
    0x13: 'secp192r1',
    0x14: 'secp224k1',
    0x15: 'secp224r1',
    0x16: 'secp256k1',
    0x17: 'secp256r1',
    0x18: 'secp384r1',
    0x19: 'secp521r1',
    0x1a: 'brainpoolP256r1',
    0x1b: 'brainpoolP384r1',
    0x1c: 'brainpoolP512r1',
    0x1d: 'x25519',
    0x1e: 'x448',
    0xff00: 'Unassigned',
    0xff01: 'arbitrary_explicit_prime_curves',
    0xff02: 'arbitrary_explicit_char2_curves',
    }
TLS_EC_POINT_FORMAT_REGISTRY = {
    0x00: 'uncompressed',
    0x01: 'ansiX962_compressed_prime',
    0x02: 'ansiX962_compressed_char2',
    }
TLS_EC_CURVE_TYPE_REGISTRY = {
    0x00: 'Unassigned',
    0x01: 'explicit_prime',
    0x02: 'explicit_char2',
    0x03: 'named_curve',
    }
TLS_SUPPLEMENTAL_DATA_FORMATS = {
    0x00: 'user_mapping_data',
    0x4002: 'authz_data',
    }
TLS_USERMAPPINGTYPE_VALUES = {
    0x40: 'upn_domain_hint',
    }
TLS_SIGNATUREALGORITHM_REGISTRY = {
    0x00: 'anonymous',
    0x01: 'rsa',
    0x02: 'dsa',
    0x03: 'ecdsa',
    0x07: 'ed25519',
    0x08: 'ed448',
    }
TLS_HASHALGORITHM_REGISTRY = {
    0x00: 'none',
    0x01: 'md5',
    0x02: 'sha1',
    0x03: 'sha224',
    0x04: 'sha256',
    0x05: 'sha384',
    0x06: 'sha512',
    0x07: 'Unassigned',
    0x08: 'Intrinsic',
    }
# Skipping: AttributeError("'NoneType' object has no attribute 'text'",)
# Skipping: AttributeError("'NoneType' object has no attribute 'text'",)
# Skipping: AttributeError("'NoneType' object has no attribute 'text'",)
# Skipping: AttributeError("'NoneType' object has no attribute 'text'",)
# Skipping: AttributeError("'NoneType' object has no attribute 'text'",)
# Skipping: AttributeError("'NoneType' object has no attribute 'text'",)
# Skipping: AttributeError("'NoneType' object has no attribute 'text'",)
# Skipping: AttributeError("'NoneType' object has no attribute 'text'",)
# Skipping: AttributeError("'NoneType' object has no attribute 'text'",)
# Skipping: AttributeError("'NoneType' object has no attribute 'text'",)
# Skipping: AttributeError("'NoneType' object has no attribute 'text'",)
# Skipping: AttributeError("'NoneType' object has no attribute 'text'",)
# Skipping: AttributeError("'NoneType' object has no attribute 'text'",)
# Skipping: AttributeError("'NoneType' object has no attribute 'text'",)
# Skipping: AttributeError("'NoneType' object has no attribute 'text'",)
# Skipping: AttributeError("'NoneType' object has no attribute 'text'",)
TLS_EXPORTER_LABEL_REGISTRY = {
    }
TLS_AUTHORIZATION_DATA_FORMATS = {
    0x00: 'x509_attr_cert',
    0x01: 'saml_assertion',
    0x02: 'x509_attr_cert_url',
    0x03: 'saml_assertion_url',
    0x40: 'keynote_assertion_list',
    0x41: 'keynote_assertion_list_url',
    0x42: 'dtcp_authorization',
    }
HEARTBEAT_MESSAGE_TYPES = {
    0x00: 'Reserved',
    0x01: 'heartbeat_request',
    0x02: 'heartbeat_response',
    0xff: 'Reserved',
    }
HEARTBEAT_MODES = {
    0x00: 'Reserved',
    0x01: 'peer_allowed_to_send',
    0x02: 'peer_not_allowed_to_send',
    0xff: 'Reserved',
    }
# Generator: fetch_iana_tls_registry.py
# date:      2018-02-12
# sources:   https://www.iana.org/assignments/comp-meth-ids/comp-meth-ids.xml
#            WARNING! THIS FILE IS AUTOGENERATED, DO NOT EDIT!

TLS_COMPRESSION_METHOD_IDENTIFIERS = {
    0x00: 'NULL',
    0x01: 'DEFLATE',
    0x40: 'LZS',
    }
# Generator: fetch_iana_tls_registry.py
# date:      2018-02-12
# sources:   https://www.iana.org/assignments/tls-  type-values/tls-extensiontype-values.xml
#            WARNING! THIS FILE IS AUTOGENERATED, DO NOT EDIT!

EXTENSIONTYPE_VALUES = {
    0x00: 'server_name',
    0x01: 'max_fragment_length',
    0x02: 'client_certificate_url',
    0x03: 'trusted_ca_keys',
    0x04: 'truncated_hmac',
    0x05: 'status_request',
    0x06: 'user_mapping',
    0x07: 'client_authz',
    0x08: 'server_authz',
    0x09: 'cert_type',
    0x0a: 'supported_groups',
    0x0b: 'ec_point_formats',
    0x0c: 'srp',
    0x0d: 'signature_algorithms',
    0x0e: 'use_srtp',
    0x0f: 'heartbeat',
    0x10: 'application_layer_protocol_negotiation',
    0x11: 'status_request_v2',
    0x12: 'signed_certificate_timestamp',
    0x13: 'client_certificate_type',
    0x14: 'server_certificate_type',
    0x15: 'padding',
    0x16: 'encrypt_then_mac',
    0x17: 'extended_master_secret',
    0x18: 'token_binding',
    0x19: 'cached_info',
    0x23: 'SessionTicket_TLS',
    0xff01: 'renegotiation_info',
}
TLS_CERTIFICATE_TYPES = {
    0x00: 'X_509',
    0x01: 'OpenPGP',
    0x02: 'Raw_Public_Key',
    }
TLS_CERTIFICATE_STATUS_TYPES = {
    0x00: 'Reserved',
    0x01: 'ocsp',
    0x02: 'ocsp_multi',
    }
APPLICATION_LAYER_PROTOCOL_NEGOTIATION_PROTOCOL_IDS = {
    'c-webrtc': 'Confidential_WebRTC_Media_and_Data',
    'coap': 'CoAP',
    'ftp': 'FTP',
    'h2': 'HTTP_2_over_TLS',
    'h2c': 'HTTP_2_over_TCP',
    'http/1.1': 'HTTP_1_1',
    'imap': 'IMAP',
    'managesieve': 'ManageSieve',
    'pop3': 'POP3',
    'spdy/1': 'SPDY_1',
    'spdy/2': 'SPDY_2',
    'spdy/3': 'SPDY_3',
    'stun.nat-discovery': 'NAT_discovery_using_Session_Traversal_Utilities_for_NAT',
    'stun.turn': 'Traversal_Using_Relays_around_NAT',
    'webrtc': 'WebRTC_Media_and_Data',
    }
TLS_CACHEDINFORMATIONTYPE_VALUES = {
    0x00: 'Reserved',
    0x01: 'cert',
    0x02: 'cert_req',
    }