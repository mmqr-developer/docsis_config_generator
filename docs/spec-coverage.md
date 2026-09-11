Specification coverage
======================

The configuration settings this tool understands live in `src/symtable.rs`,
one row per setting, each carrying the specification and section it comes
from. This note records a review of that table against the current CableLabs
specifications, what was changed as a result, and what remains missing.

Specifications consulted
------------------------

| Document | Issue | Date |
| --- | --- | --- |
| CableLabs' Assigned Names and Numbers, CL-SP-CANN | I24 | 20 March 2025 |
| DOCSIS 3.1 MAC and Upper Layer Protocols Interface, CM-SP-MULPIv3.1 | I24 | 19 October 2022 |
| DOCSIS 4.0 MAC and Upper Layer Protocols Interface, CM-SP-MULPIv4.0 | I11 | 19 February 2026 |
| DOCSIS 4.0 Cable Modem Operations Support System Interface, CM-SP-CM-OSSIv4.0 | I09 | 12 October 2023 |
| Business Services over DOCSIS Layer 2 Virtual Private Networks, CM-SP-L2VPN | I17 | 13 October 2025 |
| eDOCSIS, CM-SP-eDOCSIS | I31 | 31 August 2022 |
| IPv4 and IPv6 eRouter, CM-SP-eRouter | I22 | 3 May 2024 |

CL-SP-CANN is the registry that assigns every DOCSIS provisioning TLV number,
so its March 2025 issue is the authority for what exists. MULPI gives the
lengths, value ranges and nesting that the registry does not.

The table already cites MULPIv4.0-I07 (May 2023). It has since been checked
against MULPIv4.0-I11 Annex C Table 108 and Annex G Table 144: apart from the
four rows listed under "Still missing" and the deprecated Telephone Settings
Option (TLV 15), every configuration-file TLV in the February 2026 issue is
present.

Defects found and fixed
-----------------------

Three settings existed in the table but could not be reached.

**TLV 74.4.2.1 through 74.4.2.4** — the Upstream Activity Detection thresholds
inside Energy Management DOCSIS Light Sleep Mode named their own first child as
their parent instead of TLV 74.4.2. Writing them worked, because encoding looks
a setting up by name, but decoding a file that contained them produced four
`GenericTLV` lines, so a decoded file no longer re-encoded to the same bytes.

**TLV 25.39** — Service Flow to IATC Profile Name Reference appeared twice,
once for the upstream service flow and once, in the downstream block, still
pointing at the upstream parent. TLV 24.39 worked; TLV 25.39 decoded as an
unknown TLV.

**TLV 94** — Downstream Enhanced HQoS ASF carried the name of TLV 93,
`UpstreamEHQoSASF`. Since a keyword resolves to the first row that bears it,
the downstream aggregate could not be written at all, and decoding one labelled
it as upstream.

Settings added
--------------

| TLV | Setting | Source |
| --- | --- | --- |
| 41.1.3 | `SingleDsChannelType` | MULPIv3.1-I24 C.1.1.22.1.3 |
| 41.2.5 | `DsFreqRangeChannelType` | MULPIv3.1-I24 C.1.1.22.2.5 |
| 43.5.22 | `VPNSGAttribute` | L2VPN-I17 B.3.22 |
| 43.5.25 | `L2VPNNetworkTimingProfileReference` | L2VPN-I17 B.3.25 |
| 43.5.27 | `L2VPNMultipointForwardingMode` | L2VPN-I17 B.3.27 |

The two channel-type settings say whether a downstream channel list entry names
an OFDM or an SC-QAM channel; without them a configuration file cannot pin the
channel type, and the modem scans for both.

The three L2VPN subtypes are used by DPoE rather than by DOCSIS L2VPN, which is
also true of several subtypes the table already carried. An L2VPN Encoding can
appear under seven different parents, so each was added under all seven. With
those in place, L2VPN-I17 Annex B.3 is covered apart from the 43.5.254 error
encoding, which only a modem sends.

Still missing
-------------

Assigned in CL-SP-CANN-I24 but not implemented.

Four of them are now fully specified. CM-SP-MULPIv4.0-I11 (19 February 2026)
arrived in `docsis_specifications/` after this table was first written, and
Annex C.3.1 and C.1.2.26 give their encodings; `docs/provisioning-reference.md`
section 2.8 summarises them. Implementing 103 and 104 means more than adding
rows, because both use a two-octet length field and fragment across repeated
elements, which the encoder does not yet support.

| TLV | Setting | Encoding known? |
| --- | --- | --- |
| 103 | CM SSH Server Configuration Settings | Yes, MULPI 4.0 C.3.1.2 |
| 104 | Security Configuration Settings | Yes, MULPI 4.0 C.3.1.3 |
| 106 | FDX Downstream Upper Band Edge, 2 octets | Yes, MULPI 4.0 C.1.2.26 |
| 24.24 | Unsolicited Grant Time Reference, 4 octets | Yes, MULPI 4.0 C.2.2.10.10 |

The rest still need a document that is not to hand.

| TLV | Setting | Defined by |
| --- | --- | --- |
| 83.1 - 83.4 | L2CP Management: CMIM, L2CP Mode, L2PT D-MAC Address, L2CP Filter | DPoE 2.0 |
| 43.5.15.4 | L2CP Filter | DPoE 2.0 |
| 22.10.4, 23.10.4 | Classifier Slow Protocol Subtype | DPoE |
| 219 | eTEA, and its 70-odd sub-settings | CM-SP-TEI |
| 201, 216, 220, 221, 222, 223 | ePS, eMTA, eDVA, eSG, ePTA and eTR eSAFE containers | eDOCSIS I31 Table 5 |

Four eRouter settings are specified in CM-SP-eRouter-I22 Annex B.4 and could
be added directly: 202.4 and 202.5 with its five sub-settings, the TR-369
LocalAgent controller configuration; 202.12, IP Multicast Configuration Server,
an ASCII address or FQDN; and 202.13, Link-ID Control, one octet.

Where CL-SP-CANN-I24 §11.1.9 places the eRouter access view type and name at
202.53.2.3 and 202.53.2.4, CM-SP-eRouter-I22 B.4.6 places them at 202.53.3 and
202.53.4, alongside the DOCSIS TLV 53 layout. The symbol table follows the
eRouter specification, which is the defining document.

TLV 83 needs care rather than just a table row: DOCSIS 3.1 defines TLV 83 as a
one-octet DTP Mode Configuration, which is what the table has, while DPoE 2.0
defines the same number as an L2CP Management aggregate. The two cannot both be
decoded without knowing which kind of file is being read.

Until they are implemented, all of these can still be written by hand, subject
to the 255-octet limit that `GenericTLV` inherits from the one-octet length:

    GenericTLV TlvCode 106 TlvLength 2 TlvValue 0x04b0;

Deliberately absent
-------------------

The table describes what a configuration file may contain. These are assigned
TLV numbers that only ever appear in messages between a modem and a CMTS, so
they are out of scope:

- Registration-only encodings: modem capabilities beyond those already listed
  (TLV 5.47 - 5.85), Vendor ID (8), Service(s) Not Available (13), Vendor
  Specific Capabilities (44), Transmit Channel Configuration (46), SID Cluster
  Assignment (47), Receive Channel Profile and Configuration (48, 49), DSID
  encodings (50), Security Association (51), Initializing Channel Timeout (52),
  CM Initialization Reason (57), Primary Service Flow Indicator (90).
- Dynamic-service and privacy encodings: HMAC-Digest (27), Authorization Block
  (30), Key Sequence Number (31), FDX Transmission Group (85), FDX Reset (86),
  Echo Cancellation Training (87), Extended SID Cluster Assignment (89).
- Error encodings a modem sends when it rejects a setting: 22.8, 23.8, 26.6,
  60.8, 43.5.254, and the per-service-flow equivalents at 24.5, 25.5, 70.5
  and 71.5.
- CMTS-assigned identifiers: service flow identifiers at 70.2, 71.2, 93.2 and
  94.2, aggregate identifiers at 24.47 and 25.47, and the grant timing
  parameters 24.24 and 24.25.

Reproducing this review
-----------------------

`src/symbol.rs` carries tests that assert the properties the three defects
above violated: every setting reaches a top-level TLV, none is its own parent,
and a keyword always means one TLV code with one encoder. Those tests would
have caught all three.
