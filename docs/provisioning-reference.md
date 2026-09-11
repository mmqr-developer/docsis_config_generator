# DOCSIS and PacketCable provisioning reference

A condensed summary of three things a provisioning system has to get right:
the DHCP options a cable modem and its embedded devices exchange, the binary
format of the cable modem configuration file, and the binary format of
PacketCable and other eSAFE configuration files.

Every statement below is traceable to one of these documents. Where a fact
comes from outside them it is marked.

| Short name | Document | Issue | Date |
| --- | --- | --- | --- |
| MULPI 4.0 | CM-SP-MULPIv4.0, MAC and Upper Layer Protocols Interface | I11 | 19 Feb 2026 |
| eRouter | CM-SP-eRouter, IPv4 and IPv6 eRouter | I22 | 3 May 2024 |
| eDOCSIS | CM-SP-eDOCSIS | I31 | 31 Aug 2022 |
| L2VPN | CM-SP-L2VPN, Layer 2 Virtual Private Networks | I17 | 13 Oct 2025 |
| TEI | CM-SP-TEI, TDM Emulation Interface | I06 | 11 Jun 2010 |
| SEC 4.0 | CM-SP-SECv4.0, Security | I08 | 3 Sep 2025 |
| DHCP-Reg | CL-SP-CANN-DHCP-Reg, CableLabs' DHCP Options Registry | I15 | 9 May 2018 |
| CANN | CL-SP-CANN, CableLabs' Assigned Names and Numbers | I24 | 20 Mar 2025 |

MULPI 4.0, eRouter, eDOCSIS, L2VPN, TEI and SEC 4.0 are in
`docsis_specifications/`. DHCP-Reg and CANN are the CableLabs registries the
first six normatively defer to for option and TLV number assignment.

## 1. DHCP options

### 1.1 Where DHCP sits

The modem ranges and registers on the RF interface, then uses DHCP to learn
its management IP address, the TFTP server holding its configuration file, and
the name of that file. Everything in section 2 depends on those three values.
Each embedded device behind the modem (eRouter, eMTA, eDVA, eSTB) runs its own
DHCP client with its own identity.

### 1.2 DHCPv4, cable modem

Sent in DHCPDISCOVER and DHCPREQUEST (MULPI 4.0 §10.2.5.1.1):

| Field | Value |
| --- | --- |
| `htype` / `hlen` | 1 / 6 |
| `chaddr` | 48-bit MAC of the modem's RF interface |
| Option 61 | Client identifier, formatted per RFC 4361 |
| Option 55 | Parameter request list, containing at least 1, 2, 3, 4, 7, 42, 125 |
| Option 60 | Vendor class identifier, `docsis4.0:` |
| Option 125 | Vendor-identifying vendor-specific information, enterprise 4491 |

Option 60 carries the DOCSIS generation and, before DOCSIS 3.0, an ASCII hex
encoding of the modem capabilities (DHCP-Reg Table 10):

| Client | Option 60 string |
| --- | --- |
| DOCSIS 1.1 / 2.0 | `docsis1.1:<hex caps>`, `docsis2.0:<hex caps>` |
| DOCSIS 3.0 / 3.1 / 4.0 | `docsis3.0:`, `docsis3.1:`, `docsis4.0:` |
| PacketCable 1.0 / 1.5 / 2.0 MTA | `pktc1.0:<hex>`, `pktc1.5:<hex>`, `pktc2.0:<hex>` |
| eRouter | `eRouter1.0` |

Option 125 sub-options, enterprise 4491 (DHCP-Reg §4.4). The modem sends 1, 2
and 5:

| Sub-option | Name | Contents |
| --- | --- | --- |
| 1 | `CL_V4OPTION_ORO` | Count, then the sub-option codes the client wants back |
| 2 | `CL_V4OPTION_TFTP_SERVERS` | IPv4 addresses of TFTP servers |
| 3 | `CL_V4EROUTER_CONTAINER_OPTION` | Options the eRouter passes to CPE |
| 4 | `CL_V4_PACKETCABLE_MIB_ENV_OPTION` | 1 CableLabs, 2 IETF, 3 EuroCableLabs |
| 5 | `CL_V4OPTION_MODEM_CAPABILITIES` | TLV 5 modem capabilities, encoded as in Annex C |
| 6, 7 | ACS server, RADIUS server | IPv4 address or FQDN |

Option 43 is the device-inventory option, sent by the modem and by each
embedded device (DHCP-Reg Table 1). Sub-options 1 to 10 are common; the rest
are per project:

| Sub-option | Contents |
| --- | --- |
| 2 | Device type of the requesting component: `ECM`, `EMTA`, `EPS`, `ESTB`, `EROUTER`, `EDVA`, `DEMARC`, `RPD`, `CARD` |
| 3 | Colon list of everything in the device, `ECM` first, e.g. `ECM:EMTA`, `ECM:EROUTER`, `ECM:EMTA:EPS`. Vendor entries are appended with a `v` prefix |
| 4 to 10 | Serial number, hardware version, software version, boot ROM version, OUI, model number, vendor name; each matching the corresponding `sysDescr` field |
| 15 | Colon list of the eSAFEs that accept configuration through the modem's own configuration file (section 3.2) |
| 31, 32 | PacketCable MTA MAC address (6 octets); provisioning correlation ID (4 octets) |
| 128 to 254 | Reserved for vendors |

Expected in DHCPOFFER and DHCPACK. Missing a critical field fails IPv4
acquisition; missing a non-critical field is logged and ignored:

| Field | Criticality |
| --- | --- |
| `yiaddr` | critical |
| TFTP server, from option 125 sub-option 2 or `siaddr` | critical |
| `file`, the configuration file name | critical |
| Option 1 subnet mask, 2 time offset, 3 router, 4 time server, 7 log server, 42 NTP | non-critical |

### 1.3 DHCPv6, cable modem

The modem builds a link-local address, does router discovery, and uses DHCPv6
when the RA's M bit is set. The Solicit carries (MULPI 4.0 §10.2.5.2.3):

- Client Identifier with a DUID per RFC 8415 §9.1
- IA_NA, for the management address
- Vendor Class (16), enterprise 4491, string `docsis4.0`
- Vendor-specific Information (17), enterprise 4491, containing the modem
  capabilities option, the device ID option holding the RF-interface MAC, and
  `CL_OPTION_ORO` requesting time servers, time offset, TFTP servers,
  configuration file name and syslog servers
- Rapid Commit, and NTP server option 56 with sub-option 1

`OPTION_VENDOR_OPTS` (17) must also appear in the plain ORO (6), so the server
knows to look inside it (DHCP-Reg §5.2). MULPI 4.0 Appendix XI shows a worked
Solicit.

The vendor class string is written `docsis 4.0`, with a space, in MULPI 4.0
§10.2.5.2.3, and `docsis4.0`, without one, in that specification's own
Appendix XI and in DHCP-Reg Table 18. The unspaced form is the one deployed
equipment uses; the spaced form is an erratum.

A CableLabs vendor-specific sub-option code is 16 bits:

```
  bits 15..13   reserved, zero
  bits 12..10   CableLabs project code
  bits  9..0    sub-option type

  code = (project << 10) | subtype
```

Project codes: 0 common, 1 DOCSIS, 2 PacketCable, 3 OpenCable, 4 CableHome.
So the DOCSIS CMTS capabilities option is `(1 << 10) | 1` = 1025, and the
PacketCable client configuration option is `(2 << 10) | 122` = 2170.

Common (project 0) sub-options the modem uses (DHCP-Reg Table 14):

| Code | Name | Contents |
| --- | --- | --- |
| 1 | `CL_OPTION_ORO` | 16-bit codes of the vendor sub-options wanted |
| 2, 3 | Device type, embedded components list | Same strings as option 43 sub-options 2 and 3 |
| 4 to 10 | Serial, hardware, software, boot ROM, OUI, model, vendor name | As option 43 sub-options 4 to 10 |
| 32 | `CL_OPTION_TFTP_SERVERS` | One or more 16-octet IPv6 addresses |
| 33 | `CL_OPTION_CONFIG_FILE_NAME` | Configuration file name |
| 34 | `CL_OPTION_SYSLOG_SERVERS` | One or more IPv6 addresses |
| 35 | `CL_OPTION_MODEM_CAPABILITIES` | TLV 5 modem capabilities |
| 36 | `CL_OPTION_DEVICE_ID` | 6-octet MAC address |
| 37, 38 | RFC 868 time servers, time offset | IPv6 addresses; signed 32-bit seconds |
| 39 | `CL_OPTION_IP_PREF` | 1 IPv4 preferred, 2 IPv6 preferred |
| 42 | `CL_V6_OPTION_CER-ID` | IPv6 address, or 128 zero bits |

The Reply must contain the IA_NA and a vendor-specific option carrying time
servers, time offset, TFTP servers, configuration file name and syslog
servers; a missing one fails address acquisition, except that time servers and
time offset may be replaced by the NTP server option.

### 1.4 Relay agent

| Direction | Requirement |
| --- | --- |
| DHCPv4 | The CMTS relay adds option 82 with the modem's RF-side MAC in the agent remote ID (sub-option 2), and uses `giaddr` to separate modem and CPE subnets |
| DHCPv4 | The relay adds the CMTS capabilities option carrying DOCSIS version `4.0`, inside option 82 sub-option 9, enterprise 4491 |
| DHCPv6 | Relay-Forward carries the Interface-ID option, the CMTS capabilities option (1025) with DOCSIS version `4.0`, and the CM MAC address option |

Option 82 sub-options in use: 1 agent circuit ID, 2 agent remote ID, 4 DOCSIS
device class (RFC 3256), 9 vendor-specific, whose 4491 TLVs are 1 CMTS DOCSIS
version, 2 DPoE system version, 4 DPoE PBB service, 5 CM service class name,
6 MSO-defined text, 7 secure file transfer URI.

### 1.5 eRouter

The eRouter is a separate DHCP client on the modem's CPE side (eRouter §7).
DHCPv4: option 60 is `eRouter1.0`, option 43 identifies the device, and the
parameter request list asks for 1, 3, 6, 42, 55. Critical fields in the ACK
are `yiaddr`, lease time (51), server identifier (54), subnet mask (1), router
(3) and DNS servers; a critical field missing restarts the DHCP cycle rather
than failing provisioning.

DHCPv6: Solicit carries a persistent DUID, IA_NA, IA_PD for the delegated
prefix, Reconfigure Accept, an ORO asking for DNS servers, DNS search list,
`SOL_MAX_RT` (82) and NTP server (56), Vendor Class 4491 `eRouter1.0`, the
device identifier option, and a vendor-specific option holding
`CL_OPTION_ORO` requesting `CL_EROUTER_CONTAINER_OPTION`. With no prefix
already held, the eRouter hints a prefix large enough for one /64 per
customer-facing interface, rounded up to a nibble.

### 1.6 PacketCable

An embedded MTA is provisioned through option 122, CableLabs Client
Configuration (RFC 3495), whose sub-options carry the telephony provider's
primary and secondary DHCPv4 servers (1, 2), SNMP manager address (3), AS-REQ
and AP-REQ backoff and retry (4, 5), Kerberos realm (6), ticket granting
server usage (7), provisioning timer (8) and security ticket invalidation (9).
Over IPv6 the same information travels as `CL_OPTION_CCC` (2170) and
`CL_OPTION_CCCV6`.

## 2. Cable modem configuration file

### 2.1 Container

MULPI 4.0 Annex D.1.1. A stream of octets with no header and no record
markers, fetched by TFTP, in the format DHCP uses for vendor extension data:

```
  +--------+--------+==================+
  |  Type  | Length |      Value       |
  | 1 byte | 1 byte | 1..254 bytes     |
  +--------+--------+==================+
```

Settings follow one another directly. Aggregates nest the same encoding inside
their value. A modem must accept a file of at least 8192 bytes.

Three exceptions to the one-octet length:

| TLV | Length field | Note |
| --- | --- | --- |
| 103, 104 and sub-TLVs 103.3.1, 104.1.1 | 2 bytes | DOCSIS 4.0. Values over 65533 bytes are split across successive elements of the same type and concatenated in order |
| 0 (Pad), 255 (End-of-Data) | none | Type octet only, no length and no value |
| 64 in a PacketCable file | 2 bytes | Not DOCSIS; see section 3.3 |

### 2.2 Mandatory settings

A file lacking any of these is rejected, and the modem must not register from
it (Annex D.1.2): Network Access (3), CM MIC (6), CMTS MIC (7), End-of-Data
(255), and at least one Upstream (24) and one Downstream (25) Service Flow.

A file that mixes DOCSIS 1.0 Class of Service (4) with Service Flow settings
(24, 25) is rejected by the CMTS.

### 2.3 Build order

The order is fixed, because each step digests the bytes the previous step
produced (Annex D.1.3):

1. Emit the TLVs for every parameter the modem needs.
2. Append the Extended CMTS MIC parameters, TLV 43.6, if used.
3. Append the CM MIC, TLV 6.
4. Append the CMTS MIC, TLV 7.
5. Append End-of-Data, TLV 255, then Pad octets (TLV 0) until the file is a
   whole number of 32-bit words.

### 2.4 CM MIC

MD5 over the bytes of the configuration settings exactly as they appear in the
file, disregarding TLV order and content, with two exclusions: the CM MIC TLV
itself and the CMTS MIC TLV, type, length and value in both cases. The 43.6
bytes are included, which is why step 2 precedes step 3. The modem recomputes
the digest and discards the file if it differs.

### 2.5 CMTS MIC and Extended CMTS MIC

The CMTS MIC authenticates the provisioning server to the CMTS using a shared
secret. It is verified against the registration request, not the file.

Pre-3.0 form: HMAC-MD5 (RFC 2104) keyed with the shared secret, over these
settings, in this order, whichever are present (Annex D.2.1):

```
  1, 2, 3, 17, 43, 6, 18, 19, 20, 22, 23, 24, 25, 28, 29, 35, 36, 37, 40
```

Two wrinkles in that list. The TFTP-provisioned modem address is type 20 for
IPv4 and type 59 for IPv6, and whichever is present takes that position.
Generators that also serve DOCSIS 1.1 and 2.0 modems additionally digest
type 4, class of service, and type 26, payload header suppression, both of
which later specifications removed; a generator that keeps them stays
compatible, because neither can appear in a 3.x or 4.0 file.

Extended form, TLV 43.6, which covers TLVs the pre-3.0 list cannot reach:

| Sub-TLV | Name | Value |
| --- | --- | --- |
| 43.6.1 | HMAC type | 1 MD5, 2 MMH16-σ-n, 43 vendor-specific |
| 43.6.2 | Bitmap | BITS, one bit per top-level TLV type, bit 0 always zero |
| 43.6.3 | Explicit digest | Optional. Omit it and TLV 7 carries the extended digest implicitly |

The extended digest is computed over the selected TLVs in the order they were
received, and over sub-types in the order received, so the modem must not
reorder anything. If 43.6.2 selects TLV 43, the 43.6.3 value is zero-filled
for the calculation. TLV 43.6 must not share a TLV 43 instance with any
sub-type other than 8.

### 2.6 What reaches the CMTS

The modem forwards to the CMTS only the settings covered by the pre-3.0 CMTS
MIC list, the settings selected by the E-MIC bitmap, and five allowed
unprotected TLVs: Downstream Channel List (41), CMTS MIC (7), Channel
Assignment (56), Upstream Drop Classifier Group ID (62) and Energy Management
Parameter (74). Anything else in the file is either consumed by the modem
alone or silently discarded by the CMTS. A file whose settings need to reach
the CMTS therefore has to protect them with one of the two MICs.

### 2.7 Top-level settings that belong in a configuration file

From MULPI 4.0 Annex C Table 108, restricted to rows marked for the
configuration file. Types not listed here are registration, dynamic-service or
error encodings and never appear in a file.

| Type | Setting | Type | Setting |
| --- | --- | --- | --- |
| 0 | Pad | 55 | SNMP CPE access control |
| 1 | Downstream frequency | 56 | Channel assignment |
| 2 | Upstream channel ID | 58 | SW upgrade IPv6 TFTP server |
| 3 | Network access control | 59 | TFTP-provisioned modem IPv6 address |
| 4 | DOCSIS 1.0 class of service (deprecated) | 60 | Upstream drop packet classification |
| 6, 7 | CM MIC, CMTS MIC | 61 | Subscriber mgmt CPE IPv6 prefix list |
| 9 | SW upgrade filename | 62 | Upstream drop classifier group ID |
| 10, 11 | SNMP write access control, SNMP MIB object | 63 | Subscriber mgmt control max CPE IPv6 prefixes |
| 14 | CPE Ethernet MAC address | 64 | CMTS static multicast session |
| 17 | Baseline privacy | 65 | L2VPN MAC aging |
| 18 | Max number of CPEs | 66 | Management event control |
| 19 | TFTP server timestamp | 67 | Subscriber mgmt CPE IPv6 list |
| 20 | TFTP-provisioned modem IPv4 address | 68 | Default upstream target buffer |
| 21 | SW upgrade IPv4 TFTP server | 69 | MAC address learning control |
| 22, 23 | Upstream, downstream packet classification | 70, 71 | Upstream, downstream aggregate service flow |
| 24, 25 | Upstream, downstream service flow | 72 | Metro Ethernet service profile |
| 28 | Maximum number of classifiers | 73 | Network timing profile |
| 29 | Privacy enable | 74 | Energy management parameter |
| 32, 33 | Manufacturer, co-signer CVC | 76 | CM upstream AQM disable |
| 34 | SNMPv3 kickstart | 79 | UNI control |
| 35, 36, 37 | Subscriber mgmt control, CPE IPv4 list, filter groups | 81, 82 | Manufacturer, co-signer CVC chain |
| 38 | SNMPv3 notification receiver | 83 | DTP mode configuration |
| 39, 40 | Enable 2.0 mode, enable test modes | 84 | Diplexer band edge |
| 41 | Downstream channel list | 88 | QoS framework |
| 42 | Static multicast MAC address | 91, 92 | Low latency disable, distributed HQoS enable |
| 43 | DOCSIS extension field | 93, 94 | Upstream, downstream enhanced HQoS ASF |
| 45 | Downstream unencrypted traffic filtering | 96, 97 | FDD diplexer band edge, advanced band plan control |
| 53, 54 | SNMPv1v2c coexistence, SNMPv3 access view | 101, 102 | DOCSIS sync configurations, PTP addresses |
| 201-231 | eSAFE configuration (section 3.2) | 103, 104, 106 | See section 2.8 |
| 255 | End-of-Data | | |

### 2.8 DOCSIS 4.0 additions

| Type | Setting | Reference |
| --- | --- | --- |
| 96 | FDD diplexer band edge, 12 octets: 96.1 upstream upper, 96.2 downstream lower, 96.3 downstream upper, in MHz | MULPI 4.0 C.1.2.24 |
| 97 | CM advanced band plan control, 1 octet, 0 disable, 1 enable | C.1.2.25 |
| 103 | CM SSH server configuration, 2-octet length | C.3.1.2 |
| 104 | Security configuration settings, 2-octet length | C.3.1.3 |
| 106 | FDX downstream upper band edge, 2 octets | C.1.2.26 |

TLV 103 sub-settings, applied when the modem enables its physical interfaces:

| Sub-TLV | Setting | Length | Range and default |
| --- | --- | --- | --- |
| 103.1.1 | New connection timeout, seconds | 4 | 0 to 28800, default 0, meaning SSH off |
| 103.1.2 | Inactivity timeout, seconds | 4 | 0 to 86400, default 1800 |
| 103.1.3 | Enabled interfaces bitmap | 1 | Bit 0 network-facing private interfaces, default `0x01` |
| 103.1.4 | Source address restriction | n | CIDR network specifier; absent means unrestricted |
| 103.1.5 | SCCA certificate revocation check disable | 1 | Default 0, do not proceed without revocation data |
| 103.2.1 | SCCA REST API URL | n | HTTPS endpoint, for TLS-based authentication |
| 103.3.1 | `SshCmCds` credential set | n, 2-octet length | Username/password or public key entries; format in SEC 4.0 |
| 103.3.2 | CDS download URL | n | Fetched and validated, replacing existing credentials |

TLV 104 sub-settings, for secure software download:

| Sub-TLV | Setting | Note |
| --- | --- | --- |
| 104.1.1 | OCSP responses for CVC validation | Concatenated DER per SEC 4.0, 2-octet length, fragmentable |
| 104.1.2 | Code file authentication header | DER-encoded ASN.1 |

### 2.9 A numbering conflict inside MULPI 4.0 I11

Annex C Table 108 and Annex G Table 144 disagree about types 92 to 95. Table
108 gives 91 low latency disable, 92 distributed HQoS enable, 93 upstream
enhanced HQoS ASF, 94 downstream enhanced HQoS ASF, 95 DHQoS ASF SID bundle
assignment. Table 144 shifts 92 to 95 down by one. Table 108 agrees with
CL-SP-CANN-I24, so treat Table 144 as the erratum.

## 3. eSAFE and PacketCable configuration files

### 3.1 Two delivery paths

An embedded device gets its configuration one of two ways (eDOCSIS §5.2.8):

- **eSAFE-MIB configuration.** MIB objects set through the modem's own
  configuration file with TLV 11, or by SNMP against the modem.
- **Modem configuration file encapsulation.** The eSAFE's whole configuration
  travels inside the modem's file as an opaque TLV, and the modem hands it
  over after the CM MIC validates.

A standalone device instead fetches its own file by TFTP, using the file name
and server it learned from its own DHCP exchange.

### 3.2 Encapsulation TLVs

| Type | eSAFE | Type | eSAFE |
| --- | --- | --- | --- |
| 201 | ePS | 219 | eTEA |
| 202 | eRouter | 220 | eDVA |
| 216 | eMTA | 221 | eSG |
| 217 | eSTB | 222 | ePTA |
| 218 | reserved | 223 | eTR |
| 203-215, 224-231 | reserved | | |

Because a value is capped at 254 octets, a configuration longer than that is
split across repeated instances of the same type. The modem concatenates the
values in the order they appear before handing them over, so a fragment
boundary may fall anywhere, including inside an inner TLV. The modem silently
ignores encapsulation TLVs for eSAFEs it does not have. Option 43 sub-option
15 (section 1.2) advertises which eSAFEs accept this path.

TLV 202 (eRouter) is the exception that is structured rather than opaque.
Its sub-settings are defined in eRouter Annex B.4:

| Sub-TLV | Setting |
| --- | --- |
| 1 | Initialization mode: 0 disabled, 1 IPv4, 2 IPv6, 3 dual, 4 non-prefix-delegation; default 3 |
| 2 | TR-069 management server, sub-TLVs 2.1 EnableCWMP through 2.7 ACSOverride |
| 3 | Initialization mode override |
| 4, 5 | TR-369 LocalAgent: controller count, then one controller configuration (5.1 to 5.5) per controller |
| 10 | RA transmission interval, 2 octets, 3 to 1800 |
| 11 | SNMP MIB object, one variable binding |
| 12 | IP multicast configuration server, ASCII address or FQDN |
| 13 | Link-ID control, 1 octet, default 0 |
| 42 | Topology mode |
| 43 | Vendor-specific information, with 43.8 vendor OUI |
| 53 | SNMPv1v2c coexistence: 53.1 community name, 53.2 transport address access (53.2.1 address, 53.2.2 mask), 53.3 access view type, 53.4 access view name |
| 54 | SNMPv3 access view: 54.1 name, 54.2 subtree, 54.3 mask, 54.4 type |

CANN §11.1.9 places the access view type and name one level deeper, at
202.53.2.3 and 202.53.2.4. The eRouter specification is the defining document
and puts them at 202.53.3 and 202.53.4, matching the DOCSIS TLV 53 layout.

### 3.3 Standalone MTA and E-UE file format

The container is the modem file format from section 2.1, with a different
frame and a different integrity mechanism. The authority is
PKT-SP-PROV1.5 for PacketCable 1.x and PKT-SP-EUE-PROV for PacketCable 2.0;
neither is in `docsis_specifications/`, so the encoding below is stated from
the files this repository encodes and decodes, which are byte-exact against
the reference implementation.

```
  fe 01 01                     TLV 254, MTA config delimiter, value 1: file opens
  0b LL <varbind>              TLV 11, one BER varbind, value up to 254 octets
  40 LL LL <varbind>           TLV 64, one BER varbind, 2-octet big-endian length
  ...
  0b 28 <hash varbind>         optional configuration hash, section 3.4
  fe 01 ff                     TLV 254, value 255: file closes
```

Points that catch encoder authors out:

- TLV 254 brackets the file. Its value is 1 at the start and 255 at the end.
- No CM MIC, no CMTS MIC, no End-of-Data marker, no padding. Those belong to
  the modem file only.
- **TLV 64 means different things in the two file formats.** In a PacketCable
  file it is the long form of TLV 11, carrying a varbind too large for a
  one-octet length, and its length field is two octets. In a DOCSIS modem file
  TLV 64 is the CMTS Static Multicast Session Encoding with a one-octet
  length. A decoder can only tell them apart by having seen TLV 254 first.
- Values are SNMP variable bindings: a BER `SEQUENCE` of an `OBJECT
  IDENTIFIER` and a value, exactly as in TLV 11 of a modem file.

### 3.4 Configuration hash

Provisioning systems append a SHA-1 over the file so the device can detect
tampering. The digest covers every byte from the opening delimiter through the
closing `fe 01 ff`, and the result is inserted as a varbind immediately before
that closing delimiter, which is then re-emitted.

| Variant | Object identifier | Varbind prefix |
| --- | --- | --- |
| CableLabs (NA) | `1.3.6.1.4.1.4491.2.2.1.1.2.7.0`, `pktcMtaDevProvConfigHash.0` | `0b 28 30 26 06 0e ... 04 14` |
| Excentis (EU) | `1.3.6.1.4.1.7432.1.1.2.9.0` | `0b 26 30 24 06 0c ... 04 14` |

Both carry a 20-octet `OCTET STRING`, the raw digest.

### 3.5 eTEA, a documented analogue

Where the PacketCable format is not public, TEI §6.7.1.9 documents the same
pattern for the embedded TDM emulation adapter and is worth reading as a
model: the same TLV container, a file that must contain an MD5 integrity check
(there at type 53) and an End-of-Data marker at type 255, the digest taken
over the settings as they appear in the TFTP image with only the digest TLV's
own bytes excluded, and the device discarding the file when the digest does
not match.
