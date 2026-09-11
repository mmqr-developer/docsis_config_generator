docsis
======

Encodes a DOCSIS binary configuration file from a human-readable text
configuration file, and decodes a binary file back into that text form.

This is a Rust port of the `docsis` utility originally written by Cornel
Ciocirlan and later maintained by Evvolve Media and Adrian Simionov. It reads
the same configuration syntax, produces the same bytes, and keeps the same
command-line interface.

The binary is installed as `gen_docsis`. It sits beside a provisioning
server's own tools, where `docsis` is too general a name to be safe to type.
The library keeps the short name, having no such problem.

DOCSIS is a registered trademark of CableLabs, http://www.cablelabs.com

Building
--------

    ./build.sh            # checks, then a static build with the time compiled in
    ./build.sh --deploy   # ...and send it to the distribution server

`build.sh` targets `x86_64-unknown-linux-musl`, so the binary is statically
linked and carries no libc expectations to the host it lands on. That needs
`rustup target add x86_64-unknown-linux-musl` and a musl C compiler; the script
checks for both. A plain `cargo build --release` still works for a local build.

The only dependencies are the MD5, SHA-1 and HMAC crates, plus jiff to render
the build stamp `--version` prints. The C version needed
flex, bison, GNU m4, glib and net-snmp; none of those are required here. The
SNMP MIB reader and the ASN.1 encoder that net-snmp used to provide are part of
this program.

Usage
-----

    gen_docsis [modifiers] -e <modem_cfg_file> <key_file> <output_file>
    gen_docsis [modifiers] -m <modem_cfg_file1> ... <key_file> <new_extension>
    gen_docsis [modifiers] -p <mta_cfg_file> <output_file>
    gen_docsis [modifiers] -m -p <mta_file1> ... <new_extension>
    gen_docsis [modifiers] -d <binary_file>
    gen_docsis --version

`-e` writes a cable modem file, complete with CM MIC, CMTS MIC, end-of-data
marker and padding. `-p` writes a PacketCable MTA file, which gets none of
those. `-d` decodes either kind. `-m` processes several inputs at once,
replacing each file's extension. An input or output of `-` means standard
input or standard output.

Modifiers:

    -o                Print object identifiers numerically when decoding.
    -M "PATH1:PATH2"  Directories to read SNMP MIBs from.
    -na | -eu         Append the CableLabs or Excentis SHA-1 configuration
                      hash when encoding an MTA file.
    -dialplan         Append a PacketCable 2.0 dial plan read from
                      "dialplan.txt" in the current directory.
    -nohash           Comment out the PacketCable hash when decoding.

MIBs
----

Settings that carry an SNMP object, such as `SnmpMibObject` and
`SnmpWriteControl`, need the MIBs that define those objects. The search path
comes from `-M`, else from `MIBDIRS`, else from the usual net-snmp locations:
`$HOME/.snmp/mibs`, `/usr/share/snmp/mibs`, and that directory's `iana` and
`ietf` subdirectories.

The `mibs` directory here holds the DOCSIS, PacketCable and IETF modules the
tool needs. To run against them without installing anything:

    gen_docsis -M "mibs:mibs/ietf:mibs/iana" -e config.txt key config.cm

When two modules define different objects at the same OID, as the bundled
PacketCable MIBs do, the module read first wins, matching net-snmp. Modules are
read in path order, and alphabetically within each directory, so the result
does not depend on the filesystem.

Configuration file format
-------------------------

`doc/config-format.html` documents the syntax, and `examples/` holds working
configuration files. `docs/spec-coverage.md` records which CableLabs
specifications the settings come from and what is known to be missing.

Testing
-------

    cargo test

`tests/data` holds 142 configuration files paired with the binary and the
decoded text the C program produced for each. Every fixture is encoded,
decoded, and re-encoded, and all three results are compared byte for byte.
Ten fixtures are excluded because their golden files predate later changes to
the symbol table; `tests/regression.rs` names them and says why.

License
-------

GPL-2.0-or-later, as the original. See COPYING.
