//! Command-line front end for the `docsis` library.

use docsis::PROG;
use std::io::Write;
use std::path::PathBuf;
use std::process::exit;

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;

use docsis::decode::Decoder;
use docsis::lexer;
use docsis::mib::Mib;
use docsis::parser::{Parser, Tlv};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Only these top-level settings take part in the CMTS Message Integrity Check,
/// and they are hashed in this order regardless of where they appear.
const CMTS_MIC_TLVS: [u8; 21] = [
    1, 2, 3, 4, 17, 43, 6, 18, 19, 20, 22, 23, 24, 25, 28, 29, 26, 35, 36, 37, 40,
];

/// The PacketCable NA and EU configuration-hash varbind prefixes, written just
/// before the SHA-1 digest at the end of an MTA file.
const NA_HASH_PREFIX: &[u8] = &[
    0x0b, 0x28, 0x30, 0x26, 0x06, 0x0e, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xa3, 0x0b, 0x02, 0x02, 0x01,
    0x01, 0x02, 0x07, 0x00, 0x04, 0x14,
];
const EU_HASH_PREFIX: &[u8] = &[
    0x0b, 0x26, 0x30, 0x24, 0x06, 0x0c, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xba, 0x08, 0x01, 0x01, 0x02,
    0x09, 0x00, 0x04, 0x14,
];
const MTA_END: &[u8] = &[0xfe, 0x01, 0xff];

const DIALPLAN_ASN_OID: &[u8] = &[
    0x06, 0x12, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xa3, 0x0b, 0x02, 0x02, 0x08, 0x02, 0x01, 0x01, 0x03,
    0x01, 0x01, 0x02, 0x01,
];

#[derive(Default)]
struct Options {
    nohash: bool,
    numeric_oids: bool,
    custom_mibs: Option<String>,
    /// 1 for the CableLabs (NA) hash, 2 for the Excentis (EU) hash.
    hash: u32,
    dialplan: bool,
}

fn usage() -> ! {
    eprintln!("DOCSIS Configuration File creator, version {}", VERSION);
    eprintln!("Copyright (c) 1999,2000,2001 Cornel Ciocirlan, ctrl@users.sourceforge.net");
    eprintln!("Copyright (c) 2002,2003,2004,2005 Evvolve Media SRL, docsis@evvolve.com");
    eprintln!("Copyright (c) 2014 - 2015 Adrian Simionov, daniel.simionov@gmail.com\n");

    eprintln!("To encode a cable modem configuration file: \n\t{PROG} [modifiers] -e <modem_cfg_file> <key_file> <output_file>");
    eprintln!("To encode multiple cable modem configuration files: \n\t{PROG} [modifiers] -m <modem_cfg_file1> ... <key_file> <new_extension>");
    eprintln!("To encode a MTA configuration file: \n\t{PROG} [modifiers] -p <mta_cfg_file> <output_file>");
    eprintln!("To encode multiple MTA configuration files: \n\t{PROG} [modifiers] -m -p <mta_file1> ... <new_extension>");
    eprintln!("To decode a CM or MTA config file: \n\t{PROG} [modifiers] -d <binary_file>\n");

    eprintln!(
        "Where:\n\
         <cfg_file>\t\t= name of text (human readable) cable modem or MTA \n\
         \t\t\t  configuration file;\n\
         <key_file>\t\t= text file containing the authentication key\n\
         \t\t\t  (shared secret) to be used for the CMTS MIC;\n\
         <output_file> \t\t= name of output file where the binary data will\n\
         \t\t\t  be written to (if it does not exist it is created);\n\
         <binary_file>\t\t= name of binary file to be decoded;\n\
         <new_extension>\t\t= new extension to be used when encoding multiple files.\n"
    );

    eprintln!(
        "The following command-line modifiers are available:\n\
         \t-o\n\t\tDecode OIDs numerically.\n\n\
         \t-M \"PATH1:PATH2\"\n\t\tSpecify the SNMP MIB directory when encoding or decoding\n\t\tconfiguration files.\n\n\
         \t-na | -eu\n\t\tAdds CableLabs PacketCable or Excentis EuroPacketCable SHA1 hash\n\t\twhen encoding an MTA config file.\n\n\
         \t-dialplan\n\t\tAdds a PC20 dialplan from an external file called \"dialplan.txt\" in\n\t\tthe current directory.\n\n\
         \t-nohash\n\t\tRemoves the PacketCable SHA1 hash from the MTA config file when\n\t\tdecoding."
    );
    eprintln!("\nSee examples/*.cfg for sample configuration files.");
    eprintln!("\nPlease report bugs or feature requests on GitHub.");
    eprintln!("\nProject repository is https://github.com/rlaager/docsis\n");
    exit(246); // the C program's exit(-10)
}

fn main() {
    // Before the parser: asking a binary when it was built must not depend on
    // the rest of the command line, on a readable configuration file, or on a
    // reachable database.
    docsis::version::print_and_exit_if_requested();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut opts = Options::default();

    let mut config_file: Option<String> = None;
    let mut key_file: Option<String> = None;
    let mut output_file: Option<String> = None;
    let mut extension: Option<String> = None;
    let mut encode_docsis = false;
    let mut decode_bin = false;
    let mut rest: Vec<String> = Vec::new();

    let mut i = 0usize;
    loop {
        if i >= args.len() {
            usage();
        }
        let arg = args[i].as_str();
        match arg {
            "-nohash" => {
                opts.nohash = true;
                i += 1;
            }
            "-o" => {
                opts.numeric_oids = true;
                i += 1;
            }
            "-M" => {
                if i + 1 >= args.len() {
                    usage();
                }
                opts.custom_mibs = Some(args[i + 1].clone());
                i += 2;
            }
            "-na" | "-eu" => {
                if opts.hash != 0 {
                    usage();
                }
                opts.hash = if arg == "-na" { 1 } else { 2 };
                i += 1;
            }
            "-dialplan" => {
                opts.dialplan = true;
                i += 1;
            }
            "-d" => {
                if args.len() - i < 2 {
                    usage();
                }
                decode_bin = true;
                config_file = Some(args[i + 1].clone());
                break;
            }
            "-e" => {
                if args.len() - i < 4 {
                    usage();
                }
                encode_docsis = true;
                config_file = Some(args[i + 1].clone());
                key_file = Some(args[i + 2].clone());
                output_file = Some(args[i + 3].clone());
                break;
            }
            "-m" => {
                // The trailing two arguments are the key file and the new
                // extension; everything between is an input file.
                if args.len() < 3 {
                    usage();
                }
                extension = Some(args[args.len() - 1].clone());
                key_file = Some(args[args.len() - 2].clone());
                encode_docsis = true;
                i += 1;
            }
            "-p" => {
                encode_docsis = false;
                i += 1;
                if args.len() - i < 2 {
                    usage();
                }
                // "-p -dialplan" is accepted for backwards compatibility.
                if args.get(i).map(String::as_str) == Some("-dialplan") {
                    opts.dialplan = true;
                    i += 1;
                }
                if args.len() - i < 2 {
                    usage();
                }
                if extension.is_none() {
                    config_file = Some(args[i].clone());
                    output_file = Some(args[i + 1].clone());
                }
                rest = args[i..].to_vec();
                break;
            }
            _ => {
                if encode_docsis || decode_bin {
                    rest = args[i..].to_vec();
                    break;
                }
                usage();
            }
        }
    }

    let mut key = Vec::new();
    if encode_docsis {
        let Some(kf) = &key_file else { usage() };
        match std::fs::read(kf) {
            Ok(mut data) => {
                data.truncate(64);
                while matches!(data.last(), Some(b'\n') | Some(b'\r')) {
                    data.pop();
                }
                key = data;
            }
            Err(_) => {
                eprintln!("{PROG}: error: can't open keyfile {}", kf);
                exit(251);
            }
        }
    }

    let mib = load_mibs(&opts);

    if decode_bin {
        decode_file(&mib, &opts, config_file.as_deref().unwrap_or(""));
        return;
    }

    if let Some(ext) = &extension {
        // Encoding several files at once: the last two arguments are not inputs
        // when a key file is also expected.
        let drop = if encode_docsis { 2 } else { 1 };
        if rest.len() <= drop {
            usage();
        }
        for input in &rest[..rest.len() - drop] {
            let Some(out) = replace_extension(input, ext) else {
                eprintln!("Cannot process input file {}, extension too short ?", input);
                continue;
            };
            eprintln!("Processing input file {}: output to  {}", input, out);
            if encode_one_file(&mib, &opts, input, &out, &key, encode_docsis).is_err() {
                exit(2);
            }
        }
    } else {
        let (Some(input), Some(out)) = (config_file.as_deref(), output_file.as_deref()) else {
            usage();
        };
        if encode_one_file(&mib, &opts, input, out, &key, encode_docsis).is_err() {
            exit(2);
        }
    }
}

/// Build the MIB search path and read every module on it.
fn load_mibs(opts: &Options) -> Mib {
    let spec = opts
        .custom_mibs
        .clone()
        .or_else(|| std::env::var("MIBDIRS").ok());

    let dirs: Vec<PathBuf> = match spec {
        Some(s) => s.split(':').map(PathBuf::from).collect(),
        None => default_mib_dirs(),
    };
    Mib::load_dirs(&dirs)
}

fn default_mib_dirs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        out.push(PathBuf::from(home).join(".snmp/mibs"));
    }
    out.push(PathBuf::from("/usr/share/snmp/mibs"));
    out.push(PathBuf::from("/usr/share/snmp/mibs/iana"));
    out.push(PathBuf::from("/usr/share/snmp/mibs/ietf"));
    out
}

fn decode_file(mib: &Mib, opts: &Options, path: &str) {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error opening binary file {}: {}", path, e);
            exit(255);
        }
    };
    let mut dec = Decoder::new(mib, opts.nohash);
    dec.set_numeric_oids(opts.numeric_oids);
    dec.decode_main_aggregate(&data);
    write_stdout(&dec.into_output());
}

fn encode_one_file(
    mib: &Mib,
    opts: &Options,
    input: &str,
    output: &str,
    key: &[u8],
    encode_docsis: bool,
) -> Result<(), ()> {
    if input == output && input != "-" {
        eprintln!("{PROG}: Error: source file is the same as destination file");
        return Err(());
    }

    let source = if input == "-" {
        let mut buf = Vec::new();
        if std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf).is_err() {
            eprintln!("{PROG}: Can't read standard input");
            return Err(());
        }
        buf
    } else {
        match std::fs::read(input) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("{PROG}: Can't open input file {}", input);
                return Err(());
            }
        }
    };

    let tokens = match lexer::Lexer::new(&source).tokenize() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{}", e);
            eprintln!("Error parsing config file {}", input);
            return Err(());
        }
    };
    let tree = Parser::new(tokens, mib).parse();
    if tree.is_empty() {
        eprintln!("Error parsing config file {}", input);
        return Err(());
    }

    // A leading MtaConfigDelimiter means this is a PacketCable MTA file, which
    // gets neither MIC nor padding.
    let mut encode_docsis = encode_docsis;
    if tree[0].code == 254 {
        eprintln!("First TLV is MtaConfigDelimiter, forcing PacketCable MTA file.");
        encode_docsis = false;
    }

    let mut buffer = Vec::new();
    flatten(&tree, &mut buffer);

    if encode_docsis {
        add_cm_mic(&mut buffer);
        add_cmts_mic(mib, opts, &mut buffer, key);
        add_eod_and_pad(&mut buffer);
    }

    if opts.dialplan {
        println!("Adding PC20 dialplan from external file.");
        add_dialplan(&mut buffer);
    }
    if opts.hash != 0 {
        let which = if opts.hash == 1 { "NA" } else { "EU" };
        println!("Adding {} ConfigHash to MTA file.", which);
        add_mta_hash(&mut buffer, opts.hash);
    }

    println!("Final content of config file:");
    let mut dec = Decoder::new(mib, opts.nohash);
    dec.set_numeric_oids(opts.numeric_oids);
    dec.decode_main_aggregate(&buffer);
    write_stdout(&dec.into_output());

    if output == "-" {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        if lock.write_all(&buffer).is_err() {
            eprintln!("{PROG}: error: can't write to standard output");
            return Err(());
        }
        let _ = lock.flush();
    } else if std::fs::write(output, &buffer).is_err() {
        eprintln!("{PROG}: error: can't write to output file {}", output);
        return Err(());
    }
    Ok(())
}

/// Write decoded output verbatim; it may contain bytes that are not UTF-8.
fn write_stdout(data: &[u8]) {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(data);
    let _ = lock.flush();
}

/// Serialise the parse tree into the byte sequence a modem reads.
fn flatten(tlvs: &[Tlv], out: &mut Vec<u8>) {
    for tlv in tlvs {
        match &tlv.children {
            Some(children) => {
                let mut sub = Vec::new();
                flatten(children, &mut sub);
                if sub.len() > 255 {
                    eprintln!(
                        "Warning: aggregate size of settings block larger than 255, skipping"
                    );
                    continue;
                }
                out.push(tlv.code);
                out.push(sub.len() as u8);
                out.extend_from_slice(&sub);
            }
            None if tlv.value.len() <= 255 => {
                out.push(tlv.code);
                out.push(tlv.value.len() as u8);
                out.extend_from_slice(&tlv.value);
            }
            // An oversized SnmpMibObject becomes TLV 64, which has a 16-bit length.
            None if tlv.code == 11 => {
                out.push(64);
                out.extend_from_slice(&(tlv.value.len() as u16).to_be_bytes());
                out.extend_from_slice(&tlv.value);
            }
            None => {
                eprintln!("Warning: Non-SnmpMibObject TLV larger than 255... skipping.");
            }
        }
    }
}

fn add_cm_mic(buf: &mut Vec<u8>) {
    if buf.is_empty() {
        return;
    }
    let digest = Md5::digest(&buf[..]);
    buf.push(6);
    buf.push(16);
    buf.extend_from_slice(&digest);
}

fn add_cmts_mic(mib: &Mib, opts: &Options, buf: &mut Vec<u8>, key: &[u8]) {
    if buf.is_empty() {
        return;
    }

    let mut selected = Vec::new();
    for want in CMTS_MIC_TLVS {
        let mut pos = 0usize;
        while pos + 1 < buf.len() {
            let code = buf[pos];
            let step = if code == 64 {
                if pos + 3 > buf.len() {
                    break;
                }
                u16::from_be_bytes([buf[pos + 1], buf[pos + 2]]) as usize + 3
            } else {
                buf[pos + 1] as usize + 2
            };
            if code == want {
                let end = (pos + buf[pos + 1] as usize + 2).min(buf.len());
                selected.extend_from_slice(&buf[pos..end]);
                pos = end;
            } else {
                pos += step;
            }
        }
    }

    println!("##### Calculating CMTS MIC using TLVs:");
    let mut dec = Decoder::new(mib, opts.nohash);
    dec.set_numeric_oids(opts.numeric_oids);
    dec.decode_main_aggregate(&selected);
    write_stdout(&dec.into_output());
    println!("##### End of CMTS MIC TLVs");

    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&selected);
    let digest = mac.finalize().into_bytes();

    print!(" --- MD5 DIGEST: 0x");
    for b in digest.iter() {
        print!("{:02x}", b);
    }
    println!();

    buf.push(7);
    buf.push(16);
    buf.extend_from_slice(&digest);
}

fn add_eod_and_pad(buf: &mut Vec<u8>) {
    if buf.is_empty() {
        return;
    }
    buf.push(255);
    let pad = (4 - (buf.len() % 4)) % 4;
    buf.resize(buf.len() + pad, 0);
}

/// Append the PacketCable configuration hash, replacing the file terminator.
fn add_mta_hash(buf: &mut Vec<u8>, hash: u32) {
    let digest = Sha1::digest(&buf[..]);
    if buf.len() < 3 {
        return;
    }
    let prefix = if hash == 1 {
        NA_HASH_PREFIX
    } else {
        EU_HASH_PREFIX
    };
    buf.truncate(buf.len() - 3);
    buf.extend_from_slice(prefix);
    buf.extend_from_slice(&digest);
    buf.extend_from_slice(MTA_END);
}

/// Append a PacketCable 2.0 dial plan read from `dialplan.txt`.
fn add_dialplan(buf: &mut Vec<u8>) {
    let body = match std::fs::read("dialplan.txt") {
        Ok(d) => d,
        Err(_) => {
            eprintln!("Cannot open dialplan.txt file, fatal error, closing.");
            exit(255);
        }
    };
    let size = body.len();
    if buf.len() < 3 {
        return;
    }
    buf.truncate(buf.len() - 3);

    buf.push(0x40);
    let outer: u16 = if size > 0x7f {
        (2 + 2 + 20 + 2 + 2 + size) as u16
    } else if size > 0x69 {
        (2 + 2 + 20 + 1 + 1 + size) as u16
    } else {
        (1 + 1 + 20 + 1 + 1 + size) as u16
    };
    buf.extend_from_slice(&outer.to_be_bytes());

    buf.push(0x30);
    let seq_len = 0x16 + size;
    if seq_len < 0x80 {
        buf.push(seq_len as u8);
    } else {
        buf.push(0x82);
        let inner: u16 = if size > 0x7f {
            (20 + 2 + 2 + size) as u16
        } else {
            (20 + 1 + 1 + size) as u16
        };
        buf.extend_from_slice(&inner.to_be_bytes());
    }

    buf.extend_from_slice(DIALPLAN_ASN_OID);
    buf.push(0x04);
    if size > 0x7f {
        buf.push(0x82);
        buf.extend_from_slice(&(size as u16).to_be_bytes());
    } else {
        buf.push(size as u8);
    }
    buf.extend_from_slice(&body);
    buf.extend_from_slice(MTA_END);
}

/// Swap a path's extension, refusing when the new one would not fit.
fn replace_extension(path: &str, extension: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut old_len = 0usize;
    for i in (0..bytes.len()).rev() {
        if bytes[i] == b'/' || bytes[i] == b'\\' {
            break;
        }
        if bytes[i] == b'.' {
            old_len = bytes.len() - i;
            break;
        }
    }
    if old_len < extension.len() {
        return None;
    }
    Some(format!("{}{}", &path[..bytes.len() - old_len], extension))
}
