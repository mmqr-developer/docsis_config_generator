//! End-to-end regression tests against the fixture corpus in `tests/data`.
//!
//! Each fixture is a text configuration file (`.txt`) paired with the binary a
//! modem is provisioned with (`.cm`) and the text that decoding that binary
//! produces (`.conf`).  Both golden files come from the original C program, so
//! matching them byte for byte is the strongest evidence this port behaves
//! identically.
//!
//! Every fixture is checked three ways, mirroring the original `RunTests.sh`:
//! encode, decode, and re-encode what was decoded.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Fixtures whose golden files predate changes made to the symbol table in the
/// upstream C project, so the goldens no longer describe what the current
/// symbol table encodes.  They are excluded rather than regenerated, which
/// would only make the corpus agree with this implementation by construction.
///
/// - The `SOAMSubtype` fixtures date from 2016; upstream commit d7c9643
///   (2019) changed `FrameLossMeasurementTransmissionPeriodicity` from a
///   16-bit to an 8-bit value.
/// - The remaining three date from 2016; upstream commit 915fd66 (2023)
///   changed `Up`/`DownstreamAggregateServiceFlowReference` from an aggregate
///   into a 16-bit value, and dropped the TLV 70/71 sub-settings entirely.
const STALE_FIXTURES: &[&str] = &[
    "TLV_22_43_5_24_SOAMSubtype",
    "TLV_23_43_5_24_SOAMSubtype",
    "TLV_24_43_5_24_SOAMSubtype",
    "TLV_25_43_5_24_SOAMSubtype",
    "TLV_26_43_5_24_SOAMSubtype",
    "TLV_43_5_24_SOAMSubtype",
    "TLV_60_43_5_24_SOAMSubtype",
    "TLV_24_last_before_43",
    "TLV_25_remaining",
    "TLV_70_TLV_71_AggregateServiceFlow",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn mib_path() -> String {
    let mibs = root().join("mibs");
    format!(
        "{}:{}:{}",
        mibs.display(),
        mibs.join("ietf").display(),
        mibs.join("iana").display()
    )
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_gen_docsis"))
        .args(args)
        .output()
        .expect("the gen_docsis binary should run")
}

/// Encode `input` and return the bytes written, panicking with the program's
/// diagnostics if it failed.
fn encode(input: &Path, key: &Path, out: &Path) -> Vec<u8> {
    let output = run(&[
        "-M",
        &mib_path(),
        "-e",
        &input.display().to_string(),
        &key.display().to_string(),
        &out.display().to_string(),
    ]);
    assert!(
        output.status.success(),
        "encoding {} failed: {}",
        input.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read(out).expect("the encoder should have written an output file")
}

fn decode(input: &Path) -> Vec<u8> {
    let output = run(&["-M", &mib_path(), "-d", &input.display().to_string()]);
    assert!(
        output.status.success(),
        "decoding {} failed: {}",
        input.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[test]
fn fixtures_round_trip_byte_for_byte() {
    let data = root().join("tests/data");
    let key = data.join("key");
    let work = std::env::temp_dir().join("docsis-regression");
    std::fs::create_dir_all(&work).expect("a scratch directory is needed");

    let mut checked = 0usize;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&data)
        .expect("tests/data should exist")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "txt"))
        .collect();
    entries.sort();

    for source in entries {
        let name = source.file_stem().unwrap().to_string_lossy().into_owned();
        if STALE_FIXTURES.contains(&name.as_str()) {
            continue;
        }

        let expected_binary = std::fs::read(data.join(format!("{name}.cm")))
            .unwrap_or_else(|_| panic!("{name}.cm is missing"));
        let expected_text = std::fs::read(data.join(format!("{name}.conf")))
            .unwrap_or_else(|_| panic!("{name}.conf is missing"));

        let first = encode(&source, &key, &work.join(format!("{name}.cm")));
        assert_eq!(
            first, expected_binary,
            "encoding {name} produced different bytes"
        );

        let text = decode(&work.join(format!("{name}.cm")));
        assert_eq!(
            String::from_utf8_lossy(&text),
            String::from_utf8_lossy(&expected_text),
            "decoding {name} produced different text"
        );

        // What we decoded must encode back to the same binary.
        let round_trip_source = work.join(format!("{name}.conf"));
        std::fs::write(&round_trip_source, &text).expect("scratch file should be writable");
        let second = encode(
            &round_trip_source,
            &key,
            &work.join(format!("{name}.re.cm")),
        );
        assert_eq!(
            second, expected_binary,
            "re-encoding the decoded form of {name} produced different bytes"
        );

        checked += 1;
    }

    assert!(
        checked > 100,
        "expected the full fixture corpus, ran {checked}"
    );
}

#[test]
fn an_mta_file_gets_no_mic_and_no_padding() {
    let work = std::env::temp_dir().join("docsis-regression");
    std::fs::create_dir_all(&work).expect("a scratch directory is needed");
    let source = work.join("mta.cfg");
    std::fs::write(
        &source,
        b"Main\n{\n\tMtaConfigDelimiter 1;\n\tSnmpMibObject sysContact.0 String \"test\";\n\tMtaConfigDelimiter 255;\n}\n",
    )
    .expect("scratch file should be writable");

    let out = work.join("mta.bin");
    let output = run(&[
        "-M",
        &mib_path(),
        "-p",
        &source.display().to_string(),
        &out.display().to_string(),
    ]);
    assert!(output.status.success());
    let binary = std::fs::read(&out).unwrap();

    // Starts with the delimiter and ends with it; no CM MIC (TLV 6) is added.
    assert_eq!(&binary[..3], &[0xfe, 0x01, 0x01]);
    assert_eq!(&binary[binary.len() - 3..], &[0xfe, 0x01, 0xff]);

    let text = decode(&out);
    let text = String::from_utf8_lossy(&text);
    assert!(
        text.contains("SnmpMibObject sysContact.0 String \"test\";"),
        "{text}"
    );
}

#[test]
fn the_packetcable_hash_is_appended_over_the_terminator() {
    let work = std::env::temp_dir().join("docsis-regression");
    std::fs::create_dir_all(&work).expect("a scratch directory is needed");
    let source = work.join("hash.cfg");
    std::fs::write(
        &source,
        b"Main\n{\n\tMtaConfigDelimiter 1;\n\tSnmpMibObject sysContact.0 String \"test\";\n\tMtaConfigDelimiter 255;\n}\n",
    )
    .expect("scratch file should be writable");

    let plain = work.join("plain.bin");
    let hashed = work.join("hashed.bin");
    run(&[
        "-M",
        &mib_path(),
        "-p",
        &source.display().to_string(),
        &plain.display().to_string(),
    ]);
    run(&[
        "-M",
        &mib_path(),
        "-na",
        "-p",
        &source.display().to_string(),
        &hashed.display().to_string(),
    ]);

    let plain = std::fs::read(&plain).unwrap();
    let hashed = std::fs::read(&hashed).unwrap();
    // The hash replaces the three terminator bytes and re-adds them after a
    // 22-octet varbind prefix and a 20-octet digest.
    assert_eq!(hashed.len(), plain.len() - 3 + 22 + 20 + 3);
    assert_eq!(&hashed[..plain.len() - 3], &plain[..plain.len() - 3]);
    assert_eq!(&hashed[hashed.len() - 3..], &[0xfe, 0x01, 0xff]);

    // Decoding with -nohash comments the hash out rather than showing it.
    let output = run(&[
        "-M",
        &mib_path(),
        "-nohash",
        "-d",
        &work.join("hashed.bin").display().to_string(),
    ]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("/* SnmpMibObject"), "{text}");
}

/// The settings added or repaired after reviewing the current CableLabs
/// specifications must survive a full encode/decode/re-encode cycle.
/// See docs/spec-coverage.md for where each one comes from.
#[test]
fn settings_added_from_the_current_specifications_round_trip() {
    let work = std::env::temp_dir().join("docsis-regression");
    std::fs::create_dir_all(&work).expect("a scratch directory is needed");

    let source = work.join("current-specs.cfg");
    std::fs::write(
        &source,
        br#"Main
{
	NetworkAccess 1;
	DsChannelList
	{
		SingleDsChannel
		{
			SingleDsTimeout 10;
			SingleDsFrequency 681000000;
			SingleDsChannelType 1;
		}
		DsFreqRange
		{
			DsFreqRangeTimeout 10;
			DsFreqRangeStart 300000000;
			DsFreqRangeEnd 900000000;
			DsFreqRangeStepSize 6000000;
			DsFreqRangeChannelType 0;
		}
	}
	VendorSpecific
	{
		VendorIdentifier 0xffffff;
		L2VPNEncoding
		{
			VPNIdentifier 0x564c414e313030;
			VPNSGAttribute "SG1";
			L2VPNNetworkTimingProfileReference 7;
			L2VPNMultipointForwardingMode 1;
		}
	}
	EnergyManagementParameter
	{
		EnergyManagementDLSMode
		{
			UpstreamActivityDetectionParameters
			{
				UpstreamEntryBitrateThreshold 1000000;
				UpstreamEntryTimeThreshold 10;
				UpstreamExitBitrateThreshold 2000000;
				UpstreamExitTimeThreshold 5;
			}
		}
	}
	DownstreamEHQoSASF
	{
		ServiceFlowReference 3;
		TrafficPriority 1;
	}
	UsServiceFlow { UsServiceFlowRef 1; QosParamSetType 7; }
	DsServiceFlow
	{
		DsServiceFlowRef 2;
		QosParamSetType 7;
		SFtoIATCProfileNameReference "iatc";
	}
}
"#,
    )
    .expect("scratch file should be writable");

    let key = root().join("tests/data/key");
    let binary = encode(&source, &key, &work.join("current-specs.cm"));
    let text = decode(&work.join("current-specs.cm"));
    let text = String::from_utf8(text).expect("decoded text is ASCII");

    // Every new setting decodes back to its own keyword rather than a
    // GenericTLV, which is what an unreachable symbol would produce.
    for expected in [
        "SingleDsChannelType 1;",
        "DsFreqRangeChannelType 0;",
        "VPNSGAttribute \"SG1\";",
        "L2VPNNetworkTimingProfileReference 7;",
        "L2VPNMultipointForwardingMode 1;",
        "UpstreamEntryBitrateThreshold 1000000;",
        "UpstreamEntryTimeThreshold 10;",
        "UpstreamExitBitrateThreshold 2000000;",
        "UpstreamExitTimeThreshold 5;",
        "DownstreamEHQoSASF",
        "SFtoIATCProfileNameReference \"iatc\";",
    ] {
        assert!(
            text.contains(expected),
            "{expected} is missing from:\n{text}"
        );
    }
    assert!(
        !text.contains("GenericTLV"),
        "something decoded as unknown:\n{text}"
    );

    let round_trip = work.join("current-specs.conf");
    std::fs::write(&round_trip, text.as_bytes()).expect("scratch file should be writable");
    let again = encode(&round_trip, &key, &work.join("current-specs.re.cm"));
    assert_eq!(
        again, binary,
        "re-encoding the decoded form changed the bytes"
    );
}

/// The name the binary is installed as, the constant every diagnostic is
/// prefixed with, and the usage text are three copies of one fact. Renaming
/// the `[[bin]]` alone is how a tool ends up still introducing itself by a
/// name that no longer runs anything.
#[test]
fn the_program_introduces_itself_by_the_name_it_is_installed_as() {
    let exe = Path::new(env!("CARGO_BIN_EXE_gen_docsis"));
    let installed = exe
        .file_name()
        .and_then(|s| s.to_str())
        .expect("the built binary has a file name");
    assert_eq!(
        installed,
        docsis::PROG,
        "the binary is installed as {installed} but calls itself {}",
        docsis::PROG
    );

    // Run with no arguments: the usage text goes to stderr.
    let out = run(&[]);
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(
        text.contains(&format!("\t{installed} [modifiers]")),
        "the usage text does not tell the reader to run {installed}:\n{text}"
    );
    assert!(
        !text.contains("\tdocsis [modifiers]"),
        "the usage text still names the old binary:\n{text}"
    );
}
