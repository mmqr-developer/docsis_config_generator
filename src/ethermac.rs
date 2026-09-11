//! Ethernet MAC address conversion, matching the original `ether_aton` and
//! `ether_ntoa` helpers: six colon-separated hex groups of at most two digits.

pub fn ether_aton(macstr: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = macstr.split(':');
    for slot in out.iter_mut() {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 2 {
            return None;
        }
        let v = u32::from_str_radix(part, 16).ok()?;
        if v > 255 {
            return None;
        }
        *slot = v as u8;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

pub fn ether_ntoa(mac: &[u8]) -> String {
    mac.iter()
        .take(6)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_two_digit_groups() {
        assert_eq!(
            ether_aton("00:11:22:33:44:55").unwrap(),
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );
        assert_eq!(ether_aton("B4:EE:B4:05:06:07").unwrap()[0], 0xB4);
    }

    #[test]
    fn rejects_malformed_addresses() {
        assert!(ether_aton("00:11:22:33:44").is_none());
        assert!(ether_aton("00:11:22:33:44:55:66").is_none());
        assert!(ether_aton("00:11:22:33:44:zz").is_none());
        assert!(ether_aton("00:11:22:33:44:555").is_none());
    }

    #[test]
    fn prints_lowercase_colon_separated() {
        assert_eq!(
            ether_ntoa(&[0xb4, 0xee, 0xb4, 5, 6, 7]),
            "b4:ee:b4:05:06:07"
        );
    }
}
