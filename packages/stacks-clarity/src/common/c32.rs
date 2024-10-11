// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use sha2::{Digest, Sha256};

use super::Error;

const C32_CHARACTERS: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// C32 chars as an array, indexed by their ASCII code for O(1) lookups.
/// Supports lookups by uppercase and lowercase.
///
/// The table also encodes the special characters `O, L, I`:
///   * `O` and `o` as `0`
///   * `L` and `l` as `1`
///   * `I` and `i` as `1`
///
/// Table can be generated with:
/// ```
/// let mut table: [Option<u8>; 128] = [None; 128];
/// let alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// for (i, x) in alphabet.as_bytes().iter().enumerate() {
///     table[*x as usize] = Some(i as u8);
/// }
/// let alphabet_lower = alphabet.to_lowercase();
/// for (i, x) in alphabet_lower.as_bytes().iter().enumerate() {
///     table[*x as usize] = Some(i as u8);
/// }
/// let specials = [('O', '0'), ('L', '1'), ('I', '1')];
/// for pair in specials {
///     let i = alphabet.find(|a| a == pair.1).unwrap() as isize;
///     table[pair.0 as usize] = Some(i as u8);
///     table[pair.0.to_ascii_lowercase() as usize] = Some(i as u8);
/// }
/// ```
const C32_CHARACTERS_MAP: [Option<u8>; 128] = [
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(0),
    Some(1),
    Some(2),
    Some(3),
    Some(4),
    Some(5),
    Some(6),
    Some(7),
    Some(8),
    Some(9),
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    Some(10),
    Some(11),
    Some(12),
    Some(13),
    Some(14),
    Some(15),
    Some(16),
    Some(17),
    Some(1),
    Some(18),
    Some(19),
    Some(1),
    Some(20),
    Some(21),
    Some(0),
    Some(22),
    Some(23),
    Some(24),
    Some(25),
    Some(26),
    None,
    Some(27),
    Some(28),
    Some(29),
    Some(30),
    Some(31),
    None,
    None,
    None,
    None,
    None,
    None,
    Some(10),
    Some(11),
    Some(12),
    Some(13),
    Some(14),
    Some(15),
    Some(16),
    Some(17),
    Some(1),
    Some(18),
    Some(19),
    Some(1),
    Some(20),
    Some(21),
    Some(0),
    Some(22),
    Some(23),
    Some(24),
    Some(25),
    Some(26),
    None,
    Some(27),
    Some(28),
    Some(29),
    Some(30),
    Some(31),
    None,
    None,
    None,
    None,
    None,
];

fn c32_encode(input_bytes: &[u8]) -> String {
    // ASCII characters are 8-bits and c32-encoding encodes 5-bits per
    // character, so the c32-encoded size should be ceil((ascii size) * 8 / 5)
    let size = input_bytes.len().saturating_mul(8).div_ceil(5);
    let mut result = Vec::with_capacity(size);
    let mut carry = 0;
    let mut carry_bits = 0;

    for current_value in input_bytes.iter().rev() {
        let low_bits_to_take = 5 - carry_bits;
        let low_bits = current_value & ((1 << low_bits_to_take) - 1);
        let c32_value = (low_bits << carry_bits) + carry;
        result.push(C32_CHARACTERS[c32_value as usize]);
        carry_bits = (8 + carry_bits) - 5;
        carry = current_value >> (8 - carry_bits);

        if carry_bits >= 5 {
            let c32_value = carry & ((1 << 5) - 1);
            result.push(C32_CHARACTERS[c32_value as usize]);
            carry_bits -= 5;
            carry >>= 5;
        }
    }

    if carry_bits > 0 {
        result.push(C32_CHARACTERS[carry as usize]);
    }

    // remove leading zeros from c32 encoding
    while let Some(v) = result.pop() {
        if v != C32_CHARACTERS[0] {
            result.push(v);
            break;
        }
    }

    // add leading zeros from input.
    for current_value in input_bytes.iter() {
        if *current_value == 0 {
            result.push(C32_CHARACTERS[0]);
        } else {
            break;
        }
    }

    let result: Vec<u8> = result.into_iter().rev().collect();
    String::from_utf8(result).unwrap()
}

fn c32_decode(input_str: &str) -> Result<Vec<u8>, Error> {
    // must be ASCII
    if !input_str.is_ascii() {
        return Err(Error::InvalidCrockford32);
    }
    c32_decode_ascii(input_str)
}

fn c32_decode_ascii(input_str: &str) -> Result<Vec<u8>, Error> {
    let mut iter_c32_digits = Vec::<u8>::with_capacity(input_str.len());

    for x in input_str.as_bytes().iter().rev() {
        if let Some(Some(x)) = C32_CHARACTERS_MAP.get(*x as usize) {
            iter_c32_digits.push(*x)
        }
    }

    if input_str.len() != iter_c32_digits.len() {
        // at least one char was None
        return Err(Error::InvalidCrockford32);
    }

    // c32-encoding encodes 5 bits into each character, while ASCII encodes
    // 8-bits into each character. So, the ASCII-encoded size should be
    // ceil((c32 size) * 5 / 8)
    let size = iter_c32_digits.len().saturating_mul(5).div_ceil(8);
    let mut result = Vec::with_capacity(size);
    let mut carry: u16 = 0;
    let mut carry_bits = 0; // can be up to 5

    for current_5bit in &iter_c32_digits {
        carry += (*current_5bit as u16) << carry_bits;
        carry_bits += 5;

        if carry_bits >= 8 {
            result.push((carry & ((1 << 8) - 1)) as u8);
            carry_bits -= 8;
            carry >>= 8;
        }
    }

    if carry_bits > 0 {
        result.push(carry as u8);
    }

    // remove leading zeros from Vec<u8> encoding
    while let Some(v) = result.pop() {
        if v != 0 {
            result.push(v);
            break;
        }
    }

    // add leading zeros from input.
    for current_value in iter_c32_digits.iter().rev() {
        if *current_value == 0 {
            result.push(0);
        } else {
            break;
        }
    }

    result.reverse();
    Ok(result)
}

fn double_sha256_checksum(data: &[u8]) -> Vec<u8> {
    let tmp = Sha256::digest(Sha256::digest(data));
    tmp[0..4].to_vec()
}

fn c32_check_encode(version: u8, data: &[u8]) -> Result<String, Error> {
    if version >= 32 {
        return Err(Error::InvalidVersion(version));
    }

    let mut check_data = vec![version];
    check_data.extend_from_slice(data);
    let checksum = double_sha256_checksum(&check_data);

    let mut encoding_data = data.to_vec();
    encoding_data.extend_from_slice(&checksum);

    // working with ascii strings is awful.
    let mut c32_string = c32_encode(&encoding_data).into_bytes();
    let version_char = C32_CHARACTERS[version as usize];
    c32_string.insert(0, version_char);

    Ok(String::from_utf8(c32_string).unwrap())
}

fn c32_check_decode(check_data_unsanitized: &str) -> Result<(u8, Vec<u8>), Error> {
    // must be ASCII
    if !check_data_unsanitized.is_ascii() {
        return Err(Error::InvalidCrockford32);
    }

    if check_data_unsanitized.len() < 2 {
        return Err(Error::InvalidCrockford32);
    }

    let (version, data) = check_data_unsanitized.split_at(1);

    let data_sum_bytes = c32_decode_ascii(data)?;
    if data_sum_bytes.len() < 5 {
        return Err(Error::InvalidCrockford32);
    }

    let (data_bytes, expected_sum) = data_sum_bytes.split_at(data_sum_bytes.len() - 4);

    let mut check_data = c32_decode_ascii(version)?;
    check_data.extend_from_slice(data_bytes);

    let computed_sum = double_sha256_checksum(&check_data);
    if computed_sum != expected_sum {
        let computed_sum_u32 = (computed_sum[0] as u32)
            | ((computed_sum[1] as u32) << 8)
            | ((computed_sum[2] as u32) << 16)
            | ((computed_sum[3] as u32) << 24);

        let expected_sum_u32 = (expected_sum[0] as u32)
            | ((expected_sum[1] as u32) << 8)
            | ((expected_sum[2] as u32) << 16)
            | ((expected_sum[3] as u32) << 24);

        return Err(Error::BadChecksum(computed_sum_u32, expected_sum_u32));
    }

    let version = check_data[0];
    let data = data_bytes.to_vec();
    Ok((version, data))
}

pub fn c32_address_decode(c32_address_str: &str) -> Result<(u8, Vec<u8>), Error> {
    if !c32_address_str.is_ascii() || c32_address_str.len() <= 5 {
        Err(Error::InvalidCrockford32)
    } else {
        c32_check_decode(&c32_address_str[1..])
    }
}

pub fn c32_address(version: u8, data: &[u8]) -> Result<String, Error> {
    let c32_string = c32_check_encode(version, data)?;
    Ok(format!("S{}", c32_string))
}
