/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io::IoResult;

struct RC4RawStream {
  i: u8,
  j: u8,
  state: [u8, ..256u]
}

impl RC4RawStream {
  fn new(key: &[u8]) -> RC4RawStream {
    let mut state: [u8, ..256u] = [0 as u8, ..256u];

    for i in range(0u, 256u) {
      state[i] = i as u8;
    }

    let klen = key.len();
    let mut j: u8 = 0;

    for i in range(0u, 256u) {
      j += state[i] + key[i % klen];
      state.swap(i as uint, j as uint);
    }

    RC4RawStream { i: 0, j: 0, state: state }
  }
}

impl Reader for RC4RawStream {
  fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
    let blen = buf.len();

    for b in range(0, blen) {
      self.i += 1;
      let i = self.i as uint;

      self.j += self.state[i];
      let j = self.j as uint;

      self.state.swap(i, j);

      let nidx = self.state[i] + self.state[j];
      buf[b] = self.state[nidx as uint];
    }

    Ok(blen)
  }
}

struct RC4DataStream<R> {
  raw: RC4RawStream,
  data: R
}

impl<R: Reader> RC4DataStream<R> {
  fn new(key: &[u8], data: R) -> RC4DataStream<R> {
    let raw = RC4RawStream::new(key);
    RC4DataStream { raw: raw, data: data }
  }
}

impl<R: Reader> Reader for RC4DataStream<R> {
  fn read(&mut self, buf: &mut [u8]) -> IoResult<uint> {
    let num = match self.data.read(buf) {
      Err(e) => return Err(e),
      Ok(num) => num
    };

    for b in range(0, num) {
      buf[b] ^= self.raw.read_byte().unwrap();
    }

    Ok(num)
  }
}

#[cfg(test)]
mod test {
  use RC4RawStream;
  use RC4DataStream;
  use std::io::MemReader;
  use std::str::from_utf8;

  #[test]
  fn test_raw() {
    test_rc4_raw("Key", "EB9F7781B734CA72A719");
    test_rc4_raw("Wiki", "6044DB6D41B7");
    test_rc4_raw("Secret", "04D46B053CA87B59");
  }

  #[test]
  fn test_data() {
    test_rc4_data("Key", "Plaintext", "BBF316E8D940AF0AD3");
    test_rc4_data("Wiki", "pedia", "1021BF0420");
    test_rc4_data("Secret", "Attack at dawn", "45A01F645FC35B383552544B9BF5");
  }

  #[test]
  fn test_data_decrypt() {
    test_rc4_data_decrypt("Key", "Plaintext");
    test_rc4_data_decrypt("Wiki", "pedia");
    test_rc4_data_decrypt("Secret", "Attack at dawn");
  }

  fn test_rc4_raw(key: &str, hex: &str) {
    let stream = RC4RawStream::new(key.as_bytes());
    cmp_hex(stream, hex);
  }

  fn test_rc4_data(key: &str, data: &str, hex: &str) {
    let data = MemReader::new(StrBuf::from_str(data).into_bytes());
    let stream = RC4DataStream::new(key.as_bytes(), data);
    cmp_hex(stream, hex);
  }

  fn test_rc4_data_decrypt(key: &str, plain: &str) {
    let data = MemReader::new(StrBuf::from_str(plain).into_bytes());
    let estream = RC4DataStream::new(key.as_bytes(), data);
    let mut dstream = RC4DataStream::new(key.as_bytes(), estream);
    let buf = dstream.read_exact(plain.len()).unwrap();
    assert_eq!(from_utf8(buf.as_slice()).unwrap(), plain);
  }

  fn cmp_hex<R: Reader>(mut reader: R, hex: &str) {
    let buf = reader.read_exact(hex.len() / 2).unwrap();
    let result = buf.iter().fold("".to_owned(), |a, &b| format!("{}{:02X}", a, b));
    assert_eq!(result, hex.to_owned());
  }
}
