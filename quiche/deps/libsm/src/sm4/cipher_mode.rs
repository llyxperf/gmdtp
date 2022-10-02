// Copyright 2018 Cryptape Technology LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::btree_map::Range;

use super::cipher::Sm4Cipher;

pub enum CipherMode {
    Cfb,
    Ofb,
    Ctr,
    Cbc,
  
     
}

pub struct Sm4CipherMode {
    cipher: Sm4Cipher,
    mode: CipherMode,
}

fn block_xor(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut out: [u8; 16] = [0; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn block_add_one(a: &mut [u8]) {
    let mut carry = 1;

    for i in 0..16 {
        let (t, c) = a[15 - i].overflowing_add(carry);
        a[15 - i] = t;
        if !c {
            return;
        }
        carry = c as u8;    //only c==1
    }
}

impl Sm4CipherMode {
    pub fn new(key: &[u8], mode: CipherMode) -> Sm4CipherMode {
        let cipher = Sm4Cipher::new(key);
        Sm4CipherMode { cipher, mode }
    }

    pub fn encrypt(&self, data: &  [u8], iv: &[u8]) -> Vec<u8> {
        if iv.len() != 16 {
            panic!("the iv of sm4 must be 16-byte long");
        }
        match self.mode {
            CipherMode::Cfb => self.cfb_encrypt(data, iv),
            CipherMode::Ofb => self.ofb_encrypt(data, iv),
            CipherMode::Ctr => self.ctr_encrypt(data, iv),
            CipherMode::Cbc => self.cbc_encrypt(data, iv),
                
        }
    }

    pub fn decrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        if iv.len() != 16 {
            panic!("the iv of sm4 must be 16-byte long");
        }
        match self.mode {
            CipherMode::Cfb => self.cfb_decrypt(data, iv),
            CipherMode::Ofb => self.ofb_encrypt(data, iv),
            CipherMode::Ctr => self.ctr_encrypt(data, iv),
            CipherMode::Cbc => self.cbc_decrypt(data, iv),
       
            
        }
    }

    fn cfb_encrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..]);
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            for i in ct.iter() {
                out.push(*i);
            }
            vec_buf.clone_from_slice(&ct);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..]);
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        out
    }
    //lyxalter
    //cipher to be self
    pub fn cfb_encrypt_inplace(&self, data: &mut [u8], iv: &[u8],datalen:usize ){
        
        let mut now = std::time::SystemTime::now();
        
        let block_num = datalen / 16;
        let tail_len = datalen - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);
      
        now = std::time::SystemTime::now();
        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..]);
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            for i in ct.iter() {
                out.push(*i);
            }
            vec_buf.clone_from_slice(&ct);
        }
        
        now = std::time::SystemTime::now();
        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..]);
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }

        for i in 0..out.len(){
            data[i]=out[i];
        }
       
    }

    fn cfb_decrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..]);
            let ct = &data[i * 16..i * 16 + 16];
            let pt = block_xor(&enc, ct);
            for i in pt.iter() {
                out.push(*i);
            }
            vec_buf.clone_from_slice(ct);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..]);
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        out
    }
//lyxalter
 pub fn cfb_decrypt_inplace(&self, data: &mut [u8], iv: &[u8],klen:usize) {
    let block_num =klen / 16;
    let tail_len = klen - block_num * 16;

    let mut out: Vec<u8> = Vec::new();
    let mut vec_buf: Vec<u8> = vec![0; 16];
    vec_buf.clone_from_slice(iv);

    // Normal
    for i in 0..block_num {
        let enc = self.cipher.encrypt(&vec_buf[..]);
        let ct = &data[i * 16..i * 16 + 16];
        let pt = block_xor(&enc, ct);
        for i in pt.iter() {
            out.push(*i);
        }
        vec_buf.clone_from_slice(ct);
    }

    // Last block
    let enc = self.cipher.encrypt(&vec_buf[..]);
    for i in 0..tail_len {
        let b = data[block_num * 16 + i] ^ enc[i];
        out.push(b);
    }
    for i in 0..klen{
        data[i]=out[i];
    }
}
    fn ofb_encrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..]);
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            for i in ct.iter() {
                out.push(*i);
            }
            vec_buf.clone_from_slice(&enc);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..]);
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        out
    }
    pub fn tctr_encrypt_inplace(&self, data: &mut [u8], iv: &[u8],datalen:usize )
    {
     // let mut encTime=0;
     let mut index:usize=0;
     let mut now = std::time::SystemTime::now();
      let block_num = datalen / 16;
      let tail_len = datalen- block_num * 16;
      
     // let mut out: Vec<u8> = Vec::new();
      let mut vec_buf: Vec<u8> = vec![0; 16];
      vec_buf.clone_from_slice(iv);
    //  encTime+=now.elapsed().unwrap().as_millis();

    //  println!("1 cost {:?}\n",now.elapsed().unwrap().as_millis());
      
      // Normal

      let mut enc1=0;
      let mut enc2=0;
      let mut enc3=0;
      let mut enc4=0;
      now = std::time::SystemTime::now();
      for i in 0..block_num {
          let pre1=std::time::SystemTime::now();
          let enc = self.cipher.encrypt(&vec_buf[..]);
          enc1+=pre1.elapsed().unwrap().as_nanos();
          let pre2=std::time::SystemTime::now();
          let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
          enc2+=pre2.elapsed().unwrap().as_nanos();
          let pre3=std::time::SystemTime::now();
          for i in ct.iter() {
              data[index]=*i;
              index+=1;
          }
          enc3+=pre3.elapsed().unwrap().as_nanos();
          let pre4=std::time::SystemTime::now();
          block_add_one(&mut vec_buf[..]);
          enc4+=pre4.elapsed().unwrap().as_nanos();
      }
      
      // Last block
      let enc = self.cipher.encrypt(&vec_buf[..]);
      for i in 0..tail_len {
         // let b = data[block_num * 16 + i] ^ enc[i];
          data[index]=data[block_num * 16 + i] ^ enc[i];
          index+=1;
      }
  
     
  }


    pub fn ctr_encrypt_inplace(&self, data: &mut [u8], iv: &[u8],datalen:usize )
      {
       // let mut encTime=0;
       let mut now = std::time::SystemTime::now();
        let block_num = datalen / 16;
        let tail_len = datalen- block_num * 16;
        
        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);
      //  encTime+=now.elapsed().unwrap().as_millis();

      //  println!("1 cost {:?}\n",now.elapsed().unwrap().as_millis());
        now = std::time::SystemTime::now();
        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..]);
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            for i in ct.iter() {
                out.push(*i);
            }
            block_add_one(&mut vec_buf[..]);
        }
        
        now = std::time::SystemTime::now();
        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..]);
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
       // println!("3 cost {:?}\n",now.elapsed().unwrap().as_millis());
        now = std::time::SystemTime::now();
        for i in 0..out.len(){
            data[i]=out[i];
        }
        println!("4 cost second {:?}\n",now.elapsed().unwrap().as_millis());
       
    }


    fn ctr_encrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..]);
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            for i in ct.iter() {
                out.push(*i);
            }
            block_add_one(&mut vec_buf[..]);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..]);
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        out
    }

    fn cbc_encrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        let block_num = data.len() / 16;
        let remind = data.len() % 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf = [0; 16];
        vec_buf.copy_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let ct = block_xor(&vec_buf, &data[i * 16..i * 16 + 16]);
            let enc = self.cipher.encrypt(&ct);

            out.extend_from_slice(&enc);
            vec_buf = enc;
        }

        if remind != 0 {
            let mut last_block = [16 - remind as u8; 16];
            last_block[..remind].copy_from_slice(&data[block_num * 16..]);

            let ct = block_xor(&vec_buf, &last_block);
            let enc = self.cipher.encrypt(&ct);
            out.extend_from_slice(&enc);
        } else {
            let ff_padding = block_xor(&vec_buf, &[0x10; 16]);
            let enc = self.cipher.encrypt(&ff_padding);
            out.extend_from_slice(&enc);
        }

        out
    }

    fn cbc_decrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        let data_len = data.len();
        let block_num = data_len / 16;
        assert_eq!(data_len % 16, 0);

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf = [0; 16];
        vec_buf.copy_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.decrypt(&data[i * 16..i * 16 + 16]);
            let ct = block_xor(&vec_buf, &enc);

            for j in ct.iter() {
                out.push(*j);
            }
            vec_buf.copy_from_slice(&data[i * 16..i * 16 + 16]);
        }

        let last_u8 = out[data_len - 1];
        assert!(last_u8 <= 0x10 && last_u8 != 0);
        out.resize(data_len - last_u8 as usize, 0);

        out
    }
}

// TODO: AEAD in SM4
// pub struct SM4Gcm;

// Tests below

#[cfg(test)]
mod tests {
    use super::*;

    use rand::RngCore;

    fn rand_block() -> [u8; 16] {
        let mut rng = rand::thread_rng();
        let mut block: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut block[..]);
        block
    }

    fn rand_data(len: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut dat: Vec<u8> = Vec::new();
        dat.resize(len, 0);
        rng.fill_bytes(&mut dat[..]);
        dat
    }

    #[test]
    fn test_driver() {
        test_ciphermode(CipherMode::Ctr);
        test_ciphermode(CipherMode::Cfb);
        test_ciphermode(CipherMode::Ofb);
        test_ciphermode(CipherMode::Cbc);
    }

    fn test_ciphermode(mode: CipherMode) {
        let key = rand_block();
        let iv = rand_block();

        let cmode = Sm4CipherMode::new(&key, mode);

        let pt = rand_data(10);
        let ct = cmode.encrypt(&pt[..], &iv);
        let new_pt = cmode.decrypt(&ct[..], &iv);
        assert_eq!(pt, new_pt);

        let pt = rand_data(100);
        let ct = cmode.encrypt(&pt[..], &iv);
        let new_pt = cmode.decrypt(&ct[..], &iv);
        assert_eq!(pt, new_pt);

        let pt = rand_data(1000);
        let ct = cmode.encrypt(&pt[..], &iv);
        let new_pt = cmode.decrypt(&ct[..], &iv);
        assert_eq!(pt, new_pt);
    }

    #[test]
    fn ctr_enc_test() {
        let key = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let iv = hex::decode("fedcba0987654321fedcba0987654321").unwrap();

        let cipher_mode = Sm4CipherMode::new(&key, CipherMode::Ctr);
        let msg = b"hello world, this file is used for smx test\n";
        let lhs = cipher_mode.encrypt(msg, &iv);
        let lhs: &[u8] = lhs.as_ref();

        let rhs: &[u8] = include_bytes!("example/text.sms4-ctr");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn cfb_enc_test() {
        let key = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let iv = hex::decode("fedcba0987654321fedcba0987654321").unwrap();

        let cipher_mode = Sm4CipherMode::new(&key, CipherMode::Cfb);
        let msg = b"hello world, this file is used for smx test\n";
        let lhs = cipher_mode.encrypt(msg, &iv);
        let lhs: &[u8] = lhs.as_ref();

        let rhs: &[u8] = include_bytes!("example/text.sms4-cfb");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn ofb_enc_test() {
        let key = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let iv = hex::decode("fedcba0987654321fedcba0987654321").unwrap();

        let cipher_mode = Sm4CipherMode::new(&key, CipherMode::Ofb);
        let msg = b"hello world, this file is used for smx test\n";
        let lhs = cipher_mode.encrypt(msg, &iv);
        let lhs: &[u8] = lhs.as_ref();

        let rhs: &[u8] = include_bytes!("example/text.sms4-ofb");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn cbc_enc_test() {
        let key = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let iv = hex::decode("fedcba0987654321fedcba0987654321").unwrap();

        let cipher_mode = Sm4CipherMode::new(&key, CipherMode::Cbc);
        let msg = b"hello world, this file is used for smx test\n";
        let lhs = cipher_mode.encrypt(msg, &iv);
        let lhs: &[u8] = lhs.as_ref();

        let rhs: &[u8] = include_bytes!("example/text.sms4-cbc");
        assert_eq!(lhs, rhs);
    }
}
