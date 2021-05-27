#![allow(non_snake_case)]
use num::bigint::{BigInt, Sign};

use crate::packets::auth::RemoteParameters;
use ring::{digest,  hmac};
use itertools::Itertools;

use openssl::symm::{Cipher, Crypter, Mode};


pub struct SRP {
    pub b: BigInt,
    pub g: BigInt,
    pub n: BigInt,
    pub s: BigInt,
    pub user: String,
    pub pass: String,
}

#[derive(Clone)]
pub struct ClientProof{
    pub M1: Vec<u8>,
    pub S: Vec<u8>,
    pub A: Vec<u8>,
    pub crc: Vec<u8>,
}

impl SRP {
    pub fn new(params: &RemoteParameters, user: String, pass: String)->SRP{
        SRP{
            b: BigInt::from_bytes_be(Sign::Plus,&params.b),
            g: BigInt::from_bytes_be(Sign::Plus,&params.g),
            n: BigInt::from_bytes_be(Sign::Plus,&params.n),
            s: BigInt::from_bytes_be(Sign::Plus,&params.s),
            user,
            pass,
        }
    }


    pub fn compute_challenge(&self, a: BigInt, k: BigInt) -> (Vec<u8>,ClientProof){

        let mut data = Vec::new();
        data.append(&mut Vec::from(self.user.as_bytes()));
        data.append(&mut Vec::from(":".to_string().as_bytes()));
        data.append(&mut Vec::from(self.pass.as_bytes()));
        let cred = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &data);
        // println!("Digest:\t{}",hex::encode(cred.as_ref()));

        let mut data = Vec::new();
        data.append(&mut self.s.to_bytes_be().1);
        data.append(&mut Vec::from(cred.as_ref()));
        let mut nd = Vec::from(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &data).as_ref());
        nd.reverse();

        let x = BigInt::from_bytes_be(Sign::Plus, &nd);
        let v = self.g.modpow(&x, &self.n);
        // println!("n:\t{}", self.n.to_str_radix(16));
        // println!("g:\t{}", self.g.to_str_radix(16));
        // println!("v: {}", v.to_str_radix(16));

        let A = self.g.modpow(&a, &self.n);

        let ab = A.to_bytes_be().1;
        let mut abr = ab.clone();
        abr.reverse();

        let b = self.b.to_bytes_be().1;
        let mut br = b.clone();
        br.reverse();

        let mut o = Vec::new();
        o.append(&mut abr.clone());
        o.append(&mut br.clone());
        let mut od = Vec::from(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &o).as_ref());
        od.reverse();

        //-----
        // println!("--------------------------------------------");
        // println!("A:\t{}", A.to_str_radix(16));
        // println!("B:\t{}", self.b.to_str_radix(16));
        // println!("u:\t{}", hex::encode(&od));
        // println!("k:\t{}", k.to_str_radix(16));
        // println!("v:\t{}", v.to_str_radix(16));
        // println!("n:\t{}", &self.n.to_str_radix(16));
        // println!("x:\t{}", x.to_str_radix(16));
        // println!("--------------------------------------------");
        //-----

        //calculate session key

        let u = BigInt::from_bytes_be(Sign::Plus, &od);
        let kgx = k * v;
        let aux = a + (&u * x);
        let sub = &self.b - kgx;      
        let session_key = sub.modpow(&aux, &self.n);



        // println!("S:\t{}", session_key.to_str_radix(16));
        // println!("sub:\t{}", sub.to_str_radix(16));
        // println!("aux:\t{}", aux.to_str_radix(16));
        // println!("--------------------------------------------");


        //Store odd and even bytes in separate byte-arrays
        let s_bytes = session_key.to_bytes_be().1;
        let mut s0 = s_bytes
            .iter()
            .enumerate()
            .filter(|a| a.0 % 2 == 0)
            .map(|a| *a.1)
            .collect::<Vec<_>>();
        let mut s1 = s_bytes
            .iter()
            .enumerate()
            .filter(|a| a.0 % 2 == 1)
            .map(|a| *a.1)
            .collect::<Vec<_>>();

        //reverse and hash them
        &s0.reverse();
        &s1.reverse();

        let mut ds0 = Vec::from(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &s0).as_ref());
        let mut ds1 = Vec::from(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &s1).as_ref());

        ds0.reverse();
        ds1.reverse();

        //interleave the digests

        let mut K = ds0.iter().interleave(ds1.iter()).map(|i|*i).collect::<Vec<_>>();

        // println!("K:\t{}",hex::encode(&K));



        //Hash prime and generator
        let mut nc = self.n.to_bytes_be().1;
        nc.reverse();
        let mut prime = Vec::from(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &nc).as_ref());
        prime.reverse();
        // println!("prime:\t{}",hex::encode(&prime));


        let mut gc = self.g.to_bytes_be().1;
        gc.reverse();
        let mut generator = Vec::from(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &gc).as_ref());
        generator.reverse();
        // println!("generator:\t{}", hex::encode(&generator));
        let mut ngh = generator.iter().zip(prime.iter()).map(|i|(i.0)^(i.1)).collect::<Vec<_>>();

        // hash identifier (username)
        let mut Ih = Vec::from(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &self.user.clone().as_bytes()).as_ref());

        //reverse all the things... actually only some...
        ngh.reverse();
        K.reverse();

        // println!("ngh: {}", &ngh.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(""));
        // println!("ih: {}", &Ih.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(""));
        // println!("s: {}", &self.s.to_bytes_be().1.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(""));
        // println!("abr: {}", &abr.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(""));
        // println!("br: {}", &br.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(""));
        // println!("K: {}", &K.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(""));

        let final_session_key = K.clone();

        let mut m1d = Vec::new();
        m1d.append(&mut ngh);
        m1d.append(&mut Ih);
        m1d.append(&mut self.s.to_bytes_be().1);
        m1d.append(&mut abr);
        m1d.append(&mut br);
        m1d.append(&mut K);
        let M1 = Vec::from(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &m1d).as_ref());
        //M1.reverse();
        // println!("M1: {}", hex::encode(&M1));



        let proof = ClientProof{
            M1: M1.to_vec(),
            S: session_key.to_bytes_be().1,
            A: A.to_bytes_le().1,
            // crc: BigInt::parse_bytes(
            //     b"288900a60dae387aeb4335ca9b48a6c0d3122442",
            //     16,
            // ).unwrap().to_bytes_be().1
            crc: vec![1;20]
        };
        (final_session_key,proof)

    }
}

pub fn generate_auth_response(k: Vec<u8>, account: String, seed: Vec<u8>) -> (Vec<u8>,Vec<u8>){

    let mut seed = seed.clone();
    // seed.reverse();
    let mut k = k.clone();
    // k.reverse();

    // println!("Seed: {}", hex::encode(&seed));
    // println!("k: {}", hex::encode(&k));

    let client_seed = vec![0x10,0x00,0x00,0x10];

    let mut data = Vec::new();
    data.append(&mut Vec::from(account.as_bytes()));
    data.append(&mut vec![0;4]);
    data.append(&mut client_seed.clone());    //clientSeed
    data.append(&mut seed); // flip?
    data.append(&mut k);    // flip?
    let hmac = Vec::from(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &data).as_ref());
    //hmac.reverse();
    // println!("hmac: {}", hex::encode(&hmac));
    (hmac,client_seed)
}

pub struct SessionCrypto{
    server_decrypt: Crypter,
    client_encrypt: Crypter,
}

impl SessionCrypto{
    pub fn new(session_key: Vec<u8>)-> Self{
        let client_enc_key_seed : Vec<u8> = vec![ 0x40, 0xAA, 0xD3, 0x92, 0x26, 0x71, 0x43, 0x47, 0x3A, 0x31, 0x08, 0xA6, 0xE7, 0xDC, 0x98, 0x2A ];
        let client_dec_key_seed : Vec<u8> = vec![ 0x08, 0xF1, 0x95, 0x9F, 0x47, 0xE5, 0xD2, 0xDB, 0xA1, 0x3D, 0x77, 0x8F, 0x3F, 0x3E, 0xE7, 0x00 ];

        let enc_hmac = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &client_enc_key_seed);
        let enc_key_tag = hmac::sign(&enc_hmac, &session_key.clone());
        let enc_key= enc_key_tag.as_ref();

        let dec_hmac = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &client_dec_key_seed);
        let dec_key_tag = hmac::sign(&dec_hmac, &session_key.clone());
        let dec_key = dec_key_tag.as_ref();

        // println!("enc_key: {}", hex::encode(&enc_key));
        // println!("dec_key: {}", hex::encode(&dec_key));

        let mut encrypter = Crypter::new(
            Cipher::rc4(),
            Mode::Encrypt,
            enc_key,
            None).unwrap();
        let mut decrypter = Crypter::new(
            Cipher::rc4(),
            Mode::Decrypt,
            dec_key,
            None).unwrap();

        let iv = [0;1024];
        let mut iv_target = [0;1024];
        let _ = encrypter.update(&iv,&mut iv_target);
        let _ = decrypter.update(&iv,&mut iv_target);

        SessionCrypto{
            server_decrypt: decrypter,
            client_encrypt: encrypter
        }
    }

    pub fn decrypt_header(&mut self, header: &[u8], target: &mut[u8],){
        let _ = self.server_decrypt.update(header,target);
    }
    pub fn encrypt_header(&mut self, header: &[u8], target: &mut[u8],){
        let _ = self.client_encrypt.update(header,target);
    }
}

#[allow(dead_code)]
pub struct WardenCrypto{
    input_crypto: Crypter,
    output_crypto: Crypter,
}

impl WardenCrypto {
    pub fn new(session_key: Vec<u8>) -> Self {
        // println!("Generating warden key");
        // println!("session_key: \t {}", hex::encode(&session_key));
        let s_key_a = Vec::from(&session_key[..session_key.len() / 2]);
        let s_key_b = Vec::from(&session_key[session_key.len() / 2 ..]);
        // println!("s_key_a: \t {}", hex::encode(&s_key_a));
        // println!("s_key_b: \t {}", hex::encode(&s_key_b));

        let o1 = Vec::from(&digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &s_key_a).as_ref()[..20]);
        let o2 = Vec::from(&digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &s_key_b).as_ref()[..20]);
        let o0 = vec![0u8; 20];

        let mut pre_key = WardenCrypto::fill_up(o0.clone(), o1.clone(), o2.clone());


        let warden_key_a = Vec::from(&pre_key[0..16]);
        let mut warden_key_b = vec![0_u8;16];

        let mut taken = 16;
        for i in 0..16 {
            if taken == 20 {
                // println!("pre_key pre: \t{}", hex::encode(&pre_key));
                pre_key = WardenCrypto::fill_up(pre_key.clone(), o1.clone(), o2.clone());
                // println!("pre_key post: \t{}", hex::encode(&pre_key));
                taken = 0;
            }
            warden_key_b[i] = pre_key[taken];
            taken+=1;
        }
        // println!("warden_key_a: {}", hex::encode(&warden_key_a));
        // println!("warden_key_b: {}", hex::encode(&warden_key_b));

        let _seed = vec![ 0x4D, 0x80, 0x8D, 0x2C, 0x77, 0xD9, 0x05, 0xC4, 0x1A, 0x63, 0x80, 0xEC, 0x08, 0x58, 0x6A, 0xFE];

        // Attention, we need to swap the keys here to mirror input/output semantics of the server
        let input_crypto = Crypter::new(
            Cipher::rc4(),
            Mode::Encrypt,
            &warden_key_b,
            None).unwrap();
        let output_crypto = Crypter::new(
            Cipher::rc4(),
            Mode::Decrypt,
            &warden_key_a,
            None).unwrap();

        WardenCrypto{
            input_crypto,
            output_crypto
        }

    }

    fn fill_up(mut o0: Vec<u8>, mut o1: Vec<u8>, mut o2: Vec<u8>) -> Vec<u8> {
        let mut md = Vec::new();
        md.append(&mut o1);
        md.append(&mut o0);
        md.append(&mut o2);
        Vec::from(&digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &md).as_ref()[..20])
    }
    #[allow(dead_code)]
    pub fn decrypt_payload(&mut self, payload: &[u8], target: &mut[u8],){
        let _ = self.input_crypto.update(payload,target);
    }

    #[allow(dead_code)]
    pub fn encrypt_payload(&mut self, payload: &[u8], target: &mut[u8],){
        let _ = self.output_crypto.update(payload,target);
    }
}