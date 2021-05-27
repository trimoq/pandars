#![allow(non_snake_case)]

use crate::packets::{*};
use bytes::{BytesMut, BufMut, Buf};
use std::convert::TryInto;
//use crate::packets::bitutil::BitUtil;

pub struct CAuthResponse{
    pub digest: Vec<u8>,
    pub client_seed: Vec<u8>,
    //security: u8,
    pub client_build: u16,
    //id: u32,
    pub addon_size: u32,
    // locale: u8,
    pub account: String
}

impl Default for CAuthResponse{
    fn default() -> Self {
        Self{
            digest: vec![],
            client_seed: vec![0x10,0x00,0x00,0x10],
            client_build: 0x47ee,
            addon_size: 0,
            account: "".to_string()
        }
    }
}


impl Serializeable for CAuthResponse{
    fn write(&self, buf: &mut BytesMut) {
        let mut payload = BytesMut::with_capacity(0x0120);
        // TODO write length !

        payload.put_u16_le(0x00b2); // opcode
        payload.put_u16_le(0x0000); // unknown zeroes
        payload.put_u32_le(0x0000); // skipped zeroes
        payload.put_u32_le(0x0000); // skipped zeroes

        payload.put_u8(self.digest[18]);
        payload.put_u8(self.digest[14]);
        payload.put_u8(self.digest[3]);
        payload.put_u8(self.digest[4]);
        payload.put_u8(self.digest[0]);

        payload.put_u32_le(0x0001); // 
        payload.put_u8(self.digest[11]);
        payload.put(&(self.client_seed.clone()[..]));
        payload.put_u8(self.digest[19]);
        payload.put_u8(0x01);  // skipped zeroes
        payload.put_u8(0x00);  // skipped zeroes
        payload.put_u8(self.digest[2]);
        payload.put_u8(self.digest[9]);
        payload.put_u8(self.digest[12]);
        payload.put_u64_le(0x00u64);
        payload.put_u32_le(0x00u32);
        payload.put_u8(self.digest[16]);
        payload.put_u8(self.digest[5]);
        payload.put_u8(self.digest[6]);
        payload.put_u8(self.digest[8]);
        payload.put_u16_le(self.client_build);
        payload.put_u8(self.digest[17]);
        payload.put_u8(self.digest[7]);
        payload.put_u8(self.digest[13]);
        payload.put_u8(self.digest[15]);
        payload.put_u8(self.digest[1]);
        payload.put_u8(self.digest[10]);

        let addon_with_len = hex::decode(
            "7201000030050000789c7593616e83300c85d93d76845da2ed56d4a948acd0fe9d4ce282458891096\
            cede5b7a049d32639fce47b76e297e7a72ccbb68eee7710fbbe311de18203fa703e640fc3c7e331fbc7c5748\
            0ecb8bd25387ad0c96c02b157d916a441993a1e133804875742670bf234c0a889c85bf2addec081e90b901ef\
            5a976e0d05b100d75e0226c71d22b1d45ab2a58d05e40081a879326e3a18170e436c96afc0c3a1cc1841390d\
            d0b0c7af3f3be14be927ef43336735b333b0dbe78c3b30f28af3c8b07a74872771b3b75f6bc88e6e886e6453\
            5cb827a46f2999cdd82efd374c73e08bbb44025073f8d68f41b1d020e1b172785640a5749c526862495a3557\
            11e5b018b2a3f32f7b176cf92be6401465827bc6009562125869f1d50eb224d3fdf9a1cb5ea845796363569b\
            d6e84ee644d0316e0a1456d5f6aee51b7b75e6dab7a72fab3464c1e456517265b059678a6eec0a554ffbfcd3\
            8855dc76450a16b47bddf660eddefe2ff557cc5ef1b7aeb96c4").unwrap();

        //payload.put_u32_le(self.addon_size); // 0x 00 00 01 72
        payload.put(&addon_with_len[..]);

        // TODO put addon data
        // try with 00 00


        // works for acc len up until 128
        let mut acc_len = self.account.len();
        payload.put_u8(0);
        acc_len = acc_len<<4;
        payload.put_u8(acc_len as u8);
        payload.put( self.account.as_bytes());

        let len = payload.len();
        buf.put_u16_le(len as u16);
        buf.put(payload);

    }
}

pub struct SAuthResponse{
    pub success: bool
}


impl Readable for SAuthResponse{
    fn read(_opcode:&u16, size: &u16,buf: &mut BytesMut) -> Result<Self, ParseError> {
        let a = buf.get_u8();
        let _first_bit = a & 0x80;
        let success =  a == 0x80;

        buf.advance((*size as usize) - 1 );

        Ok(SAuthResponse{
            success
        })
    }
}
pub struct SEnumCharactersResponse{
    pub guid: u64
}


impl Readable for SEnumCharactersResponse{
    fn read(_opcode:&u16, size: &u16,buf: &mut BytesMut) -> Result<Self, ParseError> {
        let _crap = buf.get_u16_le();
        let _crap = buf.get_u8();
        let bitbuf = buf.get_u16();
        let charcount = bitbuf>>3;
        // println!("charcount {}", charcount);
        let bitbuf_rest = bitbuf & 3;
        let mut bitfield = vec![0; (3 * charcount) as usize];
        buf.copy_to_slice(&mut bitfield);
        // println!("bitfield {:?}", bitfield);

        let mut bGuildGuid = vec![false;8];
        let mut bGuid = vec![false;8];
        // last byte
        bGuildGuid[4] =   bitbuf_rest & 0b100 > 1;
        bGuid[0]=         bitbuf_rest & 0b010 > 1;
        bGuildGuid[3]=    bitbuf_rest & 0b001 > 1;
        // byte 0
        bGuid[3]=         bitfield[0] & 0b1000_0000 > 1;
        bGuid[7]=         bitfield[0] & 0b0100_0000 > 1;
        bGuid[6]=         bitfield[0] & 0b0000_1000 > 1;
        bGuildGuid[6]=    bitfield[0] & 0b0000_0100 > 1;
        // byte1
        bGuid[1]=         bitfield[1] & 0b0000_1000 > 1;
        bGuildGuid[1]=    bitfield[1] & 0b0000_0100 > 1;
        bGuildGuid[0]=    bitfield[1] & 0b0000_0010 > 1;
        bGuid[4]=         bitfield[1] & 0b0000_0001 > 1;
        // byte2
        bGuildGuid[7]=    bitfield[2] & 0b1000_0000 > 1;
        bGuid[2]=         bitfield[2] & 0b0100_0000 > 1;
        bGuid[5]=         bitfield[2] & 0b0010_0000 > 1;
        bGuildGuid[2]=    bitfield[2] & 0b0001_0000 > 1;
        bGuildGuid[5]=    bitfield[2] & 0b0000_1000 > 1;




        let mut namelen = (bitfield[0] & 0b11)<<4; // bit 10 to 12
        namelen += (bitfield[1] & 0b11110000) >> 4;  // bit 13 to 16
        // println!("namelen {}", namelen);

        let remaining_byte_len = (*size as usize) - 5 - (3 * charcount) as usize;
        let mut charbytes = vec![0; remaining_byte_len];
        buf.copy_to_slice(&mut charbytes);
        let mut guid = vec![0u8; 8];


        let mut offset = 4;
        if bGuid[1]{
            guid[1]= charbytes[4]^1;
            offset +=1;
        }

        let _slot = charbytes[offset];
        // println!("slot {}", slot);
        // println!("hair {}", charbytes[offset+1]);
        offset += 2;    // slot and hair

        if bGuildGuid[2]{
            offset +=1;
        }
        if bGuildGuid[0]{
            offset +=1;
        }
        if bGuildGuid[6]{
            offset +=1;
        }

        // add the name length to skip it
        let namebytes = &charbytes[offset..offset+ namelen as usize];
        let name = String::from_utf8(Vec::from(namebytes)).expect("dont care");
        // println!("Name: {}", name);
        offset += namelen as usize;

        if bGuildGuid[3]{
            offset +=1;
        }

        offset += 10;       // other fields to skip

        if bGuildGuid[5]{
            offset +=1;
        }

        // skip equipment slots
        offset += (23 as usize)*9;
        offset += 4;        // skip customization

        if bGuid[3]{
            guid[3]= charbytes[offset]^1;
            offset +=1;
        }
        if bGuid[5]{
            guid[5]= charbytes[offset]^1;
            offset +=1;
        }
        offset += 4;        // skip petFamily

        if bGuildGuid[4]{
            offset +=1;
        }

        offset += 6;        // skip race, skin map

        if bGuildGuid[1]{
            offset +=1;
        }

        // println!("level: {}", charbytes[offset]);
        let level = charbytes[offset];
        offset +=1;         // skip level

        if bGuid[0]{
            guid[0]= charbytes[offset]^1;
            offset +=1;
        }
        if bGuid[2]{
            guid[2]= charbytes[offset]^1;
            offset +=1;
        }
        offset +=7;         // skip hair gender facial petLevel

        if bGuid[4]{
            guid[4]= charbytes[offset]^1;
            offset +=1;
        }
        if bGuid[7]{
            guid[7]= charbytes[offset]^1;
            offset +=1;
        }

        offset +=12;         // skip y, petDisplayId. 0

        if bGuid[6]{
            guid[6]= charbytes[offset]^1;
            // offset +=1; last field
        }

        println!("Login with {} (lvl {})",name, level);

        // now the real shit happens: we need to add the booleans in bGuid to the guid bytes
        // let guid = guid.iter().zip(bGuid).map(|(g,b)| g + b as u8).collect::<Vec<u8>>();
        let guid = u64::from_le_bytes(guid[0..8].try_into().unwrap());
        // println!("guid {}", guid);

        Ok(SEnumCharactersResponse{
            guid
        })
    }
}

pub struct CReadyForAccountDataTimes{
}
impl Serializeable for CReadyForAccountDataTimes{
    fn write(&self, buf: &mut BytesMut) {
        buf.put(&to_plain_header(0,0x031C)[..]) // opcode CMSG_READY_FOR_ACCOUNT_DATA_TIMES
    }
}
pub struct CEnumCharacters{
}
impl Serializeable for CEnumCharacters{
    fn write(&self, buf: &mut BytesMut) {
        buf.put(&to_plain_header(0,0x00E0)[..]) // opcode CMSG_ENUM_CHARACTERS
    }
}

pub struct CPlayerLogin{
    pub guid: u64
}
impl Serializeable for CPlayerLogin{
    fn write(&self, buf: &mut BytesMut) {

        let mut payload = BytesMut::with_capacity(40); // CMSG_PLAYER_LOGIN

        //payload.put_u32(0);
        payload.put_u16(0);
        payload.put_u8(0x7a);
        payload.put_u8(0x44);

        write_guid_mask_login(&mut payload, &self.guid.to_le_bytes().into());
        write_guid_login(&mut payload, &self.guid.to_be_bytes().into());

        // payload.put_u8(0xad);
        // let guid = vec![0xf2, 0x63, 0x08, 0x0c, 0x00];
        // payload.put(&guid[..]);


        // println!("payload  {}", hex::encode(&payload.bytes()));


        let len = payload.len();

        buf.put(&to_plain_header(len as u16, 0x158F)[..]);
        buf.put(payload);
    }
}


pub struct SUpdateObject{
    pub guids: Vec<Vec<u8>>
}



impl Readable for SUpdateObject{
    fn read(_opcode:&u16, size: &u16,buf: &mut BytesMut) -> Result<Self, ParseError> {
        if *size > buf.remaining() as u16{
            println!("Over-Long packet received!");
            return Err(ParseError::NotEnoughData);
        }
        let _map = buf.get_u16_le();
        let _block_count = buf.get_u32_le();

        let amt = usize::min(buf.remaining(),*size as usize - 6);

        let mut blocks = vec![0;amt];
        buf.copy_to_slice(&mut blocks);
        // println!("SUpdateObject: map {}, blocks {}",map,block_count);
        // if block_count > 7{

        // }
        // println!("{}",hex::encode(&blocks));
        let _buf = BytesMut::from(&(blocks[..]));

        let mut guids = Vec::new();

        // This does work on the local server but crashes with the remote server
        // good luck, GUIDs are hardcoded

        // for i in 0..block_count {
        //     let update_type = buf.get_u8();
        //     println!("Block {}, ty {}, ", i, update_type);
        //     match update_type {
        //         0 => { // values
        //             let guid = SUpdateObject::get_pack_guid(&mut buf);
        //             println!("Processing VALUES block for guid {:?}", u64::from_le_bytes(guid[..].try_into().unwrap()));
        //             // // if u64::from_le_bytes(guid[..].try_into().unwrap()) == 99 {
        //             // //     break;
        //             // // }
        //             // guids.push(guid);

        //             let obj_type = buf.get_u8();
        //             buf = SUpdateObject::get_value_update(buf,obj_type);
        //             // break;
        //         }
        //         1 |2 => {
        //             let guid = SUpdateObject::get_pack_guid(&mut buf);
        //             println!("------- Processing CREATE block for guid {} --------", u64::from_le_bytes(guid[..].try_into().unwrap()));
                    
        //             // if u64::from_le_bytes(guid[..].try_into().unwrap()) == 99 {
        //             //     break;
        //             // }

        //             guids.push(guid);

        //             let obj_type = buf.get_u8();
        //             let mov_upd_start_rem = buf.remaining();
        //             buf = SUpdateObject::get_movement_update(buf);    
        //             let mov_upd_end_rem = buf.remaining();              
        //             println!("Mov update was {} bytes long",mov_upd_start_rem-mov_upd_end_rem);                    
        //             buf = SUpdateObject::get_value_update(buf,obj_type);
        //             let val_upd_end_rem = buf.remaining();                                  
        //             println!("Val update was {} bytes long",mov_upd_end_rem-val_upd_end_rem);                    

        //             println!("Leaving {} bytes unhandeled", buf.remaining());

        //         }
        //         3 => { // OOR GUIDS
        //             let guid_count = buf.get_u32_le();
        //             for j in 0..guid_count{
        //                 let guid = SUpdateObject::get_pack_guid(&mut buf);
        //                 // println!("Received oor for guid {:?}",hex::encode(&guid));
        //                 guids.push(guid);
        //             }
        //         }
        //         _ =>{
        //             panic!("unimplemented block type");
        //         }                
        //     }
        // }

        // for guid in &guids {
        //     println!("++++++++ Found GUID {:?}",hex::encode(guid));
        // }

        // server
        // let mut hardcoded_guid = vec![0xF1, 0x30, 0xB2, 0x5B, 0x00, 0x03, 0x16, 0x07];
        // hardcoded_guid.reverse();
        // guids.push(hardcoded_guid);

        // local
        let mut hardcoded_guid = vec![0xF1, 0x30, 0xB2, 0x5B, 0x00, 0x02, 0x76, 0x18];
        hardcoded_guid.reverse();
        guids.push(hardcoded_guid);

        Ok(SUpdateObject{
            guids
        })


    }
}

impl SUpdateObject {
    /*

    // Bugged on server, works local
    // I still do not want to delete it, since this was so much work

    fn get_pack_guid(buf: &mut BytesMut) -> Vec<u8> { // create_object
        let mask = buf.get_u8();
        let mut guid = vec![0; 8];
        for i in 0..8 {
            if mask>>i & 1  == 1{
                guid[i] = buf.get_u8();
            }
        }
       guid
    }

    fn get_movement_update(mut buf: BytesMut) -> BytesMut{
        // BuildMovementUpdate

        let mut bits = BitUtil::new(buf);
        let _ = bits.read_bits(2);
        let has_living = bits.read_bit();
        let _ = bits.read_bits(22+2);
        let has_vehicle = bits.read_bit();
        let _ = bits.read_bits(2);
        let has_transport = bits.read_bit();
        let has_rotation = bits.read_bit();
        let _ = bits.read_bit();
        let _has_self = bits.read_bit();
        let has_target = bits.read_bit();
        let _ = bits.read_bits(4);
        let has_go_transport_position = bits.read_bit();
        let _ = bits.read_bit();
        let has_stationary_position = bits.read_bit();


        let mut has_unit_transport = false;
        let mut has_movement_counter = false;
        let mut has_spline = false;
        let mut has_fall_data = false;
        let mut has_fall_direction = false;
        let mut has_spline_elevation = false;
        let mut has_Movement_info_time = false;
        let mut has_pitch = false;
        let mut has_fuzzy_eq = false;

        if has_living {
            // println!("Handling living");

            let _ = bits.read_bits(2);
            has_pitch = ! bits.read_bit();
            has_unit_transport = bits.read_bit();
            let _ = bits.read_bit();
            if has_unit_transport{
                // consume 10 bits
                panic!("unimplemented has_unit_transport")
            }
            has_Movement_info_time = ! bits.read_bit();
            let _ = bits.read_bits(3);
            has_fuzzy_eq = bits.read_bit();

            has_movement_counter = ! bits.read_bit();
            let _ = bits.read_bits(22+1);
            let has_movement_flags = !bits.read_bit();
            let _ = bits.read_bits(19);
            has_fall_data = bits.read_bit();
            if has_movement_flags {
                bits.read_bits(30);
            }
            has_spline_elevation = !bits.read_bit();
            has_spline = bits.read_bit();
            let _ = bits.read_bits(4);

            if has_spline {
                panic!("unimplemented has_spline")
            }
            let has_movement_flags_extra = !bits.read_bit();
            if has_fall_data {
                has_fall_direction = bits.read_bit();
            }
            if has_movement_flags_extra{
                let _ = bits.read_bits(13);
            }
    // 1032 {}
            if has_go_transport_position{
                panic!("unimplemented has_go_transport_position")
            }
            if has_target{
                let _ = bits.read_bits(8);
            }

        }

        // 1064 {}
        buf = bits.flush_and_destroy();

        if has_living {
            if has_unit_transport{
                panic!("unimplemented has_unit_transport")
            }
            let _guid_4 = buf.get_u8();
            if has_spline {
                panic!("unimplemented has_spline")
            }
            let _ = buf.get_u32();   //speed
            if has_movement_counter{
                let _ = buf.get_u32();   //movement_counter
            }
            let _ = buf.get_u8();
            if has_fall_data {
                if has_fall_direction {
                    let _ = buf.get_u32();
                    let _ = buf.get_u32();
                    let _ = buf.get_u32();

                }
                let _ = buf.get_u32();
                let _ = buf.get_u32();
            }
            let _ = buf.get_u8();
            let _ = buf.get_u32();  //MOVE_TURN_RATE
            if has_Movement_info_time {
                let _ = buf.get_u32();  //MOVE_TURN_RATE
            }
            let _ = buf.get_u32();  //MOVE_RUN_BACK
            if has_spline_elevation {
                let _ = buf.get_u32();
            }
            let _guid_7 = buf.get_u8();
            // println!("Guid_7: {}",guid_7);
            let _ = buf.get_u32();
            let _ = buf.get_u32();  //MOVE_TURN_RATE
            if has_pitch {
                let _ = buf.get_u32();
            }
            if ! has_fuzzy_eq {
                let _ = buf.get_u32();
            }
            let _ = buf.get_u32();
            let _ = buf.get_u32();
            let _ = buf.get_u32();

            let _ = buf.get_u8();
            let _ = buf.get_u8();
            let _ = buf.get_u8();
            // let _ = buf.get_u8();
            // TODO although this is not correct, we over-read one byte

            let _ = buf.get_u32();
            let _ = buf.get_u32();
            let _ = buf.get_u32();
            let _last_bytes = buf.get_u32();
            // println!("Last byte of movement_update:{}",hex::encode(last_bytes.to_be_bytes()));

        }

        if has_go_transport_position {
            panic!("unimplemented has_go_transport_position");
        }
        if has_target {
            panic!("unimplemented has_target");
        }
        if has_vehicle {
            panic!("unimplemented has_vehicle");
        }
        if has_stationary_position {
            let _ = buf.get_u32();
            let _ = buf.get_u32();
            let _ = buf.get_u32();
            let _ = buf.get_u32();
        }
        if has_transport {
            let _ = buf.get_u32();
        }
        if has_rotation {
            let _ = buf.get_u64();
        }
        if has_spline && has_living {
            panic!("unimplemented has_spline && has_living");
        }
        buf
    }



    fn get_value_update(mut buf: BytesMut, obj_type: u8) -> BytesMut{
        // BuildValuesUpdate

        /*
            u8 value_count
            update_mask
            field buffer (32bit values, value_count many )
            dynamic values update

            block_count = (valuesCount + CLIENT_UPDATE_MASK_BITS - 1) / CLIENT_UPDATE_MASK_BITS;
                        = (valuesCount + 4*8 -1) / (4*8)

            len(update_mask) =  block_count * 4 bytes
            len(field_buffer) = [valid flags] * 4 bytes
        */

        let block_count = buf.get_u8();
        if block_count == 0{
            // println!("Found empty value block, ignoring");
            return buf;
        }


        let update_mask_size = (block_count as usize) * 4; // since the mask parts are 32 bits
        let mut mask = vec![0;update_mask_size as usize];
        buf.copy_to_slice(&mut mask[..]);
        let mut valid_fields = 0;
        for mask_byte in &mask {
            for i in 0 ..8 {
                if mask_byte & (1<< i) > 0{
                    valid_fields+=1;
                }
            }
        }
        // println!("Trying to process {} value update blocks with {} valid fields according to mask {}", block_count, valid_fields, hex::encode(&mask));

        // read and ignore the fields
        for _ in 0 .. valid_fields {
            let _ = buf.get_u32();
        }

        /*
            BuildDynamicValuesUpdate
        */
        let has_dynamic = buf.get_u8();
        if has_dynamic > 0{
            if obj_type != 1 { // TYPEID_ITEM

            }
            else{
                let is_dynamic_tab_mask = buf.get_u8();
                // println!("is_dynamic_tab_mask {}",is_dynamic_tab_mask);
                if is_dynamic_tab_mask > 0 {
                    unimplemented!("unimplemented is_dynamic_tab_mask")
                }
            }
        }
        buf
    }
    */

}

pub struct CAuctionHello{
    pub guid: Vec<u8>
}

impl Serializeable for CAuctionHello{
    fn write(&self, buf: &mut BytesMut) {

        let mut payload = BytesMut::with_capacity(40);

        write_guid_mask_ah_hello(&mut payload, &self.guid);
        write_guid_ah_hello(&mut payload, &self.guid);

        // println!("CAuctionHello payload  {}", hex::encode(&payload.bytes()));

        let len = payload.len();
        buf.put(&to_plain_header(len as u16, 0x0379)[..]);
        buf.put(payload);
    }
}



pub struct SAuctionHello{
    
}
impl Readable for SAuctionHello{
    fn read(_opcode:&u16, size: &u16,buf: &mut BytesMut) -> Result<Self, ParseError> {
        // ignore the whole packet
        buf.advance(*size as usize);
        Ok(
            SAuctionHello{}
        )
    }
}

pub struct CSetSelection{
    pub guid: Vec<u8>,
}
impl Serializeable for CSetSelection{
    fn write(&self, buf: &mut BytesMut) {
        let mut payload = BytesMut::with_capacity(40);

        write_guid_mask_set_selection(&mut payload, &self.guid);
        write_guid_set_selection(&mut payload, &self.guid);

        // println!("CSetSelection payload  {}", hex::encode(&payload.bytes()));

        let len = payload.len();
        buf.put(&to_plain_header(len as u16, 0x0740)[..]);
        buf.put(payload);
    }
}


pub struct CListOwnerItems{
    pub guid: Vec<u8>,
}
impl Serializeable for CListOwnerItems{
    fn write(&self, buf: &mut BytesMut) {
        let mut payload = BytesMut::with_capacity(40);

        payload.put_u32(0); // list from

        write_guid_mask_ah_list_owner_items(&mut payload, &self.guid);
        write_guid_ah_list_owner_items(&mut payload, &self.guid);

        // println!("CSListOwnerItems payload  {}", hex::encode(&payload.bytes()));

        let len = payload.len();
        buf.put(&to_plain_header(len as u16, 0x0361)[..]);
        buf.put(payload);
    }
}
pub struct CListBidderItems{
    pub guid: Vec<u8>,
}
impl Serializeable for CListBidderItems{
    fn write(&self, buf: &mut BytesMut) {
        let mut payload = BytesMut::with_capacity(40);


        payload.put_u32(0); // list from
        
        let mut bits_0 = 0u8;
        bits_0 += ((self.guid[3]>1)as u8)<<7;
        bits_0 += ((self.guid[4]>1)as u8)<<6;
        bits_0 += ((self.guid[1]>1)as u8)<<5;
        bits_0 += ((self.guid[5]>1)as u8)<<4;
        bits_0 += ((self.guid[6]>1)as u8)<<3;
        bits_0 += ((self.guid[2]>1)as u8)<<2;

        let mut bits_1 = 0u8;
        bits_1 += ((self.guid[7]>1)as u8)<<2;
        bits_1 += ((self.guid[0]>1)as u8)<<1;

        payload.put_u8(bits_0);
        payload.put_u8(bits_1);

        write_byte_seq(&mut payload, self.guid[3]);
        write_byte_seq(&mut payload, self.guid[4]);
        write_byte_seq(&mut payload, self.guid[1]);
        write_byte_seq(&mut payload, self.guid[0]);
        write_byte_seq(&mut payload, self.guid[2]);
        write_byte_seq(&mut payload, self.guid[5]);
        write_byte_seq(&mut payload, self.guid[7]);
        write_byte_seq(&mut payload, self.guid[6]);


        // println!("CListBidderItems payload  {}", hex::encode(&payload.bytes()));

        let len = payload.len();
        buf.put(&to_plain_header(len as u16, 0x12D0)[..]);
        buf.put(payload);
    }
}



pub struct CAuctionListItems{
    pub guid: Vec<u8>,
    pub start_list_from: u32
}
impl Serializeable for CAuctionListItems{
    fn write(&self, buf: &mut BytesMut) {

        let mut payload = BytesMut::with_capacity(40);

        let magic_number_to_list_all_the_things = 4294967295u32;
        let auction_slot_id = magic_number_to_list_all_the_things;
        let auction_main_category = magic_number_to_list_all_the_things;
        let auction_sub_category = magic_number_to_list_all_the_things;
        let quality = magic_number_to_list_all_the_things;
        let sort_count = 0x0e;  // was 0
        let level_min = 0;
        let level_max = 0;
        let list_from = self.start_list_from;
        let search_string_len = 0;

        payload.put_u32(auction_slot_id);
        payload.put_u32_le(list_from);
        payload.put_u32(auction_main_category);
        payload.put_u8(7); //was 8
        payload.put_u8(level_max);
        payload.put_u8(level_min);
        payload.put_u32(quality);
        payload.put_u32(auction_sub_category);
        payload.put_u32_le(sort_count);

        let mut bits_0 = 0u8;
        bits_0 += ((self.guid[3]>1)as u8)<<7;
        bits_0 += ((self.guid[4]>1)as u8)<<6;
        bits_0 += ((self.guid[5]>1)as u8)<<5;
        bits_0 += ((self.guid[2]>1)as u8)<<4;
        //skip usable items and exact match
        bits_0 += ((self.guid[7]>1)as u8)<<1;
        bits_0 += (self.guid[0]>1) as u8;

        let mut bits_1 = 0u8;
        bits_1 += ((self.guid[1]>1)as u8)<<7;
        bits_1 += ((self.guid[6]>1)as u8)<<6;


        let unknown_data = 
            // vec![
            //     //0x0a, 0x00, 0x01, 
            // 0x00, 0x00, 0x01, 0x05, 0x00,
            //  0x06, 0x00, 0x09, 0x01, 0x08, 0x00, 0x03, 0x00];
            vec![
                //0x0a, 0x00, 
                0x01, 
            0x00, 0x00, 0x01, 0x05, 0x00,
             0x06, 0x00, 0x09, 0x01, 0x08, 0x00, 0x03, 0x00];

        payload.put(&unknown_data[..]);

        payload.put_u8(bits_0);
        payload.put_u8(search_string_len);
        payload.put_u8(bits_1);

        write_byte_seq(&mut payload, self.guid[6]);
        write_byte_seq(&mut payload, self.guid[3]);
        write_byte_seq(&mut payload, self.guid[4]);
        write_byte_seq(&mut payload, self.guid[0]);
        write_byte_seq(&mut payload, self.guid[7]);
        write_byte_seq(&mut payload, self.guid[2]);
                // skip the search string

        write_byte_seq(&mut payload, self.guid[1]);
        write_byte_seq(&mut payload, self.guid[5]);

        // println!("CAuctionListItems payload  {}", hex::encode(&payload.bytes()));

        let len = payload.len();
        buf.put(&to_plain_header(len as u16, 0x02EA)[..]);
        buf.put(payload);
    }
}

fn write_byte_seq(payload: &mut BytesMut, byte: u8 ){
    if byte > 0 {
        payload.put_u8(byte^1);
    }
}




pub struct SAuctionListResult{
    pub auctions: Vec<Auction>,
}


#[derive(Debug)]
pub struct Auction{
    id: u32,
    entry: u32,
    count: u32,
    owner: u64,
    startbid: u64,
    buyout: u64,
    time_left: u32,
    bidder: u64,
    bid: u64
}

impl Readable for SAuctionListResult{
    fn read(_opcode:&u16, _size: &u16,buf: &mut BytesMut) -> Result<Self, ParseError> {
        println!("##################################################################");
        println!("#############           SAuctionListResult        ################");
        let amount = buf.get_u32_le();
        println!("Expecting {} auctions",amount);

        let mut auctions = Vec::new();

        for _i in 0..amount {
            let id = buf.get_u32_le();
            let entry = buf.get_u32_le();
            for _enchant_ctr in 0..8 {
                let _enchant_id = buf.get_u32_le();
                let _enchant_dur = buf.get_u32_le();
                let _enchant_charges = buf.get_u32_le();
            }
            let _ = buf.get_u32_le();
            let _random_property_id = buf.get_u32_le();
            let _item_suffix_factor = buf.get_u32_le();
            let count = buf.get_u32_le();
            let _spell_charges = buf.get_u32_le();
            let _ = buf.get_u32_le();
            let owner = buf.get_u64_le();
            let startbid = buf.get_u64_le();
            let _whatever = buf.get_u64_le();
            let buyout = buf.get_u64_le();

            let time_left = buf.get_u32_le();
            let bidder = buf.get_u64_le();
            let bid = buf.get_u64_le();

            let auction = Auction{
                id,
                entry,
                count,
                owner,
                startbid,
                buyout,
                time_left,
                bidder,
                bid
            };
            auctions.push(auction);
        }
        
        for auction in &auctions{
            println!("-> {:?}", auction);
        }
        

        let _totalcount = buf.get_u32_le();
        let _search_delay = buf.get_u32_le();    // probably is 300ms
        println!("##################################################################");

        Ok(
            SAuctionListResult{
                auctions
            }
        )
    }
}



pub struct STimesyncRequest{
    pub counter: u32
}


impl Readable for STimesyncRequest{
    fn read(_opcode:&u16, _size: &u16,buf: &mut BytesMut) -> Result<Self, ParseError> {
        let counter = buf.get_u32_le();
        // println!("STimesyncRequest counter: {}, size: {}",counter,size);
        Ok(
            STimesyncRequest{
                counter
            }
        )
    }
}

pub struct CTimesyncResponse{
    pub counter: u32,
    pub client_ticks: u32
}


impl Serializeable for CTimesyncResponse{
    fn write(&self, buf: &mut BytesMut) {

        let mut payload = BytesMut::with_capacity(40);

        payload.put_u32_le(self.counter);
        payload.put_u32_le(self.client_ticks);        


        // println!("CTimesyncResponse payload  {}", hex::encode(&payload.bytes()));

        let len = payload.len();

        buf.put(&to_plain_header(len as u16, 0x01DB)[..]);
        buf.put(payload);
    }
}



pub struct SAuctionOwnerListResult{
    
}


impl Readable for SAuctionOwnerListResult{
    fn read(_opcode:&u16, size: &u16,buf: &mut BytesMut) -> Result<Self, ParseError> {
        if *size > buf.remaining() as u16{
            return Err(ParseError::NotEnoughData);
        }
        
        buf.advance(*size as usize);
        Ok(
            SAuctionOwnerListResult{}
        )
    }
}


pub struct SAuctionBidderListResult{
    
}


impl Readable for SAuctionBidderListResult{
    fn read(_opcode:&u16, size: &u16,buf: &mut BytesMut) -> Result<Self, ParseError> {
        if *size > buf.remaining() as u16{
            return Err(ParseError::NotEnoughData);
        }
        
        buf.advance(*size as usize);
        Ok(
            SAuctionBidderListResult{}
        )
    }
}



pub struct CAuctionMagicPacket{
}

impl Serializeable for CAuctionMagicPacket{
    fn write(&self, buf: &mut BytesMut) {
        buf.put(&to_plain_header(0,0x02DA)[..])
    }
}


pub struct CInspect{
}

impl Serializeable for CInspect{
    fn write(&self, buf: &mut BytesMut) {
        let mut payload = BytesMut::with_capacity(16);

        payload.put(&vec![0xB5, 0x0C, 0xF2, 0x08, 0x63, 0x00][..]);  

        let len = payload.len();
        buf.put(&to_plain_header(len as u16, 0x1259)[..]);
        buf.put(payload);    }
}



pub struct SAccountDataTimes{
    pub server_start_time: u64
}


impl Readable for SAccountDataTimes{
    fn read(_opcode:&u16, size: &u16,buf: &mut BytesMut) -> Result<Self, ParseError> {
        if *size > buf.remaining() as u16{
            return Err(ParseError::NotEnoughData);
        }

        let mut data = vec![0;(*size) as usize];
        let time_start_index = &data.len()-4;
        buf.copy_to_slice(&mut data[..]);
        let data = Vec::from(&data[time_start_index..]);
        // println!("SAccountDataTimes {}",hex::encode(&data));
        let server_time = u32::from_le_bytes(data[0..4].try_into().unwrap()) as u64;
        // println!("Server Time: {}", server_time);
        use std::time::{SystemTime, UNIX_EPOCH};
        let unix_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let unix_ms_time = unix_time.as_secs() * 1000 + unix_time.subsec_nanos() as u64 / 1_000_000;
        let server_start_time = unix_ms_time-server_time;
        
        // buf.advance(*size as usize);
        Ok(
            SAccountDataTimes{
                server_start_time
            }
        )
    }
}