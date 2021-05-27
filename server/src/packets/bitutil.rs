use bytes::{BytesMut, BufMut, Buf};


#[allow(dead_code)]
pub struct BitUtil{
  buf: BytesMut,
  cur_byte: u8,
  position: u32,
}

#[allow(dead_code)]
impl BitUtil{

  pub fn new(mut buf: BytesMut) -> Self{
    let first_byte = buf.get_u8();
    BitUtil{
      buf,
      cur_byte: first_byte,
      position: 0,
    }
  }

  pub fn flush_and_destroy(self) -> BytesMut{
    self.buf
  }

  // we do not shift the current byte !
  pub fn destroy(mut self) -> BytesMut{
    let mut v = vec![0u8;self.buf.remaining()];
    self.buf.copy_to_slice(&mut v[..]);
    let mut buf = BytesMut::with_capacity(self.buf.remaining()+1);
    buf.put_u8(self.cur_byte);
    buf.copy_from_slice(&v[..]);
    buf
  }



  pub fn read_bit(&mut self) -> bool{
    if self.position == 8 {
      self.position = 0;
      self.cur_byte = self.buf.get_u8();
    }
    // println!("self.cur_byte {}",self.cur_byte);
    let val = ((self.cur_byte >> (7 - self.position)) & 1) != 0;
    self.position += 1;
    return val
  }

  pub fn read_bits(&mut self,amount: u8) -> u32{
      let mut value = 0u32;
      let mut i = amount - 1;
      loop{
        if self.read_bit(){
          value |= 1 << (i);
        }
        if i == 0{
          break;
        }
        i-=1;
      }
      return value;
  }
}

mod test{
  
  
  #[test]
  fn test_single_bits(){
    let mut buf = BytesMut::with_capacity(2);
    buf.put_u8(0b0100_0010);
    buf.put_u8(0b0001_1000);

    let mut bits = BitUtil::new(buf);

    assert_eq!(false,bits.read_bit());
    assert_eq!(true,bits.read_bit());
    assert_eq!(false,bits.read_bit());
    assert_eq!(false,bits.read_bit());
    assert_eq!(false,bits.read_bit());
    assert_eq!(false,bits.read_bit());
    assert_eq!(true,bits.read_bit());
    assert_eq!(false,bits.read_bit());

    assert_eq!(false,bits.read_bit());
    assert_eq!(false,bits.read_bit());
    assert_eq!(false,bits.read_bit());
    assert_eq!(true,bits.read_bit());
    assert_eq!(true,bits.read_bit());
    assert_eq!(false,bits.read_bit());
    assert_eq!(false,bits.read_bit());
    assert_eq!(false,bits.read_bit());
  }

  #[test]
  fn test_multiple_bits(){
    let mut buf = BytesMut::with_capacity(2);
    buf.put_u8(0b0100_0010);
    buf.put_u8(0b0001_1000);

    let mut bits = BitUtil::new(buf);

    assert_eq!(false,bits.read_bit());
   
    let _ = bits.read_bits(9);

    assert_eq!(false,bits.read_bit());
    assert_eq!(true,bits.read_bit());
    assert_eq!(true,bits.read_bit());
    assert_eq!(false,bits.read_bit());
    assert_eq!(false,bits.read_bit());
    assert_eq!(false,bits.read_bit());
  }
}