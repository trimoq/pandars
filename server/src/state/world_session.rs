
use std::collections::HashMap;

pub struct WorldSessionState {
  game_objects: HashMap<Vec<u8>,GameObject>,
  pub current_scan_npc: Option<Vec<u8>>,
  pub current_scan_offset: u32,
  pub num_auction_presulde_received: u32,
  pub timesync_ctr: u32,
  pub server_start_time: u64
}

impl WorldSessionState{
  pub fn new() -> Self{
    WorldSessionState{
      game_objects: HashMap::new(),
      current_scan_npc: None,
      current_scan_offset: 0,
      num_auction_presulde_received: 0,
      timesync_ctr: 0,
      server_start_time: 0
    }
  }

  pub fn record_observed_guids(&mut self, guids: Vec<Vec<u8>>){
    for guid in guids{
      if ! self.game_objects.contains_key(&guid){
        self.game_objects.insert(guid.clone(), GameObject{/*guid*/});
      }
    }
  }

  pub fn try_start_auction_scan(&mut self) -> Option<Vec<u8>>{

    let valid_auctioneers = vec![
      vec![0xAF,0x43],
      vec![0xB2, 0x5B] 
    ];

    if self.timesync_ctr == 0 {
      return None
    }

    match self.current_scan_npc{
      Some(_) => {
        None
      },
      None => {
        for guid in self.game_objects.keys(){
          for npc_id in &valid_auctioneers{
            if is_guid_of_npc(guid,npc_id){
              self.current_scan_npc = Some(guid.clone());
              return Some(guid.clone())
            }
          }
        }
        return None
      }
    }
  }

}


fn is_guid_of_npc(guid: &Vec<u8>, npc_id: &Vec<u8>) -> bool{
  guid[4] == npc_id[1] && guid[5] == npc_id[0] 
}

struct GameObject{
  // guid: Vec<u8> // currently unused, since GUIDs are hardcoded
}

