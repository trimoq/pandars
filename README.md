# panda_rs
Your friendly  Mists of Pandaria Auction House Scanner 

## What does it do

It connects to a Mists of Pandaria server and scans the AH for you.
Things implemented:
- Authentaication
- Selecting characters from the realm server
- Joining the world with cahracters
- Talking with AH dude
- Starting an AH scan across all items

Things not implemented:
- Warden. Would work on local server but any serious private server has their own custom warden checks and we don't want to steal these. After all, this keeps all the people away from this project, that want to use this scanner to harm others.
- Dynamic GUIDs for the AH dude. This works on a local server but the reference private server is doing things the code can't handle.
- Writing the found auctions to a DB backend. This should be easy but you have to do it yourself.

## Code Quality
Hah, "quality"....

The project was mostly used to learn Rust, network debbing, C++, reverse engineering. 
Therefore, most of the code works but is unstructured, verbose, sprinkled with sections commented out.
The learning character especially shows in the main.rs file, I thought it might be a nice idea to use `mio` in this project for the first time. 

## Sample output

The output looks something like this:

```
##################################################################
#############         starting   panda_rs         ################
##################################################################
# > Don't write Bots that ruin it for others !                   #
##################################################################
Starting Panda_rs for 192.168.121.170:3724
Realm Skyfire MoP has IP 192.168.121.170:8085 and 2 chars
Connecting to Skyfire MoP at 192.168.121.170:8085
Connecting to 192.168.121.170:8085
Login with Bot (lvl 20)
Trying to login with guid 0000000000000063
##################################################################
#############           SAuctionListResult        ################
Expecting 16 auctions
-> Auction { id:  1, entry: 72988, count:  5, owner: 100, startbid: 52500, buyout: 13370000, time_left: 86221000, bidder: 0, bid: 0 }
-> Auction { id:  2, entry: 72988, count:  5, owner: 100, startbid: 52500, buyout: 13370000, time_left: 86221000, bidder: 0, bid: 0 }
-> Auction { id:  3, entry: 72988, count:  5, owner: 100, startbid: 52500, buyout: 13370000, time_left: 86221000, bidder: 0, bid: 0 }
-> Auction { id:  4, entry: 72988, count:  5, owner: 100, startbid: 52500, buyout: 13370000, time_left: 86222000, bidder: 0, bid: 0 }
-> Auction { id:  5, entry: 72988, count:  5, owner: 100, startbid: 52500, buyout: 13370000, time_left: 86222000, bidder: 0, bid: 0 }
-> Auction { id:  6, entry: 72988, count:  5, owner: 100, startbid: 52500, buyout: 13370000, time_left: 86222000, bidder: 0, bid: 0 }
-> Auction { id:  7, entry: 72988, count:  5, owner: 100, startbid: 52500, buyout: 13370000, time_left: 86222000, bidder: 0, bid: 0 }
-> Auction { id:  8, entry: 72988, count:  5, owner: 100, startbid: 52500, buyout: 13370000, time_left: 86222000, bidder: 0, bid: 0 }
-> Auction { id:  9, entry: 72988, count:  5, owner: 100, startbid: 52500, buyout: 13370000, time_left: 86222000, bidder: 0, bid: 0 }
-> Auction { id: 10, entry: 72988, count:  5, owner: 100, startbid: 52500, buyout: 13370000, time_left: 86222000, bidder: 0, bid: 0 }
-> Auction { id: 11, entry: 72988, count:  5, owner: 100, startbid: 52500, buyout: 13370000, time_left: 86222000, bidder: 0, bid: 0 }
-> Auction { id: 12, entry: 72988, count:  5, owner: 100, startbid: 52500, buyout: 13370000, time_left: 86222000, bidder: 0, bid: 0 }
-> Auction { id: 13, entry: 72988, count:  5, owner: 100, startbid: 52500, buyout: 13370000, time_left: 86222000, bidder: 0, bid: 0 }
-> Auction { id: 14, entry: 72988, count:  5, owner: 100, startbid: 52500, buyout: 13370000, time_left: 86222000, bidder: 0, bid: 0 }
-> Auction { id: 15, entry: 72988, count: 10, owner: 100, startbid: 56250, buyout:   420000, time_left: 86248000, bidder: 0, bid: 0 }
-> Auction { id: 16, entry:  2589, count:  4, owner: 100, startbid:   100, buyout:     4200, time_left: 86330000, bidder: 0, bid: 0 }
##################################################################
-------------------------- Received SAuctionListResult  --------------------------
##################################################################
#############           SAuctionListResult        ################
Expecting 0 auctions
##################################################################
-------------------------- Received SAuctionListResult  --------------------------
Found no further auctions
```
