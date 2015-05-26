## overall
- [ ] organize cpp files into headers
- [ ] add logging support throughout
- [ ] some ints need to be 64 bits
- [x] use std::string instead of char*
- [ ] pack methods should return std::string

## topology.cpp
- [ ] topology dict format
- [ ] fill unknown types in topology.cpp
- [ ] fix the parse_dict function

## router.cpp
- [ ] surround main code with try/catch
- [ ] think about sockets implementation

## packet_base.cpp
- [ ] Payload type being PacketBase* doesn't seem right
- [ ]

## scion.cpp
- [ ] have to check if path is not None before accessing any of its members
- [ ] SCIONPacket::parse: have assigned a char array to payload 
- [ ] SCIONPacket::pack: should check if payload is of type char* or PacketBase

## pcb.cpp
- [ ] fix PathConstructionBeacon
