-- Zixi 2019
-- explicit GRE protocol dissector - for GRE over UDP (rfc8086) and RIST main profile extensions

-- Generic GRE
gre_over_udp = Proto("GREoUDP", "GRE protocol")

function gre_over_udp.dissector(buffer, pinfo, tree)
	gre_dissector = DissectorTable.get("ip.proto"):get_dissector(47)
	-- pass it to the implicit GRE over IP dissector
	gre_dissector:call(buffer, pinfo, tree)
end

-- Reduced GRE 
gre_reduced = Proto("GRE_reduced", "GRE reduced overhead")
src_port = ProtoField.uint16("gre_reduced.src_port", "Source Port")
dst_port = ProtoField.uint16("gre_reduced.dst_port", "Destination Port")
gre_reduced.fields = { src_port, dst_port }

function gre_reduced.dissector(buffer, pinfo, tree)
	local subtree = tree:add(gre_reduced,buffer(), "GRE reduced header")
	subtree:add(src_port, buffer(0,2))
	subtree:add(dst_port, buffer(2,2))
	-- pass payload to UDP dissector
	udp_dissector = DissectorTable.get("ip.proto"):get_dissector(17)
	udp_dissector:call(buffer(4):tvb(), pinfo, tree)
end

-- Keepalive message  
-- | ID(48) |X|R|B|A|P|E|L|N|D|T|V|J| Rsvd1(4) |
gre_keepalive = Proto("GRE_keepalive", "GRE keepalive message header")
id = ProtoField.uint64("gre_keepalive.id", "Unique ID", base.HEX, nil, 0xFFFFFFFFFFFF0000)
X = ProtoField.uint16("gre_keepalive.X", "X", base.HEX, nil, 0x8000)
R = ProtoField.uint16("gre_keepalive.R", "R", base.HEX, nil, 0x4000)
B = ProtoField.uint16("gre_keepalive.B", "B", base.HEX, nil, 0x2000)
A = ProtoField.uint16("gre_keepalive.A", "A", base.HEX, nil, 0x1000)
P = ProtoField.uint16("gre_keepalive.P", "P", base.HEX, nil, 0x0800)
E = ProtoField.uint16("gre_keepalive.E", "E", base.HEX, nil, 0x0400)
L = ProtoField.uint16("gre_keepalive.L", "L", base.HEX, nil, 0x0200)
N = ProtoField.uint16("gre_keepalive.N", "N", base.HEX, nil, 0x0100)
D = ProtoField.uint16("gre_keepalive.D", "D", base.HEX, nil, 0x0080)
T = ProtoField.uint16("gre_keepalive.T", "T", base.HEX, nil, 0x0040)
V = ProtoField.uint16("gre_keepalive.V", "V", base.HEX, nil, 0x0020)
J = ProtoField.uint16("gre_keepalive.J", "J", base.HEX, nil, 0x0010)
Rsvd1 = ProtoField.uint16("gre_keepalive.Rsvd1", "Rsvd1", base.HEX, nil, 0x000F)
gre_keepalive.fields = { id,X,R,B,A,P,E,L,N,D,T,V,J,Rsvd1 }

function gre_keepalive.dissector(buffer, pinfo, tree)
	local subtree = tree:add(gre_keepalive,buffer(), "GRE keepalive message")
	pinfo.cols.info:set("GRE keepalive")	
	subtree:add(id, buffer(0,6))
	subtree:add(X, buffer(6,2))
	subtree:add(R, buffer(6,2))
	subtree:add(B, buffer(6,2))
	subtree:add(A, buffer(6,2))
	subtree:add(P, buffer(6,2))
	subtree:add(E, buffer(6,2))
	subtree:add(L, buffer(6,2))
	subtree:add(N, buffer(6,2))
	subtree:add(D, buffer(6,2))
	subtree:add(T, buffer(6,2))
	subtree:add(V, buffer(6,2))
	subtree:add(J, buffer(6,2))
	subtree:add(Rsvd1, buffer(6,2))
end

-- register new GRE protocols
DissectorTable.get("gre.proto"):add(0x88B6, gre_reduced);
DissectorTable.get("gre.proto"):add(0x88B5, gre_keepalive);

-- load the udp.port table
udp_table = DissectorTable.get("udp.port")

-- register our protocol to handle UDP port 5000
udp_table:add(5000, gre_over_udp)

