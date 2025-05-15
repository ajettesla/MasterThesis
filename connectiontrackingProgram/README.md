1 (type_num):
This is the numeric type of the conntrack event, included because --payload is specified.
It’s set in extract_conn_event as event.type_num = type, where type is an enum nf_conntrack_msg_type.
Based on the code:
NFCT_T_NEW = 0
NFCT_T_UPDATE = 1
NFCT_T_DESTROY = 2

(state_num):
This is the numeric TCP state, included because --payload is specified and the protocol is TCP.
It’s set in extract_conn_event as event.state_num = nfct_get_attr_u8(ct, ATTR_TCP_STATE) if the protocol is TCP and the attribute is set.
Based on the code’s state mapping:
0 = NONE
1 = SYN_SENT
2 = SYN_RECV
3 = ESTABLISHED
4 = FIN_WAIT
5 = CLOSE_WAIT
6 = LAST_ACK
7 = TIME_WAIT
8 = CLOSE

6 (proto_num):
This is the numeric protocol number, included because --payload is specified.
It’s set in extract_conn_event as event.proto_num = nfct_get_attr_u8(ct, ATTR_L4PROTO).
Standard IP protocol numbers:
6 = TCP
17 = UDP
