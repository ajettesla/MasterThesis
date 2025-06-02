Here's a professionally written and properly structured version of your `README.md` file, with corrections for grammar, clarity, and technical accuracy (based on the context you've provided):

---

# Connection Tracking Logger

This program collects connection tracking information using the **libnetfilter\_conntrack** library. It leverages the `nfct_catch` function to receive real-time updates on connection events.

Each event is timestamped using the system's **REALTIME\_CLOCK** and placed into a **Single Producer Single Consumer (SPSC)** queue. This queue is used to pass data efficiently to a parsing thread. After parsing, the data is handed off to a **syslog thread**, which batches the events (in groups of 5 or every 1 second, whichever comes first) and sends them to a syslog server.

---

## Event Fields

### 1. `type_num`

This field represents the numeric type of the conntrack event. It is included because the `--payload` option is enabled. It is set in `extract_conn_event` as:

```c
event.type_num = type;
```

Where `type` is an enum of type `nf_conntrack_msg_type`:

* `NFCT_T_NEW = 0` — New connection
* `NFCT_T_UPDATE = 1` — Updated connection
* `NFCT_T_DESTROY = 2` — Connection destroyed

---

### 2. `state_num`

This field represents the numeric TCP state and is also included due to the `--payload` option. It is only applicable when the protocol is TCP.

Set as:

```c
event.state_num = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
```

TCP state mapping based on the code:

* `0 = NONE`
* `1 = SYN_SENT`
* `2 = SYN_RECV`
* `3 = ESTABLISHED`
* `4 = FIN_WAIT`
* `5 = CLOSE_WAIT`
* `6 = LAST_ACK`
* `7 = TIME_WAIT`
* `8 = CLOSE`

---

### 3. `proto_num`

This field represents the numeric protocol number and is included because `--payload` is specified.

Set as:

```c
event.proto_num = nfct_get_attr_u8(ct, ATTR_L4PROTO);
```

Standard IP protocol numbers:

* `6 = TCP`
* `17 = UDP`

---


