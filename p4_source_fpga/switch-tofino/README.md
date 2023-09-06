switch.p4
=========

The switch.p4 program describes a data plane of an L2/L3 switch.

Supported Features
------------------
1. Basic L2 switching: Flooding, learning and STP
2. Basic L3 Routing: IPv4 and IPv6 and VRF
3. LAG
4. ECMP
5. Tunneling: VXLAN
6. Basic ACL: MAC and IP ACLs
7. Unicast RPF check
8. Host interface
9. Mirroring: Ingress and egress mirroring with ERSPAN
10. Counters/Statistics


Naming Convention
-----------------
1. Types and struct types are named using lower case words separated by `_`
  followed by `_t`. For example, `switch_port_t`.
2. Control types and extern object types are named using CamelCase. For
  example `IngressParser`.
3. Actions, extern methods, extern functions, headers, structs, and
  instances of controls and externs start with lower case and words
  are separated using `_`. For example `send_to_port`.
4. Enum members, const definitions, and #define constants are all
  caps, with words separated by `_`. For example 'ETHERTYPE_IPV4'.
5. When nameing P4 pipelines following conventions are to be followed:
   * Pipeline name _pipe_ is reserved for the switch.p4 pipeline programs.
   * All tables and other p4 entities within pipeline _pipe_ support programming via BMAI implementation present within
     the SDE.
   * Any custom pipeline that extends or appends switch.p4 pipeline _pipe_ must use a name other than pipe. (Eg. _pipe_
     on Pipe 0 and Pipe 3; _custom_ on Pipe 1 and Pipe 4)
   * An Ingress + Egress processing pipeline is generally viewed and treated as single p4 pipeline. In such cases the
     above naming conventions must be followed for any custom p4 pipelines.
   * For the case where the pipeline is logically split into two separate pipelines - an Ingress P4 Pipeline + Egress P4
     Pipeline. It is required that the pipeline name follows the naming format <name_in>_<name_eg>. The below
     conventions apply for this case.
     1. name_in/name_eg should be named as _pipe_ if the respective ingress/egress pipeline runs a part of the switch.p4
        _pipe_ pipeline
     2. for custom p4 code and ingress/egress pipeline any other valid name can be used.
        For example:
        * custom_pipe - A pipeline running _custom_ pipeline on ingress and switch.p4 _pipe_ pipeline on the egress.
        * pipe_custom - A pipeline running _custom_ pipeline on egress and switch.p4 _pipe_ pipeline on the ingress.
