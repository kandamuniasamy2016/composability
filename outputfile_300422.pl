:- use_module('cidr.pl').
:- use_module(library(clpb)).
:- use_module(library(prolog_stack)).
:- consult('properties.pl').
:- discontiguous compute/4.
:- discontiguous placement/5.
:- discontiguous secgrp_association/3.
:- discontiguous placement/5.
:- discontiguous vpc/4.
:- discontiguous secgroup/9.
:- discontiguous nacl/6.
:- discontiguous rds/3.
:- discontiguous secgrp_association/3.
:- discontiguous subnet/4.
/**
**
* VPC Configuration Information
**
*/
vpc("vpc-0b2c4cd2619c92780", ip(172,31,0,0/16), aws_account, us-east-1).
subnet("vpc-0b2c4cd2619c92780", "subnet-0855f8a5fe411af57", ip(172,31,0,0/20), public).
subnet("vpc-0b2c4cd2619c92780", "subnet-0c828c58fe44bcec2", ip(172,31,80,0/24), private).
subnet("vpc-0b2c4cd2619c92780", "subnet-07ebce5b611e576c0", ip(172,31,160,0/24), private).
nacl("vpc-0b2c4cd2619c92780", egress, 100, -1, ip(0,0,0,0/0), allow).
nacl("vpc-0b2c4cd2619c92780", egress, 32767, -1, ip(0,0,0,0/0), deny).
nacl("vpc-0b2c4cd2619c92780", ingress, 100, -1, ip(0,0,0,0/0), allow).
nacl("vpc-0b2c4cd2619c92780", ingress, 32767, -1, ip(0,0,0,0/0), deny).
secgroup(launch-wizard-1, "sg-02856cf8f1dbb4642", ingress, 0, tcp, 0, 65535, "sg-03c0557c6a2a7526b", null).
secgroup(launch-wizard-1, "sg-02856cf8f1dbb4642", ingress, 1, tcp, 22, 22, ip(172,31,0,0/16), "SSH within the VPC").
secgroup(launch-wizard-1, "sg-02856cf8f1dbb4642", ingress, 2, tcp, 443, 443, ip(0,0,0,0/0), null).
secgroup(launch-wizard-1, "sg-02856cf8f1dbb4642", ingress, 3, tcp, 5060, 5061, ip(0,0,0,0/0), "For SIP").
secgroup(launch-wizard-1, "sg-02856cf8f1dbb4642", egress, 0, -1, 0, 65535, ip(0,0,0,0/0), null).
secgroup(sg1, "sg-0af8df2ed6ca761c2", ingress, 0, tcp, 0, 65535, "sg-03c0557c6a2a7526b", null).
secgroup(sg1, "sg-0af8df2ed6ca761c2", ingress, 1, tcp, 22, 22, ip(172,31,0,0/16), "SSH within the VPC").
secgroup(sg1, "sg-0af8df2ed6ca761c2", ingress, 2, tcp, 443, 443, ip(0,0,0,0/0), null).
secgroup(sg1, "sg-0af8df2ed6ca761c2", ingress, 3, tcp, 5060, 5061, ip(0,0,0,0/0), "For SIP").
secgroup(sg1, "sg-0af8df2ed6ca761c2", egress, 0, -1, 0, 65535, ip(0,0,0,0/0), null).
secgroup(rdb-sg, "sg-0fd79e3a2f06e9942", ingress, 0, tcp, 3306, 3306, ip(172,31,0,0/16), null).
secgroup(rdb-sg, "sg-0fd79e3a2f06e9942", egress, 0, -1, 0, 65535, ip(0,0,0,0/0), null).
secgroup(default, "sg-03c0557c6a2a7526b", ingress, 0, -1, null, null, "sg-03c0557c6a2a7526b", null).
secgroup(default, "sg-03c0557c6a2a7526b", egress, 0, -1, 0, 65535, ip(0,0,0,0/0), null).
secgroup(sg3, "sg-0db5d7a7287724920", ingress, 0, tcp, 0, 65535, "sg-03c0557c6a2a7526b", null).
secgroup(sg3, "sg-0db5d7a7287724920", ingress, 1, -1, null, null, ip(0,0,0,0/0), null).
secgroup(sg3, "sg-0db5d7a7287724920", ingress, 2, tcp, 22, 22, ip(172,31,0,0/16), "SSH within VPC is allowed").
secgroup(sg3, "sg-0db5d7a7287724920", egress, 0, -1, 0, 65535, ip(0,0,0,0/0), null).
compute(c2, encrypted_ebs, "t2_micro", public).
placement(c2, "i-06b55c398c90071fe", compute, "vpc-0b2c4cd2619c92780", "subnet-0855f8a5fe411af57").
secgrp_association(c2, sg3, "sg-0db5d7a7287724920").
compute(c3, encrypted_ebs, "t2_micro", private).
placement(c3, "i-02edbb191deac5405", compute, "vpc-0b2c4cd2619c92780", "subnet-0c828c58fe44bcec2").
secgrp_association(c3, sg3, "sg-0db5d7a7287724920").
compute(c1, encrypted_ebs, "t2_micro", private).
placement(c1, "i-08cd29c47a1e96bc8", compute, "vpc-0b2c4cd2619c92780", "subnet-07ebce5b611e576c0").
secgrp_association(c1, sg3, "sg-0db5d7a7287724920").
rds(rds-instance-1, encrypted, "aurora-mysql").
placement(rds-instance-1, "db-HTYHWD4MQJTSL442JAHD4NXMTE", rdms, "vpc-0b2c4cd2619c92780", "subnet-07ebce5b611e576c0").
placement(rds-instance-1, "db-HTYHWD4MQJTSL442JAHD4NXMTE", rdms, "vpc-0b2c4cd2619c92780", "subnet-0c828c58fe44bcec2").
secgrp_association(rds-instance-1, null, "sg-03c0557c6a2a7526b").
secgrp_association(rds-instance-1, null, "sg-0fd79e3a2f06e9942").
