/**
* Semantics of networking and reachability
*
*/

/**
* Public and Private nature of resources
*/
isPublic(X) :- placement(X,_,_, _, Y),
                       subnet(_, Y, _,public).
isPrivate(X) :- placement(X,_,_, _, Y), subnet(_, Y, _,private).
canReach(X, Y) :- placement(X,_,_, Z, _), placement(Y,_,_, Z, _), X \= Y.

/**
* Some of the security groups entries do not return a name, particularly when SGs associated with RDS. Hence we reference 
* the secgrups by both the name as well as the id
*/
canSSHFromInternet(X) :- isPublic(X), secgrp_association(X, Y,_), secgroup(Y, _,ingress, 1, -1, null, null, ip(0,0,0,0/0), _). 
canSSHFromInternet(X) :- isPublic(X), secgrp_association(X, _, Y), secgroup(_, Y,ingress, 1, -1, null, null, ip(0,0,0,0/0), _).
canSSHFromInternet(X) :- isPublic(X), secgrp_association(X, Y,_), secgroup(Y, _,ingress, _, _, Fromport, Toport, ip(0,0,0,0/0), _), Fromport \= null, between(Fromport, Toport, 22).
canSSHFromInternet(X) :- isPublic(X), secgrp_association(X, _, Y), secgroup(_, Y,ingress, _, _, Fromport, Toport, ip(0,0,0,0/0), _), Fromport \= null, between(Fromport, Toport, 22).

sshPassthrough(X) :- isPrivate(X), placement(X, _, _, VPCID, _), vpc(VPCID, CIDR, _, _), secgrp_association(X, Y, _), secgroup(Y, _, ingress, _, _, Fromport, Toport,CIDR, _), Fromport \= null, between(Fromport, Toport, 22), canReach(X, Z), canSSHFromInternet(Z), X \= Z.
sshPassthrough(X) :- isPrivate(X), placement(X, _, _, VPCID, _), vpc(VPCID, CIDR, _, _), secgrp_association(X, _, Y), secgroup(_, Y, ingress, _, _, Fromport, Toport, CIDR, _), Fromport \= null, between(Fromport, Toport, 22), isPublic(Z), canReach(X, Z), canSSHFromInternet(Z), X \= Z.
sshPassthrough(X) :- isPublic(X), placement(X, _, _, VPCID, _), vpc(VPCID, CIDR, _, _), secgrp_association(X, Y, _), secgroup(Y, _, ingress, _, _, Fromport, Toport, CIDR, _), Fromport \= null, between(Fromport, Toport, 22), isPublic(Z), canReach(X, Z), canSSHFromInternet(Z), X \= Z.
sshPassthrough(X) :- isPublic(X), placement(X, _, _, VPCID, _), vpc(VPCID, CIDR, _, _), secgrp_association(X, _, Y), secgroup(_, Y, ingress, _, _, Fromport, Toport, CIDR, _), Fromport \= null, between(Fromport, Toport, 22), isPublic(Z), canReach(X, Z), canSSHFromInternet(Z), X \= Z.
/**
* canSSHFromInternet(X) :- isPrivate(X), secgrp_association(X, Y, _), secgroup(Y, _, ingress, _, _, Fromport, Toport, _, _), Fromport \= null, between(Fromport, Toport, 22), canReach(X, Z), canSSHFromInternet(Z), X \= Z.
* canSSHFromInternet(X) :- isPrivate(X), secgrp_association(X, _, Y), secgroup(_, Y, ingress, _, _, Fromport, Toport, _, _), Fromport \= null, between(Fromport, Toport, 22), canReach(X, Z), canSSHFromInternet(Z), X \= Z.
*/

/**
* Security groups with non-standard ports
*
* composableCompute(X) :- encrypted(X), not(canSSHFromInternet(X)), secgrp_association(X, Y, _), not(nonCompliantSecGroup(Y)).
*/
nonCompliantSecGroup(ID) :- secgroup(ID, _, ingress, _, _, X, _, ip(0,0,0,0/0),_), not(memberchk(X, [443, 80, 22])).

/**
* Encrypted at rest properties
*/
encrypted(X) :- compute(X, Y, _, _), Y = encrypted_ebs.
unencrypted(X) :- compute(X, Y, _, _), Y \= encrypted_ebs.
rdsEncryptionAtRest(X):- rds(X, Y, _), Y = encrypted.

composableCompute(X) :- encrypted(X), (isPrivate(X) ; (not(canSSHFromInternet(X)), secgrp_association(X, Y, _), not(nonCompliantSecGroup(Y)))).
composableRDS(X) :- rdsEncryptionAtRest(X), isPrivate(X).
