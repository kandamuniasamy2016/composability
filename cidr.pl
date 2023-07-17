:- module(cidr, [cidr/2]).

ip_int(ip(A,B,C,D), Int) :-
    Int is A<<24+B<<16+C<<8+D.

bits_mask(Bits, Mask) :-
    Mask is ((1<<Bits)-1)<<(32-Bits).

cidr(Mask/Bits, IP) :-
    ip_int(Mask, MaskInt),
    ip_int(IP, IPInt),
    bits_mask(Bits, MaskBits),
    MaskInt/\MaskBits =:= IPInt/\MaskBits.

/** <examples>
?- bits_mask(24, Bits), format('~2r', [Bits]).
?- cidr(ip(10,0,0,0)/24, ip(10,0,0,1)).
?- cidr(ip(10,0,0,0)/24, ip(10,0,1,1)).
*/
