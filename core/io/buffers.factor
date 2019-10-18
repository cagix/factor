! Copyright (C) 2004, 2005 Mackenzie Straight.
! Copyright (C) 2006, 2007 Slava Pestov.
! See http://factorcode.org/license.txt for BSD license.
IN: buffers
USING: alien errors kernel kernel-internals libc math sequences
strings ;

TUPLE: buffer size ptr fill pos ;

C: buffer ( n -- buffer )
    2dup set-buffer-size
    [ >r malloc check-ptr r> set-buffer-ptr ] keep
    0 over set-buffer-fill
    0 over set-buffer-pos ;

: buffer-free ( buffer -- )
    dup buffer-ptr free  f swap set-buffer-ptr ;

: buffer-reset ( n buffer -- )
    [ set-buffer-fill ] keep 0 swap set-buffer-pos ;

: buffer-consume ( n buffer -- )
    [ buffer-pos + ] keep
    [ buffer-fill min ] keep
    [ set-buffer-pos ] keep
    dup buffer-pos over buffer-fill >= [
        0 over set-buffer-pos
        0 over set-buffer-fill
    ] when drop ;

: buffer-addr ( buffer -- n )
    buffer-ptr alien-address ;

: buffer@ ( buffer -- alien )
    dup buffer-pos swap buffer-ptr <displaced-alien> ;

: buffer-end ( buffer -- alien )
    dup buffer-fill swap buffer-ptr <displaced-alien> ;

: buffer-peek ( buffer -- ch )
    buffer@ 0 alien-unsigned-1 ;

: buffer-pop ( buffer -- ch )
    dup buffer-peek 1 rot buffer-consume ;

: (buffer>) ( n buffer -- string )
    [ dup buffer-fill swap buffer-pos - min ] keep
    buffer@ swap memory>string ;

: buffer> ( n buffer -- string )
    [ (buffer>) ] 2keep buffer-consume ;

: (buffer>>) ( buffer -- string )
    dup buffer-pos over buffer-ptr <displaced-alien>
    over buffer-fill rot buffer-pos - memory>string ;

: buffer>> ( buffer -- string )
    dup (buffer>>) 0 rot buffer-reset ;

FUNCTION: long memcspn ( void* s, void* end, char* charset ) ;

: (buffer-until) ( separators buffer -- n )
    dup buffer@ swap buffer-end rot memcspn ;

: buffer-until ( separators buffer -- string separator )
    [ (buffer-until) ] keep over -1 number=
    [ nip buffer>> f ] [ [ buffer> ] keep buffer-pop ] if ;

: buffer-length ( buffer -- n )
    dup buffer-fill swap buffer-pos - ;

: buffer-capacity ( buffer -- n )
    dup buffer-size swap buffer-fill - ;

: buffer-empty? ( buffer -- ? )
    buffer-fill zero? ;

: extend-buffer ( n buffer -- )
    2dup buffer-ptr swap realloc check-ptr
    over set-buffer-ptr set-buffer-size ;

: check-overflow ( n buffer -- )
    2dup buffer-capacity > [ extend-buffer ] [ 2drop ] if ;

: >buffer ( string buffer -- )
    over length over check-overflow
    [ buffer-end string>memory ] 2keep
    [ buffer-fill swap length + ] keep set-buffer-fill ;

: ch>buffer ( ch buffer -- )
    1 over check-overflow
    [ buffer-end 0 set-alien-unsigned-1 ] keep
    [ buffer-fill 1+ ] keep set-buffer-fill ;

: buffer-bound ( buffer -- n )
    dup buffer-addr swap buffer-size + ;

: n>buffer ( n buffer -- )
    [ buffer-fill + ] keep 
    [ buffer-bound > [ "Buffer overflow" throw ] when ] 2keep
    set-buffer-fill ;