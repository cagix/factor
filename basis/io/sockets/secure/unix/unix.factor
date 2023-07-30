! Copyright (C) 2007, 2011, Slava Pestov, Elie CHAFTARI.
! See https://factorcode.org/license.txt for BSD license.
USING: accessors combinators destructors io.backend.unix io.files
io.sockets.private io.sockets.secure io.sockets.secure.openssl
io.timeouts kernel openssl openssl.libssl system ;
FROM: io.ports => shutdown ;
IN: io.sockets.secure.unix

M: openssl ssl-supported? t ;
M: openssl ssl-certificate-verification-supported? t ;

M: ssl-handle handle-fd file>> handle-fd ;

M: unix socket-handle fd>> ;

M: secure remote>handle
    [ addrspec>> remote>handle ] [ hostname>> ] bi <ssl-socket> ;

M: secure parse-sockaddr addrspec>> parse-sockaddr f <secure> ;

M: secure (get-local-address) addrspec>> (get-local-address) ;

M: secure establish-connection
    addrspec>> [ establish-connection ] [ secure-connection ] 2bi ;

M: secure (accept)
    [
        addrspec>> (accept) [ |dispose f <ssl-socket> ] dip
    ] with-destructors ;

: (shutdown) ( ssl-handle -- )
    dup handle>> SSL_shutdown {
        ! 0 means we need to read again (part one of two-way shutdown)
        { 0 [ [ +input+ wait-for-fd ] [ (shutdown) ] bi ] }
        ! 1 means the two-way shutdown is complete
        { 1 [ drop ] }
        ! error
        { -1 [ -1 check-ssl-error "impossible" throw ] }
    } case ;

M: ssl-handle shutdown
    dup connected>> [
        f >>connected [ (shutdown) ] with-timeout
    ] [ drop ] if ;

M: unix non-ssl-socket? fd? ;
