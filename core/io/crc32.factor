! Copyright (C) 2006 Doug Coleman
! See http://factorcode.org/license.txt for BSD license.
USING: kernel math sequences sequences-internals namespaces
words io quotations ;
IN: crc32

: crc32-polynomial HEX: edb88320 ; inline

! Generate the table at load time and define a new word with it,
! instead of using a variable, so that the compiler can inline
! the call to nth-unsafe
DEFER: crc32-table inline

\ crc32-table
256 [
    8 [
        dup 1 bitand zero? >r -1 shift r>
        [ crc32-polynomial bitxor ] unless
    ] times
] map
1quotation define-compound

: (crc32) ( crc ch -- crc )
    dupd bitxor
    mask-byte crc32-table nth-unsafe
    swap -8 shift bitxor ;

: crc32 ( seq -- n )
    >r HEX: ffffffff dup r> [ (crc32) ] each bitxor ;

: file-crc32 ( path -- n ) <file-reader> contents crc32 ;