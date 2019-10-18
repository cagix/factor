! Fast Fourier Transform, copyright (C) 2007 Hans Schmid
! http://dressguardmeister.blogspot.com/2007/01/fft.html
IN: fft
USING: arrays sequences math kernel ;

: n^v ( n v -- w ) [ ^ ] map-with ;
: even ( seq -- seq ) 2 group 0 <column> ;
: odd ( seq -- seq ) 2 group 1 <column> ;
DEFER: fft
: two ( seq -- seq ) fft 2 v/n dup append ;
: omega ( n -- n ) recip -2 pi i * * * exp ;
: twiddle ( seq -- seq ) dup length dup omega swap n^v v* ;
: (fft) ( seq -- seq ) dup odd two twiddle swap even two v+ ;
: fft ( seq -- seq ) dup length 1 = [ (fft) ] unless ;

PROVIDE: demos/fft ;