REQUIRES: libs/shuffle libs/matrices libs/http-client
libs/canvas ;

PROVIDE: demos/bunny { +files+ { "bunny.factor" } } ;

USE: bunny

MAIN: demos/bunny bunny-window ;