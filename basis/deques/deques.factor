! Copyright (C) 2008, 2010 Slava Pestov.
! See https://factorcode.org/license.txt for BSD license.
USING: fry kernel sequences ;
IN: deques

GENERIC: push-front* ( obj deque -- node )
GENERIC: push-back* ( obj deque -- node )
GENERIC: peek-front* ( deque -- obj ? )
GENERIC: peek-back* ( deque -- obj ? )
GENERIC: pop-front* ( deque -- )
GENERIC: pop-back* ( deque -- )
GENERIC: delete-node ( node deque -- )
GENERIC: deque-member? ( value deque -- ? )
GENERIC: clear-deque ( deque -- )
GENERIC: node-value ( node -- value )
GENERIC: deque-empty? ( deque -- ? )

ERROR: empty-deque ;

: peek-front ( deque -- obj )
    peek-front* [ drop empty-deque ] unless ; inline

: ?peek-front ( deque -- obj/f )
    peek-front* and* ; inline

: peek-back ( deque -- obj )
    peek-back* [ drop empty-deque ] unless ; inline

: ?peek-back ( deque -- obj/f )
    peek-back* and* ; inline

: push-front ( obj deque -- )
    push-front* drop ; inline

: push-all-front ( seq deque -- )
    '[ _ push-front ] each ; inline

: push-back ( obj deque -- )
    push-back* drop ; inline

: push-all-back ( seq deque -- )
    '[ _ push-back ] each ; inline

: pop-front ( deque -- obj )
    [ peek-front ] [ pop-front* ] bi ; inline

: pop-back ( deque -- obj )
    [ peek-back ] [ pop-back* ] bi ; inline

: slurp-deque ( ... deque quot: ( ... obj -- ... ) -- ... )
    [ drop '[ _ deque-empty? ] ]
    [ '[ _ pop-back @ ] ]
    2bi until ; inline

MIXIN: deque
