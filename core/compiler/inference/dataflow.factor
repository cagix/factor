! Copyright (C) 2004, 2007 Slava Pestov.
! See http://factorcode.org/license.txt for BSD license.
IN: inference
USING: arrays generic assocs kernel math
namespaces parser sequences words vectors intervals ;

SYMBOL: d-in
SYMBOL: meta-d
SYMBOL: meta-r

: push-d meta-d get push ;
: pop-d meta-d get pop ;
: peek-d meta-d get peek ;

: push-r meta-r get push ;
: pop-r meta-r get pop ;
: peek-r meta-r get peek ;

TUPLE: node param
in-d out-d in-r out-r
classes literals intervals
history successor children ;

C: node ( param in-d out-d in-r out-r -- node )
    [ set-node-out-r ] keep
    [ set-node-in-r ] keep
    [ set-node-out-d ] keep
    [ set-node-in-d ] keep
    [ set-node-param ] keep ;

M: node equal? 2drop f ;

M: node hashcode* drop node hashcode* ;

: node-shuffle ( node -- shuffle )
    dup node-in-d swap node-out-d <effect> ;

: make-node ( param in-d out-d in-r out-r node -- node )
    [ >r <node> r> set-delegate ] keep ;

: empty-node f { } { } { } { } ;
: param-node { } { } { } { } ;
: in-node >r f r> { } { } { } ;
: out-node >r f { } r> { } { } ;
: all-in-node f meta-d get clone { } { } { } ;
: all-out-node f { } meta-d get clone { } { } ;

: d-tail ( n -- seq )
    dup zero? [ drop f ] [ meta-d get swap tail* ] if ;

: r-tail ( n -- seq )
    dup zero? [ drop f ] [ meta-r get swap tail* ] if ;

: node-child node-children first ;

TUPLE: #label word ;
C: #label make-node ;
: #label ( word label -- node )
    param-node <#label> [ set-#label-word ] keep ;

TUPLE: #entry ;
C: #entry make-node ;

: #entry ( -- node ) all-out-node <#entry> ;

TUPLE: #call ;
C: #call make-node ;
: #call ( word -- node ) param-node <#call> ;

TUPLE: #call-label ;
C: #call-label make-node ;
: #call-label ( label -- node ) param-node <#call-label> ;

TUPLE: #push ;
C: #push make-node ;
: #push ( -- node ) empty-node <#push> ;

TUPLE: #shuffle ;
C: #shuffle make-node ;
: #shuffle ( -- node ) empty-node <#shuffle> ;

TUPLE: #>r ;
C: #>r make-node ;
: #>r ( -- node ) empty-node <#>r> ;

TUPLE: #r> ;
C: #r> make-node ;
: #r> ( -- node ) empty-node <#r>> ;

TUPLE: #values ;
C: #values make-node ;
: #values ( -- node ) all-in-node <#values> ;

TUPLE: #return ;
C: #return make-node ;
: #return ( label -- node )
    all-in-node <#return> [ set-node-param ] keep ;

TUPLE: #if ;
C: #if make-node ;
: #if ( -- node ) peek-d 1array in-node <#if> ;

TUPLE: #dispatch ;
C: #dispatch make-node ;
: #dispatch ( -- node ) peek-d 1array in-node <#dispatch> ;

TUPLE: #merge ;
C: #merge make-node ;
: #merge ( -- node ) all-out-node <#merge> ;

TUPLE: #terminate ;
C: #terminate make-node ;
: #terminate ( -- node ) empty-node <#terminate> ;

TUPLE: #declare ;
C: #declare make-node ;
: #declare ( classes -- node ) param-node <#declare> ;

UNION: #branch #if #dispatch ;

: node-inputs ( d-count r-count node -- )
    tuck
    >r r-tail r> set-node-in-r
    >r d-tail r> set-node-in-d ;

: node-outputs ( d-count r-count node -- )
    tuck
    >r r-tail r> set-node-out-r
    >r d-tail r> set-node-out-d ;

SYMBOL: dataflow-graph
SYMBOL: current-node

: node, ( node -- )
    dataflow-graph get [
        dup current-node [ set-node-successor ] change
    ] [
        dup dataflow-graph set  current-node set
    ] if ;

: node-values ( node -- values )
    [
        dup node-in-d % dup node-out-d %
        dup node-in-r % node-out-r %
    ] { } make ;

: last-node ( node -- last )
    dup node-successor [ last-node ] [ ] ?if ;

: penultimate-node ( node -- penultimate )
    dup node-successor dup [
        dup node-successor
        [ nip penultimate-node ] [ drop ] if
    ] [
        2drop f
    ] if ;

: #drop ( n -- #shuffle )
    d-tail in-node <#shuffle> ;

: all-nodes? ( node quot -- ? )
    over [
        [ call ] 2keep rot [
            [
                swap node-children [ swap all-nodes? ] all-with?
            ] 2keep rot [
                >r node-successor r> all-nodes?
            ] [
                2drop f
            ] if
        ] [
            2drop f
        ] if
    ] [
        2drop t
    ] if ; inline

: all-nodes-with? ( obj node quot -- ? )
    swap [ with rot ] all-nodes? 2nip ; inline

GENERIC: calls-label* ( label node -- ? )

M: node calls-label* 2drop f ;

M: #call-label calls-label* node-param eq? ;

: calls-label? ( label node -- ? )
    [ calls-label* not ] all-nodes-with? not ;

: recursive-label? ( node -- ? )
    dup node-param swap calls-label? ;

SYMBOL: node-stack

: >node node-stack get push ;
: node> node-stack get pop ;
: node@ node-stack get peek ;

DEFER: iterate-nodes

: iterate-children ( quot -- )
    node@ node-children [ swap iterate-nodes ] each-with ;
    inline

: iterate-next ( -- node ) node@ node-successor ;

: iterate-nodes ( node quot -- )
    over [
        [ swap >node call node> drop ] keep iterate-nodes
    ] [
        2drop
    ] if ; inline

: ?set-node-successor ( next prev -- )
    [ set-node-successor ] [ drop ] if* ;

: map-node ( prev quot -- )
    swap >r node@ swap call dup r> ?set-node-successor
    node> drop >node ; inline

DEFER: map-children
DEFER: (map-nodes)

: map-next ( quot -- )
    node@ [
        swap [ map-children ] keep
        node> node-successor >node (map-nodes)
    ] [
        drop
    ] if* ; inline

: (map-nodes) ( prev quot -- )
    node@
    [ [ map-node ] keep map-next ]
    [ drop f swap ?set-node-successor ] if ; inline

: map-first ( node quot -- node )
    call node> drop dup >node ; inline

: map-nodes ( node quot -- node )
    over [
        over >node [ map-first ] keep map-next node>
    ] when drop ; inline

: map-children ( quot -- )
    node@ [ node-children [ swap map-nodes ] map-with ] keep
    set-node-children ; inline

: with-node-iterator ( quot -- )
    [ V{ } clone node-stack set call ] with-scope ; inline

: (each-node) ( quot -- quot next )
    [ node@ swap call ] keep
    [ (each-node) ] iterate-children
    iterate-next ; inline

: each-node ( node quot -- )
    [
        swap [
            (each-node)
        ] iterate-nodes drop
    ] with-node-iterator ; inline

: each-node-with ( obj node quot -- )
    swap [ with ] each-node 2drop ; inline

: (subst-values) ( new old node -- )
    [
        [ node-in-d subst ] 3keep [ node-in-r subst ] 3keep
        [ node-out-d subst ] 3keep [ node-out-r subst ] 3keep
        drop
    ] each-node 2drop ;

: subst-values ( new old node -- )
    node-stack get 1 head-slice* swap add
    [ >r 2dup r> node-successor (subst-values) ] each 2drop ;

: node-literal? ( node value -- ? )
    dup value? >r swap node-literals key? r> or ;

: node-literal ( node value -- obj )
    dup value?
    [ nip value-literal ] [ swap node-literals at ] if ;

: node-interval ( node value -- interval )
    swap node-intervals at ;

: node-class ( node value -- class )
    swap node-classes at [ object ] unless* ;

: node-class-first ( node -- class )
    dup node-in-d first node-class ;