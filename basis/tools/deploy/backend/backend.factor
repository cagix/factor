! Copyright (C) 2007, 2008 Slava Pestov.
! See http://factorcode.org/license.txt for BSD license.
USING: namespaces make continuations.private kernel.private init
assocs kernel vocabs words sequences memory io system arrays
continuations math definitions mirrors splitting parser classes
summary layouts vocabs.loader prettyprint.config prettyprint
debugger io.streams.c io.files io.backend quotations io.launcher
words.private tools.deploy.config tools.deploy.config.editor
bootstrap.image io.encodings.utf8 destructors accessors ;
IN: tools.deploy.backend

: copy-vm ( executable bundle-name extension -- vm )
    [ prepend-path ] dip append vm over copy-file ;

: copy-fonts ( name dir -- )
    deploy-ui? get [
        append-path "resource:fonts/" swap copy-tree-into
    ] [ 2drop ] if ;

: image-name ( vocab bundle-name -- str )
    prepend-path ".image" append ;

: copy-lines ( -- )
    readln [ print flush copy-lines ] when* ;

: run-with-output ( arguments -- )
    <process>
        swap >>command
        +stdout+ >>stderr
        +closed+ >>stdin
        +low-priority+ >>priority
    utf8 [ copy-lines ] with-process-reader ;

: make-boot-image ( -- )
    #! If stage1 image doesn't exist, create one.
    my-boot-image-name resource-path exists?
    [ my-arch make-image ] unless ;

: bootstrap-profile ( -- profile )
    {
        { "math"     deploy-math?     }
        { "compiler" deploy-compiler? }
        { "threads"  deploy-threads?  }
        { "ui"       deploy-ui?       }
        { "unicode"  deploy-unicode?  }
    } [ nip get ] assoc-filter keys
    native-io? [ "io" suffix ] when ;

: staging-image-name ( profile -- name )
    "staging."
    swap strip-word-names? [ "strip" suffix ] when
    "-" join ".image" 3append temp-file ;

DEFER: ?make-staging-image

: staging-command-line ( profile -- flags )
    [
        "-staging" ,

        dup empty? [
            "-i=" my-boot-image-name append ,
        ] [
            dup but-last ?make-staging-image

            "-resource-path=" "" resource-path append ,

            "-i=" over but-last staging-image-name append ,

            "-run=tools.deploy.restage" ,
        ] if

        "-output-image=" over staging-image-name append ,

        "-include=" swap " " join append ,

        strip-word-names? [ "-no-stack-traces" , ] when

        "-no-user-init" ,
    ] { } make ;

: run-factor ( vm flags -- )
    swap prefix dup . run-with-output ; inline

: make-staging-image ( profile -- )
    vm swap staging-command-line run-factor ;

: ?make-staging-image ( profile -- )
    dup staging-image-name exists?
    [ drop ] [ make-staging-image ] if ;

: make-deploy-config ( vocab -- file )
    [ deploy-config unparse-use ]
    [ "deploy-config-" prepend temp-file ] bi
    [ utf8 set-file-contents ] keep ;

: deploy-command-line ( image vocab config -- flags )
    [
        bootstrap-profile ?make-staging-image

        [
            "-i=" bootstrap-profile staging-image-name append ,

            "-resource-path=" "" resource-path append ,

            "-run=tools.deploy.shaker" ,

            [ "-deploy-vocab=" prepend , ]
            [ make-deploy-config "-deploy-config=" prepend , ] bi

            "-output-image=" prepend ,

            strip-word-names? [ "-no-stack-traces" , ] when
        ] { } make
    ] bind ;

: make-deploy-image ( vm image vocab config -- )
    make-boot-image
    deploy-command-line run-factor ;

HOOK: deploy* os ( vocab -- )
