IN: vim
USING: definitions io kernel math namespaces parser
prettyprint process sequences tools ;

SYMBOL: vim-path
SYMBOL: vim-detach

"gvim" vim-path set-global

: vim-command ( file line -- string )
    [ "\"" % vim-path get % "\" \"" % swap % "\" +" % # ] "" make ;

: vim-location ( file line -- )
    vim-command
    vim-detach get-global
    [ run-detached ] [ run-process ] if ;

[ vim-location ] edit-hook set-global