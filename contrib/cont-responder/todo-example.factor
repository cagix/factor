! Copyright (C) 2004 Chris Double.
! 
! Redistribution and use in source and binary forms, with or without
! modification, are permitted provided that the following conditions are met:
! 
! 1. Redistributions of source code must retain the above copyright notice,
!    this list of conditions and the following disclaimer.
! 
! 2. Redistributions in binary form must reproduce the above copyright notice,
!    this list of conditions and the following disclaimer in the documentation
!    and/or other materials provided with the distribution.
! 
! THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
! INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
! FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
! DEVELOPERS AND CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
! SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
! PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
! OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
! WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
! OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
! ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
!
! A simple 'to-do list' web application.
!
! Users can register with the system and from there manage a simple
! list of things to do. All data is stored in a directory in the 
! filesystem with the users name.
IN: todo-example
USE: cont-responder
USE: cont-html
USE: cont-utils
USE: html
USE: stdio
USE: stack
USE: strings
USE: namespaces
USE: inspector
USE: lists
USE: combinators
USE: cont-examples
USE: regexp
USE: prettyprint
USE: todo
 
: show-stack-page ( -- )
  #! Debug function to show a page containing the current call stack.
  [ .s ] with-string-stream chars>entities show-message-page ;

: row ( list -- )
  #! Output an html TR row with each element of the list
  #! being called to produce the output for each TD.
  <tr> [
    [ <td> [ call ] </td> ] each
  ] </tr> ;

: simple-input ( name -- )
  #! Output a simple HTML input field which will have the
  #! specified name.
  <input type= "text" size= "20" name= input/> ;

: textarea-input ( name -- )
  #! Output a simple HTML textarea field which will have the
  #! specified name.
  <input type= "text" size= "60" name= input/> ;
!  <textarea name= textarea> [ "Enter description here." write ] </textarea> ;

: password-input ( name -- )
  #! Output an HTML password input field which will have the
  #! specified name.
  <input type= "password" size= "20" name= input/> ;

: form ( action quot  -- )
  #! Call quot with any output appearing inside an HTML form.
  #! The form is a POST form where the action is as specified.
  <form method= "post" action= swap form> swap </form> ;

: input-value ( name -- value )
  #! Get the value of the variable "name". If it is f 
  #! return "" else return the value.
  get [ "" ] unless* ;

: login-form ( url button-text -- )
  #! Write the HTML for an HTML form requesting a username
  #! and password. The 'accept' button has the text given 
  #! in 'button-text'. The form will go to the given URL on
  #! submission.
  swap [
    <table> [
      [ [ "Name:" write ] [ "name" simple-input ] ] row
      [ [ "Password:" write ] [ "password" password-input ] ] row
    ] </table>
    button     
  ] form ;
   
: registration-page ( submit-url -- )
  #! Write the HTML for the registration page to std output.
  "Register New TODO List" [
    "Enter the username and password for your new todo list:" paragraph
    "Register" login-form
  ] simple-page ;

: login-details-valid? ( name password -- )
  #! Ensure that a valid username and password were
  #! entered. In particular, ensure that only alphanumeric
  #! data was entered to prevent security problems by
  #! using .., etc in the name.
  drop "[a-zA-Z0-9]*" re-matches ;
  
: get-registration-details ( -- name password )
  #! Get the registration details from the user putting
  #! the name and password on the stack.
  [ registration-page ] show [
    "name" get "password" get
  ] bind 2dup login-details-valid? [ 
    2drop 
    "Please ensure you enter a username containing letters and numbers only." show-message-page 
    get-registration-details 	
  ] unless ;
   
: get-todo-filename ( database-path <todo> -- filename )
  #! Get the filename containing the todo list details.
  <% swap % todo-username % ".todo" % %> ;
  
: add-default-todo-item ( <todo> -- )
  #! Add a default todo item. This is a workaround for the 
  #! currently hackish method of saving todo lists which can't
  #! handle empty lists.
  "1" "Set up todo list" <todo-item> add-todo-item ;

: init-new-todo ( <todo> -- )
  #! Add the default todo item and store the todo list to
  #! persistent storage.
  dup add-default-todo-item 
  dup "database-path" get swap get-todo-filename store-todo ;

: register-new-user ( -- )
  #! Get registration details for a new user and add a
  #! todo list for them.
  get-registration-details 
  2dup "database-path" get -rot user-exists? [
    2drop
    "That user already exists in the system, sorry. Please use another name."
    show-message-page
    register-new-user
  ] [
    <todo> init-new-todo
    "You have successfully registered your todo list." show-message-page
  ] ifte ;

: login-request-paragraph ( -- )
  #! Display the paragraph requesting the user to login or register.
  <p> [ 
    "Please enter your username and password (" write
    "Click to Register" [ register-new-user ] quot-href
    "):" write
  ] </p> ;
  
: get-login-information ( -- user password )
  [
    "Login" [     
      login-request-paragraph 
      "Login" login-form
    ] simple-page 
  ] show [ 
    "name" get "password" get 
  ] bind  ;

: ensure-login-valid ( user password -- user password )
  2dup login-details-valid? [ 
    "Please ensure you enter a username containing letters and numbers only." show-message-page 
    get-login-information 	
  ] unless ;

: get-todo-list ( -- <todo> )
  #! Prompts for a username or password until a valid combination
  #! is entered then returns the <todo> list for that user.
  get-login-information ensure-login-valid 
  "database-path" get -rot user-exists? [ 
    "Sorry, your username or password was incorrect." show-message-page
    get-todo-list 
  ] unless* ;

: write-new-todo-item-form ( url -- )
  #! Display the HTML for a form allowing entry of a 
  #! todo item details.
  [
    <table> [
      [ [ "Priority:" write ]    [ "priority" simple-input ] ] row
      [ [ "Description:" write ] [ "description" textarea-input ] ] row
    ] </table>
    "Add" button
  ] form ;
  
: get-new-todo-item ( -- <todo-item> )
  #! Enter a new item to the current todo list.
  [
    "Enter New Todo Item" [ write-new-todo-item-form ] simple-page  
  ] show [ 
    "priority" get "description" get <todo-item> 
  ] bind ;

: save-current-todo ( -- )
  #! Save the current todo list
  "database-path" get "todo" get get-todo-filename "todo" get swap store-todo ;

: lcurry1 ( value quot -- quot )
  #! Return a quotation that when called will have 'value' 
  #! as the first item on the stack.
  cons ;

: write-mark-complete-action ( item -- )
  #! Write out HTML to perform a mark complete
  #! action on an item (or other appropriate
  #! action if already complete).
  dup item-complete? [
    "Delete" swap [ "todo" get swap delete-item save-current-todo ] lcurry1 quot-href
  ] [
    "Mark Completed" swap [ set-item-completed save-current-todo ] lcurry1 quot-href
  ] ifte ;

: write-item-row ( <todo-item> -- )
  #! Write the todo list item as an HTML row.
  dup dup dup
  [ [ item-priority write ] 
    [ item-complete? [ "Yes" ] [ "No" ] ifte write ] 
    [ item-description write ] 
    [ write-mark-complete-action ] 
  ] row ;

: write-item-table ( <todo> -- )
  #! Write the table of items for the todo list.
  <table> [
    [ [ "Priority" write ] [ "Complete?" write ] [ "Description" write ] [ "Action" write ] ] row
    todo-items [ write-item-row ] each 
  ] </table> ;

: do-add-new-item ( -- )
  #! Request a new item from the user and add it to the current todo list.
  "todo" get get-new-todo-item add-todo-item save-current-todo ;

: show-todo-list ( -- )
  #! Show the current todo list.
  [
    <% "todo" get todo-username % "'s To Do list" % %>
    [
      drop
      "todo" get write-item-table
      "Add Item" [ do-add-new-item ] quot-href
    ] simple-page 
  ] show drop ;

: todo-example ( path -- )
  #! Startup the todo list example using the given path as the 
  #! directory holding the todo files.
  "database-path" set
  get-todo-list "todo" set
  show-todo-list ;

"todo" [ drop "todo/" todo-example ] install-cont-responder