(*
   Require Netencoding.Url
 *)

(**
  Mono threaded OAuth 2 client for OCaml
 *)

open Https_client
open Http_client
open Http_client.Convenience

(*
 Initialize random stuff:
 - integer generator
 - https client
 *)
let _ = Random.self_init ()
let _ = Ssl.init()
let _ = configure_pipeline
  (fun p ->
    let ctx = Ssl.create_context Ssl.TLSv1 Ssl.Client_context in
    let tct = https_transport_channel_type ctx in
    p # configure_transport https_cb_id tct
  )

(*
   TYPES
 *)

(**
   OAuth Exception
 *)
exception OAuthException of (int * string)

(**
   OAuth versions supported
 *)
type oAuthVersion =
  | OAUTH_2

(**
   OAuth HTTP methods supported
 *)
type oAuthHTTPMethods =
  | GET
  | POST
  | PUT
  | DELETE

(**
   OAuth user status
 *)
type oAuthUserStatus =
  | LoggedOut (** Logged out *)
  | Code of string (** Code to be exchanged for an Access Token *)
  | Token of (string * int) (** Access Token with an expiration timestamp set *)

(**
   API definition type
 
   api_login_url string URL where the user will be redirected for login
   api_token_url string URL where the OAuth access token will be retrieved
   api_base_url string OAuth API base URL, for more simple API calls
   oauth_version oAuthVersion OAuth version used by API
 *)
type oAuthAPI = { 
  api_login_url : string;
  api_token_url : string;
  api_base_url : string;
  oauth_version : oAuthVersion;
}

(**
   OAuth API Permission
 *)
type oAuthPermission = (string)

class oAuthUser = fun ?(status = LoggedOut) ?(permissions = [""]) () ->
object (this)
    val mutable status = status
    val mutable permissions = permissions

    (**
       Get user's status

       @return oAuthUserStatus
     *)
    method getStatus () = status

    (**
       Get user's permissions

       @return (oAuthPermission) list
     *)
    method getPermissions () = permissions

    (**
       Set user's OAuth code

       @param code OAuth Code
       @return err?
     *)
    method setCode code = status <- Code (code)

    (**
       Set user's access token

       @param token OAuth Access Token
       @param int Access Token expiration timestamp
       @return err?
     *)
    method setToken token expires = status <-  Token (token, expires)

    (**
       Mark user as logged out

       @return err?
     *)
    method setLoggedOut () = status <- LoggedOut

    (**
       Set user's status

       @param new_status User new status
       @return err?
     *)
    method setStatus new_status = status <- new_status
end

class oAuthClient =
  fun endpoint
    (id : string)
    (secret : string)
    ?(identifier = "")
    ?(state = "")
    () ->

  object (this)
      val id = id
      val secret = secret
      val endpoint = endpoint
      val identifier = identifier
      val user = new oAuthUser ()

      val mutable state = state

      (**
         Generate a md5 from a random int

         @return string
       *)
      method random_token () = Digest.to_hex (
        Digest.string (
          Int32.to_string (
            Random.int32 (
              Int32.max_int))))

      (**
         Find an element in a key * value list

         @param needle element to be found
         @param l (string * string) list l
         @raise Failure Fails when key not found
         @return string
       *)
      method findParam needle l = match List.hd l with
      | (name, value) when ((String.compare name needle) == 0) -> name
      | _ -> this#findParam needle (List.tl l)

      (**
         Get user

         @return oAuthUser
       *)
      method getUser () = user

      (**
         Get identifier

         @return string
       *)
      method getIdentifier () = identifier

      (**
         Return current state (csrf unique token)
         Generate one if not found

         @return string
       *)
      method getState () =
          if ((String.length state) == 0) then 
            state <- this#random_token ();
          state

      (**
         Get a login URL for OAuth API.

         @param oAuthPermission list scope
         @param string redirect_url
         @return string
       *)
      method getLoginUrl scope redirect_url = endpoint.api_login_url ^ "?" ^
          Netencoding.Url.mk_url_encoded_parameters [
              ("client_id",  id) ;
              ("redirect_uri",  redirect_url) ;
              ("scope", (String.concat " " scope)) ;
              ("state",  (this#getState ())) ;
          ]

      (**
         Get access token for current user, if user is not logged returns
         application Access Token

         @return string
       *)
      method getAccessToken () = match user#getStatus () with
          | Token (token, _) -> token
          | _ -> id ^ "|" ^ secret

      (**
         Get an URL to exchange code to a token.

         @param oAuthPermission list scope
         @param string redirect_url
       *)
      method getAccessTokenUrl redirect_url () = 
          match user#getStatus () with
          | Code (code) ->
              endpoint.api_token_url ^ "?" ^
                  Netencoding.Url.mk_url_encoded_parameters [
                      ("client_id", id);
                      ("client_secret", secret);
                      ("redirect_uri",  redirect_url) ;
                      ("code", code);
                  ]
          | Token (_, _) -> raise (Failure "User is already logged")
          | _ -> raise (Failure "No code provided")

      (**
         Exchange a code for an access token 

         @return unit
       *)
      method exchangeCode () =
          let url = this#getAccessTokenUrl "http://TODO.fr" () in
          let response = http_post_message url [] in
          match response#response_status_code with
          | 200 -> 
              let resp_list = Netencoding.Url.dest_url_encoded_parameters
                (response#get_resp_body ()) in
              let token = this#findParam 
                "access_token" resp_list in
              let expires = int_of_string 
                (this#findParam "expires" resp_list) in
              user#setToken token expires
          | _ -> raise (OAuthException (400, "Failure on HTTP query"))

      (**
        Do an API call
        @todo
       *)
      method api
        (action : string)
        ?(http_method = GET)
        ?(http_params = [("", "")])
        ?(http_content = "")
        () =
        ()

  end

(*
   OAUTH ENDPOINT EXAMPLES
 *)

let facebook_api_endpoint = {
  api_login_url = "https://www.facebook.com/dialog/oauth";
  api_token_url = "https://graph.facebook.com/oauth/access_token";
  api_base_url = "https://graph.facebook.com/";
  oauth_version = OAUTH_2;
}

let google_api_endpoint = {
  api_login_url = "https://accounts.google.com/o/oauth2/auth";
  api_token_url = "https://accounts.google.com/o/oauth2/token";
  api_base_url = "https://www.googleapis.com/oauth2/v1/";
  oauth_version = OAUTH_2;
}