(*

Copyright (c) 2012, Guillaume Louvigny
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Guillaume Louvigny, nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL GUILLAUME LOUVIGNY BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


   Required libs > Ocamlnet : Netencoding.Url
                 > Ocamlnet : HttpClient
                 > equeue-ssl
                 > YoJson
 *)

(**
  Mono threaded OAuth 2 client for OCaml

  Only Bearer is supported
 *)

open Https_client (* needed as OAuth 2.0 requires HTTPS *)
open Http_client
open Http_client.Convenience
open Yojson.Basic.Util

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
  | OAUTH_2_D10

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
  | Token of (string * int) (** Access Token with an expiration timestamp set*)

(**
   OAuth API Permission
 *)

type oAuthPermission = (string)

(**
   API endpoints
 
   api_login_url string URL where the user will be redirected for login
   api_token_url string URL where the OAuth access token will be retrieved
   api_base_url string OAuth API base URL, for more simple API calls
   oauth_version oAuthVersion OAuth version used by API
 *)
type oAuthEndpoint = { 
  api_login_url : string;
  api_token_url : string;
  api_base_url : string;
  auth_function : (string -> oAuthUserStatus);
  oauth_version : oAuthVersion;
  identifier : string;
  addon_login_param : (oAuthUser -> (string * string) list -> (string * string) list);
  addon_token_param : (oAuthUser -> (string * string) list -> (string * string) list);
  addon_apicall_param : (oAuthUser -> (string * string) list -> (string * string) list);
} and oAuthClient = {
  id : string;
  secret : string;
  state : string;
  endpoint : oAuthEndpoint;
} and oAuthUser = {
  status : oAuthUserStatus;
  permissions : oAuthPermission list;
  api_client : oAuthClient;
}

(**
   Generate a md5 from a random int

   @return string
*)
let random_token () = Digest.to_hex (
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
let rec find_param needle l = match List.hd l with
  | (name, value) when ((String.compare name needle) == 0) -> value
  | _ -> find_param needle (List.tl l)

(**
   Set user's status

   @param oauth_user User to change status
   @param new_status User new status
*)
let set_user_status oauth_user new_status = {
  status = new_status;
  permissions = oauth_user.permissions;
  api_client = oauth_user.api_client;
}

(**
   Get a login URL for OAuth API.

   @param oAuthPermission list scope
   @param string redirect_url
   @return string
*)
let login_url api_user redirect_url = api_user.api_client.endpoint.api_login_url ^ "?" ^
  Netencoding.Url.mk_url_encoded_parameters [
    ("client_id",  api_user.api_client.id) ;
    ("redirect_uri",  redirect_url) ;
    ("scope", String.concat " " api_user.permissions) ;
    ("response_type", "code") ;
    ("state",  api_user.api_client.state) ;
  ]

(**
   Get access token for current user, if user is not logged returns
   application Access Token

   @return string
*)
let api_access_token api_client = api_client.id ^ "|" ^ api_client.secret

(**
   Params to exchange code to a token.

   @param oAuthPermission list scope
   @param string redirect_url
*)
let access_token_params api_client redirect_url code = 
  [
    ("client_id", api_client.id) ;
    ("client_secret", api_client.secret) ;
    ("redirect_uri",  redirect_url) ;
    ("grant_type", "authorization_code") ;
    ("code", code) ;
  ]

(**
   Exchange a code for an access token
   Uses jsonEncodedTokenAccess as default response parser (OAuth 2 d. 26)

   @return unit
*)
let exchange_code_for_access_token
    user
    redirect_url
    () =
  let response_parse = user.api_client.endpoint.auth_function in
  match user.status with
    | Code (code) ->
      let params =  user.api_client.endpoint.addon_token_param user (access_token_params user.api_client redirect_url code) in
      let response = http_post_message user.api_client.endpoint.api_token_url params in
      (match response#response_status_code with
	| x when (x < 400) -> set_user_status user (response_parse (response#get_resp_body ()))
	| _ -> raise (OAuthException (400, ("Failure on HTTP request:" ^ (response#get_resp_body ())))))
    | _ -> raise (OAuthException (400, "User has no code"))
	  
(**
   Appends params to url (for GET, PUT, DELETE)

   @return string
*)
let params_to_url url params =
  url ^ "?" ^ Netencoding.Url.mk_url_encoded_parameters params

(**
   Do an API call
   @todo
*)
let api
    user
    action
    ?(http_method = GET)
    ?(http_params = [])
    ?(http_content = "")
    () =
  let access_token = match user.status with
    | Token (token, expires) -> token
    | _ -> api_access_token user.api_client in
  let http_params = (* appends access token to parameters *)
    user.api_client.endpoint.addon_apicall_param user (http_params@
      [
	("access_token", access_token);
      ]) in
  let http_url =  (* check if a full URL is given *)
    if Str.string_match (Str.regexp "^https?://") action 0 then
      action
    else
      user.api_client.endpoint.api_base_url ^ action
  in
  let http_response = match http_method with
    | GET -> 
      print_endline (params_to_url http_url http_params);
      http_get_message (params_to_url http_url http_params)
    | POST -> http_post_message http_url http_params
    | PUT -> http_put_message
      (params_to_url http_url http_params) http_content
    | DELETE -> http_delete_message
      (params_to_url http_url http_params)
  in
  match http_response#response_status_code with
    | 200 -> http_response#get_resp_body ()
    | _ -> raise (OAuthException (400, "Failure on HTTP request"))


let make_api_client id secret endpoint ?(state = (random_token ())) () =
  {
    id = id;
    secret = secret;
    state = state;
    endpoint = endpoint;
  }

let make_api_user api_client ?(status = LoggedOut) ?(permissions = []) () = 
  {
    status = status;
    permissions = permissions;
    api_client = api_client;
  }
