open Oauth
open Yojson.Basic.Util
(*
   OAUTH ENDPOINT EXAMPLES
 *)

(**
   Parse an access token stored in a JSON object.
   User object is not modified as external methods may be used.

   @return Token (string, int)
*)
let decode_json_token_access data = 
  let json = Yojson.Basic.from_string data in
  let access_token = 
    List.hd ([json]
		|> filter_member "access_token"
		|> filter_string
    ) in
  let expires = 
    try
      List.hd ([json]
		  |> filter_member "expires_in"
		  |> filter_number
    ) 
    with
	_ -> 0.0 in
  Token (access_token, int_of_float expires)


(**
   Parse an access token stored in an URL encoded-style answer.
   User object is not modified as external methods may be used.
   This is mainly intended to be used with Facebook, which doesn't follow
   recent OAuth 2 RFC.

   @return Token (string, int)
*)
let decode_url_encoded_access_token data = 
  print_endline data;
  let resp_list = Netencoding.Url.dest_url_encoded_parameters
    data in
  let token = find_param "access_token" resp_list in
  let expires =
    try
      int_of_string (find_param "expires" resp_list)
    with
      | _ -> 0 in
  Token (token, expires)


let add_nothing user params = params

let foursquare_api_addon user params = match user.status with
  | Token (token, _) -> params@[("oauth_token", token)]
  | _ -> raise (Failure "User not logged in")

let deezer_auth_addon user params = params@[("app_id", user.api_client.id)]

(*
("oauth_token", access_token); (* silly hack to support foursquare*)
*)

(* 
   Register your Facebook app at
   https://developers.facebook.com/apps
*)
let facebook_oauth_endpoint = {
  api_login_url = "https://www.facebook.com/dialog/oauth";
  api_token_url = "https://graph.facebook.com/oauth/access_token";
  api_base_url = "https://graph.facebook.com/";
  auth_function = decode_url_encoded_access_token;
  oauth_version = OAUTH_2_D10;
  identifier = "facebook";
  addon_login_param = add_nothing;
  addon_token_param = add_nothing;
  addon_apicall_param = add_nothing;
}

(*
  Register your Google app at
  https://code.google.com/apis/console/
*)
let google_oauth_endpoint = {
  api_login_url = "https://accounts.google.com/o/oauth2/auth";
  api_token_url = "https://accounts.google.com/o/oauth2/token";
  api_base_url = "https://www.googleapis.com/oauth2/v1/";
  auth_function = decode_json_token_access;
  oauth_version = OAUTH_2_D10;
  identifier = "google";
  addon_login_param = add_nothing;
  addon_token_param = add_nothing;
  addon_apicall_param = add_nothing;
}

(*
  Register your Github app at
  https://github.com/settings/applications/new
*)
let github_oauth_endpoint = {
  api_login_url = "https://github.com/login/oauth/authorize";
  api_token_url = "https://github.com/login/oauth/access_token";
  api_base_url = "https://api.github.com/";
  auth_function = decode_url_encoded_access_token;
  oauth_version = OAUTH_2_D10;
  identifier = "github";
  addon_login_param = add_nothing;
  addon_token_param = add_nothing;
  addon_apicall_param = add_nothing;
}

(*
  Register your foursquare app at
  https://foursquare.com/oauth/register
*)
let foursquare_oauth_endpoint = {
  api_login_url = "https://foursquare.com/oauth2/authenticate";
  api_token_url = "https://foursquare.com/oauth2/access_token";
  api_base_url = "https://api.foursquare.com/v2/";
  auth_function = decode_json_token_access;
  oauth_version = OAUTH_2_D10;
  identifier = "foursquare";
  addon_login_param = foursquare_api_addon;
  addon_token_param = add_nothing;
  addon_apicall_param = add_nothing;
}

(*
  Endpoints below are not tested yet
*)

(*
  Register your Meetup app at
  http://www.meetup.com/meetup_api/oauth_consumers/create/
*)
let meetup_oauth_endpoint = {
  api_login_url = "https://secure.meetup.com/oauth2/authorize";
  api_token_url = "https://secure.meetup.com/oauth2/access";
  api_base_url = "https://api.meetup.com/";
  auth_function = decode_json_token_access;
  oauth_version = OAUTH_2_D10;
  identifier = "meetup";
  addon_login_param = add_nothing;
  addon_token_param = add_nothing;
  addon_apicall_param = add_nothing;
}

(*
  Register your Live app at
  https://manage.dev.live.com/AddApplication.aspx
*)
let microsoft_oauth_endpoint = {
  api_login_url = "https://login.live.com/oauth20_authorize.srf";
  api_token_url = "https://login.live.com/oauth20_token.srf";
  api_base_url = "httpS://apis.live.net/v5.0/";
  auth_function = decode_json_token_access;
  oauth_version = OAUTH_2_D10;
  identifier = "microsoft";
  addon_login_param = add_nothing;
  addon_token_param = add_nothing;
  addon_apicall_param = add_nothing;
}

(*
  Register your Instagram app at
  
*)
let instagram_oauth_endpoint = {
  api_login_url = "https://api.instagram.com/oauth/authorize/";
  api_token_url = "https://api.instagram.com/oauth/access_token";
  api_base_url = "https://api.instagram.com/";
  auth_function = decode_json_token_access;
  oauth_version = OAUTH_2_D10;
  identifier = "instagram";
  addon_login_param = add_nothing;
  addon_token_param = add_nothing;
  addon_apicall_param = add_nothing;
}

(*
  Register your Deezer app at
  
*)
let deezer_oauth_endpoint = {
  api_login_url = "https://connect.deezer.com/oauth/auth.php";
  api_token_url = "https://connect.deezer.com/oauth/access_token.php";
  api_base_url = "https://api.deezer.com/2.0/";
  auth_function = decode_url_encoded_access_token;
  oauth_version = OAUTH_2_D10;
  identifier = "deezer";
  addon_login_param = deezer_auth_addon;
  addon_token_param = deezer_auth_addon;
  addon_apicall_param = add_nothing;
}
