open Oauth
open Oauth_endpoints
open Test_callbacks
open Yojson.Basic.Util

let redirect_url = "https://localhost.ohai.fr/"

let apis = [
  (make_api_client "api_id" "api_key" instagram_oauth_endpoint (), ["likes"], instagram_test);
  (make_api_client "api_id" "api_key" microsoft_oauth_endpoint (), ["wl.basic"], ms_test);
  (make_api_client "api_id" "api_key" meetup_oauth_endpoint (), [], meetup_test);
  (make_api_client "api_id" "api_key" facebook_oauth_endpoint (), [], facebook_test);
  (make_api_client "api_id" "api_key" github_oauth_endpoint (), [], github_test);
  (make_api_client "api_id" "api_key" foursquare_oauth_endpoint (), [], foursquare_test);
  (make_api_client "api_id" "api_key" google_oauth_endpoint (), ["https://www.googleapis.com/auth/userinfo.profile"], google_test);
]

let get_api_client (api_client, _, _) = api_client
let get_scope (_, scope, _) = scope
let get_func (_, _, func) = func

(*
  Prints the api login URL
  ask for code
  set code
  display username
*)

let api_test api_and_fun = 
  let test_fun = get_func api_and_fun in
  let api_client = get_api_client api_and_fun in
  let api_user = make_api_user api_client ~permissions: (get_scope api_and_fun) () in
  (print_endline ("Testing API " ^ api_user.api_client.endpoint.identifier);
  print_endline (login_url api_user redirect_url);
  print_endline "Type issued code:";
  let code = Code (read_line ()) in
  let coded_user = set_user_status api_user (code) in
  let authed_user = exchange_code_for_access_token coded_user redirect_url () in
  let name = test_fun authed_user in
  print_endline name)

let _ = List.iter api_test apis
