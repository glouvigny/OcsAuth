open Yojson.Basic.Util
open Oauth

(*
  Each api exposes resources that aren't at the same location (eg. userinfo vs me)
  and not formatted the same way.
*)

let google_test authed_user =   
  let api_ret = api authed_user "userinfo" () in
  let json = Yojson.Basic.from_string api_ret in
  List.hd
    ([json]
	|> filter_member "name"
	|> filter_string)


let facebook_test authed_user =
  let api_ret = api authed_user "me" () in
  let json = Yojson.Basic.from_string api_ret in
  List.hd
    ([json]
	|> filter_member "name"
	|> filter_string)

let github_test authed_user =
  let api_ret = api authed_user "user" () in
  let json = Yojson.Basic.from_string api_ret in
  List.hd
    ([json]
	|> filter_member "name"
	|> filter_string)

let ms_test authed_user =
  let api_ret = api authed_user "me" () in
  let json = Yojson.Basic.from_string api_ret in
  List.hd
    ([json]
	|> filter_member "name"
	|> filter_string)

let meetup_test authed_user =
  let api_ret = api authed_user "2/member/self" () in
  let json = Yojson.Basic.from_string api_ret in
  List.hd
    ([json]
	|> filter_member "name"
	|> filter_string)

let instagram_test authed_user =
  let api_ret = api authed_user "v1/users/self" () in
  let json = Yojson.Basic.from_string api_ret in
  List.hd
    ([json]
	|> filter_member "data"
	|> filter_member "username"
	|> filter_string)


let deezer_test authed_user =
  let api_ret = api authed_user "me" () in
  let json = Yojson.Basic.from_string api_ret in
  List.hd
    ([json]
	|> filter_member "name"
	|> filter_string)


let foursquare_test authed_user =
  let api_ret = api authed_user "users/self" () in
  let json = Yojson.Basic.from_string api_ret in
  List.hd
    ([json]
	|> filter_member "response"
	|> filter_member "user"
	|> filter_member "username"
	|> filter_string)

