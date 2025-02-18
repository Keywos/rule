/* @key 2023-08-03 17:13:58
[rewrite_local]
^https:\/\/biz\.cyapi\.cn(\/p)?\/v\d\/(user\?app_name=weather|user_info|visitors|login_by_code)$ url script-response-body caiyun.js

^https?:\/\/wrapper\.cyapi\.cn\/v\d\/activity\? url reject-dict
^https?:\/\/api\.caiyunapp\.com\/v\d\/activity\? url reject-dict

[mitm]
hostname = biz.cyapi.cn
*/
let url = $request.url;
(!$response.body) && $done({});
let b = JSON.parse($response.body);
let names = "Hello" // Your Name
let exp = 4102336922;
let jpg = "https://raw.githubusercontent.com/Midnight0716/Qx/main/1.jpg" // Your icon
let Tokens = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZXJzaW9uIjoxLCJ1c2VyX2lkIjoiNWY1YmZjNTdkMmM2ODkwMDE0ZTI2YmI4Iiwic3ZpcF9leHBpcmVkX2F0IjoxNzA1MzMxMTY2LjQxNjc3MSwidmlwX2V4cGlyZWRfYXQiOjB9.h_Cem89QarTXxVX9Z_Wt-Mak6ZHAjAJqgv3hEY6wpps";

switch (true) {
  case /user\?app_name=weather/.test(url): // Pro v6.8.0
  let x = b.result;
      x.token = Tokens;
      x.name = names;
      x.svip_given = 730;
      x.phone_num = "52000001314";
      x.svip_expired_at = exp;
      x.vip_expired_at = exp;
      x.xy_svip_expire = exp;
      x.xy_vip_expire = exp;
      x.bound_status.weixin.username = "123152";
      x.bound_status.qq.username = "123153";
      x.avatar = jpg;
      if (x.wt) {
        if (x.wt.vip) {
          x.wt.vip.enabled = true;
          x.wt.vip.expired_at = exp;
          x.wt.vip.svip_expired_at = exp;
        }
        x.wt.svip_given = 730;
      }
    break;
  case /\/p\/v\d\/user_info/.test(url): // Pro v7.0.0
      b.name = names;
      b.gender = 0;
      b.reg_days = "9999";
      b.birthday = "1921-01-23";
      b.city = "";
      b.industry = "";
      b.interests = [""];
      b.avatar = jpg;
    break;
  case /\/login_by_code/.test(url):
      b = {
      "status": "ok",
      "result": {
        "is_phone_verified": true,
        "token": Tokens
      },
      "rc": 0
      }
    break;
  default:
  break;
}
$done({ body: JSON.stringify(b) })