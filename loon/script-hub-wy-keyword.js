// 转换时间: 2023/12/22 19:44:48 for script-hub
function strToArray(str) {
  var ret = new Uint8Array(str.length)
  for (var i = 0; i < str.length; i++) {
    ret[i] = str.charCodeAt(i)
  }
  return ret
}

let done = $done
let result = {
  response: {
      status: 200,
      body: strToArray("ÜÅ+0\u0013é¶l\u0003\u0002~X\u000eÎ\u0019íÐ\"I¨\u0000I ÒU]Þ¯m}ÊK Z.ÕÈUw[dd£³\u0005\u0017¼K<÷ß\t¶Þ§\u0003|¯ö`gÖ\u000eôâtãK¨\u0013I A\u001fÓ\u0013kz|!\u000f ¢ªû\u0017îd\f+¦\u000fÑ%Ë[ÿ&y]\u0000Îø¤è\núÇ«}óâNKÚb\u0016ÙÛ]\u001aãW^\u0003¤«º\b\nLU®c/'\u001aê|Çk\u001c\nÍ\u000bÏã\"Dz'mäk0#6\u001aßHY2ÿ*\u0012¹_÷åâ¶=ÙJÏÔU½7\u0010\núa+£í=ó\u0003Öd\u0007\tTè\u001f`Íñ;ÅÔY\u0019o j³Næd\\xåä\u001aNù\b\u0010ñâ)W¼\u00062zíKVÎÚd\u0017x\\É«CÍË;°ÏùúZÿ)ôØý{Ö-òÜ¯ G\b¸niËî|ðAÂÃ¿Ä\u001c5Àð\u0001w¦ôÑDðy\r/ {èò=\u001cB4\\\u0001Fä!º\u0003´ka\\]álJ\\ÒïMPawÍÎ"),
    },
}
done(result)