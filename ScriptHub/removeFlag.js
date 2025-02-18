# 去掉订阅中的国旗
body = body.replace(/([^\n]|\|)?[\uD83C][\uDDE6-\uDDFF][\uD83C][\uDDE6-\uDDFF](?:\s|$)/g,'').replace(/\丨/g,' ')