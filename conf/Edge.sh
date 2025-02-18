#!/bin/bash
#说明：macos自动打开edge禁用 bing ai图标 不能自动退出用iterm2即可 需要给予权限 chmod +x Edge.sh
open -n -a "Microsoft Edge" --args --disable-features=msEdgeSidebarV2
exit