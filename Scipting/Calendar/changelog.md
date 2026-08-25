#更新记录

### V 2.2.0

- 中组件新增 显示所有 提醒事项, 设置里可以修改

### V 2.2.0

- medium 尺寸组件新增左右分栏：左半边简约风格（今日日期+农历+本月节假日列表，连续日期合并为区间如 1-7日），右半边复用小组件月历布局
- 节假日数据改为统一走 holidayUtils 缓存（按年缓存 + 一天过期自动重拉），widget 不再每次直接查询 CalendarEvent.getAll
- 缓存同时记录“休/班”标记、节日名称（如“国庆节”“中秋节”）和节假日历颜色，周/月/大月组件全部从缓存读取

### V 2.0.0

- 优化小组件显示效果
- 点击中间区域可以打开系统日历 APP

>改自 Scripting 作者: https://scripting.fun/import_scripts?urls=%5B%22https%3A%2F%2Fgithub.com%2FScriptingApp%2FCommunity-Scripts%2Fraw%2Frefs%2Fheads%2Fmain%2FHealth%2520Center.scripting%22%5D