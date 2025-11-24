# Cloudflore Workers Vless

自用版本不保证时效性，目前稳定。

workers.js 文件中的代码复制，部署到workers中，设置变量绑定自己的域名，就这么简单。

## `变量设置`

| `变量` | `示例` | `说明` |
| --- | --- | --- | 
|`PASSWD`  | `123456`  |  访问密码，随意胡编乱造即可|
|`SUB_PATH`| `subpath` 不设置默认使用 UUID |订阅地址路径，随意胡编乱造即可  |
| `PROXYIP` | [点击获取](https://github.com/qwer-search/bestip/blob/main/kejilandbestip.txt?_blank) 也可自建,转发一个端口到任意 cf ip的443端口 |  代理IP，用于访问套了CF的站点|
|`UUID`  | `5zz1x235-1195-41pd-953v-0aafbd917b63` |生成或者符合格式的胡编乱造  |
| `WS_PATH` | `/123456` | ws路径，随意胡编乱造即可 |



基于 <a href="[佬王仓库](https://github.com/eooce/Cloudflare-proxy)" target="_blank"></a> 修改，只修改了VLESS 感谢大佬无私！

