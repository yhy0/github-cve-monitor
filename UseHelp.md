# 推送设置

## 钉钉

1.   建立群聊（可以单人建群）

2.   智能群助手添加自定义机器人

​			选择加签

![image-20211118142412234](images/image-20211118142412234.png)

建立机器人，之后在`config.yaml`中配置，将webhook和秘钥secretKey填入对应的字段，`enable`设置为`1`表示使用该通知

效果：

<img src="images/image-20211118145021974.png" style="zoom:70%"/>

##  飞书捷径推送

@[sodmelody](https://github.com/sodmelody) 添加

>   飞书工作台  - 飞书捷径 -webhook

![image](https://user-images.githubusercontent.com/29257678/136410980-302be028-3817-447c-9bad-e3d63045060d.png)

注意参数这里：

添加下列json信息

```php
{"at":{},"msgtype":"text","text":{"content":"有新的CVE送达！\r\nCVE编号：CVE-2021-41773\r\nGithub地址：https://github.com/iilegacyyii/PoC-CVE-2021-41773\r\nCVE描述：\r\n在Apache HTTP Server 2.4.49的路径规范化更改中发现了一个缺陷。攻击者可以使用路径遍历攻击将url映射到预期文档根之外的文件。如果文档根目录之外的文件没有被“require all denied”保护，这些请求就可以成功。此外，这个缺陷可能会泄露解释文件(如CGI脚本)的源代码。众所周知，这个问题是在野外被利用的。此问题仅影响Apache 2.4.49，不影响Apache 2.4.49之前的版本。"}}
```

<img src="https://user-images.githubusercontent.com/29257678/136413189-f393dfa2-4874-4fea-b8be-7b5892d65fcf.png" style="zoom:20%"/>

<img src="https://user-images.githubusercontent.com/29257678/136411286-99c2e4db-0d8a-4b61-8613-96e3ebad8e44.png" style="zoom:25%"/>

>   选择json里面的模块

<img src="https://user-images.githubusercontent.com/29257678/136413413-48417c13-285d-47ff-9fba-c78bed592430.png" style="zoom:30%"/>

`config.yaml`中配置`feishu`的`webhook`,`enable`设置为 `1`表示推送

效果：

![image](https://user-images.githubusercontent.com/29257678/136413553-48c2100b-8f2d-4f81-8b8b-74351bde0456.png)

## Telegram Bot推送支持

@[atsud0](https://github.com/atsud0) 师傅添加了 Telegram 推送

安装telegram bot

```
pip install python-telegram-bot
```

生成bot 获得群组或用户聊天ID

创建bot详情谷歌

### 获得ID

将bot加入群组后，发送几条消息。访问https://api.telegram.org/bot{TOKEN}/getUpdates

用户ID同理，

![image-20210225090416314](images/124256679-27701e00-db5e-11eb-9432-d3a9048daeec.png)

`config.yaml`中配置`tgbot`的`token`等信息,`enable`设置为 `1`表示推送



## Server 酱

ps：因微信的原因，server酱的旧版将在2021年4月后下线，新版以企业微信为主，这里使用的是旧版，想改新版的话，搞个企业微信，从新配置server酱，使用新链接 sctapi.ftqq.com

具体查看server酱官方，http://sc.ftqq.com/ ，配置简单，只需要将脚本中的uri换掉即可

[server酱新版](https://sct.ftqq.com/)支持多通道（微信、客户端、群机器人、邮件和短信）

`config.yaml`中配置`server`的`token`等信息,`enable`设置为 `1`表示推送

## 推送加【Mac 版微信可用】

免费的微信模板消息通知，支持在 Mac 版微信查看

### Mac微信效果

![image-20220126110109185](images/image-20220126110109185.png)

具体配置方法见 pushplus 公众号文章：https://mp.weixin.qq.com/s/YRYb04PUFNVZejzV2G-k4w

同时也支持使用企业微信应用通知，只需从 API 接口修改默认配置即可：

![image-20220126105710922](images/image-20220126105710922.png)

修改成功：

![image-20220126110312664](images/image-20220126110312664.png)

### 企业微信应用效果

![image-20220126110919827](images/image-20220126110919827.png)

# Github 访问限制

监控工具更新 请求次数过多，超过了每小时请求，添加gihtub token

>   对于未经身份验证的请求，github 速率限制允许每小时最多 60 个请求
>
>   而通过使用基本身份验证的 API 请求，每小时最多可以发出 5,000 个请求
>
>   https://github.com/settings/tokens/new 创建token，时间的话选无限制的，毕竟要一直跑![image-20210729172507519](images/image-20210729172507519.png)

`config.yaml`中配置github_token

