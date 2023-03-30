1-pcap_csv内的脚本可以将pcap文件提取特征、并存储到csv文件。
运行逻辑是：先执行pcap_json.py，使用[Joy](https://github.com/cisco/joy "Joy")将pcap文件提取TLS特征，存为json文件。接着执行json_csv，将json中的特征进一步提取，存入csv。
不要直接运行，每个文件打开看一下，把里面的pcap、json、csv文件路径和joy的路径改一改。

2-train_test内的脚本可以训练随机森林分类器，并进行测试。

思路可以见[这篇blog](https://www.mmuaa.com/post/5f7dc86aa4abbfc0.html "这篇blog")，刚入门流量安全的时候写的。
没有在真实场景中测试过，怀疑会产生大量误报，而且存在严重的概念漂移问题。
代码两年半~~(警觉)~~前乱糊的，小学生水平，不过博主实在太懒，能跑起来就行- -。。恳请各位大神轻喷。