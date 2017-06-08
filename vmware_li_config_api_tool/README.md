# vRealize Log Insight Configuration Management and Automation Tool

This Python code helps manage VMware's vRealize Log Insight (vRLI) by referencing a JSON configuration file and allows you to:
1. Deploy new single node or multi-node vRLI clusters
2. Add additional nodes to expand an existing vRLI deployment
3. Configure many vRLI settings such as NTP, Event Forwarding, Agent Group configurations, etc...
4. Run in audit only mode or automatically remediate deviations from the defined standard

All this takes place over https using the [Log Insight Configuration APIs.]https://vmw-loginsight.github.io/#Deployment-API. My
personal recommendation is that you store your configuration files securely in source control and schedule this to check for unauthorized
changes and configuration drift on a frequent basis.

An example screenshot showing a new deployment, adding 2 additional nodes to the new cluster and configuring settings:
![Screenshot](https://4.bp.blogspot.com/-4YKeiWbtCTc/WTmSIi-hA8I/AAAAAAAACZk/xNEu7XBMCaQXRlIry00exqRZ4fAM-wPIgCLcB/s1600/2017-06-08%2B12_05_39-Fedora%2B25%2B-%2BVMware%2BKVM.png)

This code should work with both Python 2 and 3 and is free and open source under Apache 2.0.

An overview is available in the below blog post.
http://calebs71.blogspot.com/2017/06/deploying-vrealize-log-insight-vrli-via.html

This code is not supported, released or related to VMware in any way and comes with absolutely no guarentees. If you find a bug
please shoot me an email or feel free to contribute your own code!
