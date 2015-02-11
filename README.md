# anomalia-reputation-api
###### anomalia is a plugin for nfsen that detects anomalies in TCP connections based on the flow analysis and send to reputation-api endpoint

Introduction
------------

If you do not know the reputation-api, read more about it [here](https://github.com/mdjunior/reputation-api)


Instalation
-----------

To install the plugin, you need a you add Perl libraries.
* LWP::UserAgent
* JSON

If you use Debian or Ubuntu, you can install them with the command:

	apt-get install liblwp-useragent-determined-perl libjson-perl


Setting nfsen plugin
--------------------

In `/etc/nfsen.conf` (the localization may be different depending on your installation)

Insert in `@plugins` the line: `['live', 'anomaly'],`

It should look like this:

	@plugins = (
    	[ 'live',  'PortTracker' ], 
    	[ 'live',  'Anomaly' ],
	);

You should also make additional settings. These settings are used to tell the plugin where is the endpoint of the reputation-api, from which limit the plugin should send an event to the API, and where the plugin will read the main source ports (these values were placed in a file for easier manipulation). To do this, you must include the following line in `%PluginConf`.

	Anomaly => {
		reputation_api_endpoint => "http://localhost:8081/api/ip",
		ports_file => "$BACKEND_PLUGINDIR/anomaly_ports.txt",
		threshold => 5,
	},


Setting reputation-api for plugin
---------------------------------

The plugin sends the information found to the configured endpoint, using the following categories:
* NETFLOW.SYN_CLOSED
* NETFLOW.SYN
* NETFLOW.UDP
* NETFLOW.NULL


Therefore you should configure these categories in reputation-api. The following instructions shows an insertion example in the database for the categories used with a discount tax of 1%

	INSERT INTO `reputation`.`category` (`category`, `tax`) VALUES ('NETFLOW.SYN_CLOSED', '0.9900');
	INSERT INTO `reputation`.`category` (`category`, `tax`) VALUES ('NETFLOW.SYN', '0.9900');
	INSERT INTO `reputation`.`category` (`category`, `tax`) VALUES ('NETFLOW.UDP', '0.9900');
	INSERT INTO `reputation`.`category` (`category`, `tax`) VALUES ('NETFLOW.NULL', '0.99');


Use
---

To complete the process, you must reload the nfsen.

	service nfsen reload

Go to the tab of the plugin, you should see the configuration information, as in the following example:

	Anomaly to reputation::api

	For more information about this plugin and how it works go to https://github.com/mdjunior/anomalia-reputation-api


	Backend status: running...
	Reputation::api Endpoint: http://10.0.2.2:8081/api/ip
	Ports File: /data/nfsen/plugins/anomaly_ports.txt
	Threshold config: 10


