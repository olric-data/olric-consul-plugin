# olric-consul-plugin

This package implements `ServiceDiscovery` interface of Olric and uses Consul at background. With this plugin, you don't need
to maintain a static list of alive peers in the cluster. 

## Install

Get the code:

```
go get -u github.com/olric-data/olric-consul-plugin
```

## Usage

### Load as compiled plugin

#### Build

With a properly configured Go environment:

```
go build -buildmode=plugin -o consul.so 
```

If you want to strip debug symbols from the produced binary, add `-ldflags="-s -w"` to `build` command.


If you prefer to deploy Olric in client-server scenario, add a `serviceDiscovery` block to your `olricd.yaml`. A sample:

```yaml

serviceDiscovery:
  provider: "consul"
  path: "YOUR_PLUGIN_PATH/consul.so"
  address: "http://127.0.0.1:8500"
  passingOnly: true
  replaceExistingChecks: false
  insecureSkipVerify: true
  payload: '
      {
          "Name": "olric-cluster",
          "ID": "olric-node-1",
          "Tags": [
            "primary",
            "v1"
          ],
          "Address": "localhost",
          "Port": MEMBERLIST_PORT,
          "EnableTagOverride": false,
          "check": {
            "name": "Olric node on MEMBERLIST_PORT",
            "tcp": "0.0.0.0:MEMBERLIST_PORT",
            "interval": "10s",
            "timeout": "1s"
          }
      }
'
```

In embedded member deployment scenario:

```go
// import config package
"github.com/olric-data/olric/config"

// Get a new Olric config for local environment
c := config.New("local")

// Set service discovery definition
sd := make(map[string]interface{})
sd["provider"] = "consul"
sd["path"] = "YOUR_PLUGIN_PATH/consul.so"
sd["address"] = "http://127.0.0.1:8500"
sd["passingOnly"] = true
sd["payload"] = `{
  "Name": "olric-cluster",
  "ID": "olric-node-1",
  "Tags": [
    "primary",
    "v1"
  ],
  "Address": "localhost",
  "Port": MEMBERLIST_PORT,
  "EnableTagOverride": false,
  "check": {
    "name": "Check Olric node on MEMBERLIST_PORT",
    "tcp": "0.0.0.0:MEMBERLIST_PORT",
    "interval": "1s",
    "timeout": "1s"
  }
}`

c.ServiceDiscovery = sd
```

### Import directly as a library

You can load the plugin directly as a library:

```go
import (
    olricconsul "github.com/olric-data/olric-consul-plugin/lib"
)

//...
sd := make(map[string]interface{})
sd["plugin"] = &olricconsul.ConsulDiscovery{}
//...
```

## Configuration

This plugin has very few configuration parameters: 

| Parameter | Description |
| --------- | ----------- |
| provider    | Name of the service discovery daemon. It's Consul. Just informal |
| path        | Absolute path of the compiled plugin |
| plugin      | Pointer to imported plugin |  
| address     | Network address of the service discovery daemon |
| passingOnly | If you set this `true`, only healthy nodes will be discovered |
| payload     | Service record for Consul |
| replaceExistingChecks| Missing healthchecks from the request will be deleted from the agent. Using this parameter allows to idempotently register a service and its checks without having to manually deregister checks.|
| insecureSkipVerify| Controls whether a client verifies the server's certificate chain and host name. If insecureSkipVerify is true, TLS accepts any certificate presented by the server and any host name in that certificate. |

Please note that you cannot set `plugin` and `path` simultaneously. Olric chooses `path` if you set both of them.  

## Contributions

Please don't hesitate to fork the project and send a pull request or just e-mail me to ask questions and share ideas.

## License

The Apache License, Version 2.0 - see LICENSE for more details.
