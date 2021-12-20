Configuration file format

```json
{
        "mongo": {
                "uri": "mongosrv",
        },
        "server": {
        	"jwt": {
			"issuer": "issuer",
			"IssuerRefresh": "issuer-refresh"
		}
        },
        "orchestration": {
                "url": "https:url"
        },
        "keyLocation": {
                "private": "keys/api.rsa",
                "public": "keys/api.rsa.pub"
        }
}
```
