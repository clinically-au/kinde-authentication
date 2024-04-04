To regenerate the API:

```bash
sudo openapi-generator-cli generate -i https://kinde.com/api/kinde-mgmt-api-specs.yaml -g csharp -o Kinde.Sdk --package-name=Kinde.Api -c config.yaml --library=httpclient --additional-properties=targetFramework=net8.0,packageVersion=1.2.5,sourceFolder=
```