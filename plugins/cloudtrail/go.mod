module example.com/cloudtrail

go 1.15

replace github.com/mstemm/libsinsp-plugin-sdk-go => ../../../libsinsp-plugin-sdk-go

require github.com/aws/aws-sdk-go v1.36.23

require (
	github.com/mstemm/libsinsp-plugin-sdk-go v0.0.2-plugin-system-api-additions
	github.com/valyala/fastjson v1.6.3
)
