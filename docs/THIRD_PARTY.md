# Third-party notices and implementation references

The Button wrapper is adapted from shadcn/ui's Base UI registry (MIT):
https://github.com/shadcn-ui/ui/blob/main/apps/v4/registry/bases/base/ui/button.tsx
Copyright (c) 2023 shadcn. The MIT permission and disclaimer in the root LICENSE
apply to this adaptation; dependencies retain their own published licenses.

The dialog uses Base UI's Dialog primitives directly. Studio styles are authored
for Coffre, not copied from a third-party application.

Primary implementation references:
- https://developers.cloudflare.com/workers/framework-guides/web-apps/tanstack-start/
- https://tanstack.com/start/latest/docs/framework/react/guide/server-routes
- https://developers.cloudflare.com/d1/worker-api/d1-database/
- https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/rpc/
- https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/
- https://www.scaleway.com/en/developers/api/key-manager/keys
- https://github.com/scaleway/scaleway-sdk-go/blob/main/api/key_manager/v1alpha1/key_manager_sdk.go

Package versions are exact in package.json. The dependency lock must be committed
and reviewed before release. No dependency's install script is required here.
