/// <reference types="vite/client" />
/// <reference types="vite-plugin-pwa/client" />

interface ImportMetaEnv {
  readonly VITE_DEVICE_LEASE_PUBLIC_JWK: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
