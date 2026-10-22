/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Base URL of the analyzer API. Empty/unset means "use the dev-server proxy". */
  readonly VITE_API_BASE_URL?: string;
}
