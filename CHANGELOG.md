# Changelog

## 2026-05-31

- chore: redeploy to regenerate the service manifest without the retired
  per-service rate-limit `CiliumEnvoyConfig`. The CEC emitted an invalid Envoy
  listener that NACKed the cluster's State-of-the-World LDS batch, freezing xDS
  and stalling endpoint propagation on deploys. The source was removed upstream
  (DevopsZon.API#861); this redeploy clears the stale CEC from this service's
  committed GitOps manifest so an `argocd sync` can no longer recreate it.
