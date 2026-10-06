# Preserve the historical blue addresses when the optional legacy slot is
# enabled. Production has already deleted that container and sets count = 0.
moved {
  from = yandex_serverless_container.backend
  to   = yandex_serverless_container.backend[0]
}

moved {
  from = yandex_serverless_container_iam_binding.gateway_backend_invoker
  to   = yandex_serverless_container_iam_binding.gateway_backend_invoker[0]
}
