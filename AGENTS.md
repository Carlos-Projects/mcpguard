# Agent Operating Map

Este archivo es la puerta de entrada para Codex, OpenCode, Claude, Cursor u otro agente. Debe mantenerse corto.

## Read Order

1. `HARNESS.yml`
2. `progress/current.md`
3. `docs/architecture.md`
4. `docs/verification.md`
5. Solo despues, leer codigo especifico de la tarea.

## Agent Adapters

- Codex: usar este archivo como mapa de contexto y actualizar `progress/current.md`.
- OpenCode: incluir `AGENTS.md`, `HARNESS.yml` y `progress/current.md` en `opencode.jsonc`.
- Claude/Cursor: leer el mismo orden y no crear memoria paralela salvo que se sincronice aqui.

## Rules

- No leer el repo completo al inicio.
- No modificar secretos, credenciales ni archivos `.env` salvo instruccion explicita.
- Antes de editar, identificar comando de verificacion minimo.
- Cada cambio debe actualizar `progress/current.md`.
- Hallazgos de seguridad van en `progress/security-findings.md`.
- Decisiones de arquitectura van en `docs/decisions.md`.
- Si falta contexto, buscar primero en archivos harness antes que en chat.
- Si una herramienta tiene memoria propia, registrar solo punteros/resumenes y mantener este harness como fuente de verdad operativa.

## Done Means

- Tests/checks relevantes ejecutados o razon documentada.
- Riesgos y secretos revisados.
- Cambios resumidos en `progress/current.md`.
- Siguiente paso claro.
