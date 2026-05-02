---
description: Subagents use the parent chat model (not a fixed Composer model)
alwaysApply: true
---

# Subagent model inheritance

When spawning subagents via the Task tool:

- **Do not** pass a `model` argument unless the user explicitly asks for a specific model for that run. Omitting `model` uses the same model as the parent agent (see Cursor Task tool behavior).

- **Do not** default to `composer-2` or other fixed model slugs for subagents.

When adding or editing custom subagent files under `.cursor/agents/` (or user `~/.cursor/agents/`):

- Set **`model: inherit`** in YAML frontmatter (this is also Cursor’s documented default; keep it explicit so overrides are visible in review).

Built-in subagents (`explore`, `bash`, `browser`) follow Cursor’s built-in model choices and are not overridden by this rule.

If subagents still always use Composer despite the above, check Cursor account/plan docs: some legacy request-based plans route subagents to Composer unless Max Mode / usage-based behavior applies.
