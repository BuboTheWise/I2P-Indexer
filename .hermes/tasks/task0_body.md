# Goal
Set up the senior dev agent Hermes profile so it can execute kanban tasks on this board.

## Context
This is a multi-profile project running two profiles: **default** (working directory) and **senior dev agent** (to share workload). The senior dev agent profile likely needs to be created or configured with kanban access before it can take on tasks.

## Steps
1. Verify if senior dev agent profile exists at ~/.hermes/profiles/senior dev agent/. If not, create it via `hermes profile create senior dev agent`.
2. Ensure the profile has a working model and provider configured (check config.yaml).
3. Enable kanban toolset for senior dev agent so it can claim tasks: verify `toolsets` includes `kanban`.
4. Test board access: `hermes --profile senior dev agent kanban --board i2p-indexer list` should return task list.
5. Verify the dispatcher can spawn a worker with this profile name.

## Definition of Done
- [ ] senior dev agent profile exists, has model/provider configured, and can reach an LLM backend
- [ ] Kanban toolset is active (profile can use kanban_claim, kanban_complete, etc.)
- [ ] Board visibility confirmed: task list loads for this board
- [ ] At least one test command run successfully as senior dev agent profile

## Notes
- Use the default profile's config.yaml as a template if starting from scratch
- The i2p-indexer board already exists (created by the orchestrator session)
