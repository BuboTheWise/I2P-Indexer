# Goal
Set up the cthugha Hermes profile so it can execute kanban tasks on this board.

## Context
This is a multi-profile project running two profiles: **default** (working directory) and **cthugha** (to share workload). The cthugha profile likely needs to be created or configured with kanban access before it can take on tasks.

## Steps
1. Verify if cthugha profile exists at ~/.hermes/profiles/cthugha/. If not, create it via `hermes profile create cthugha`.
2. Ensure the profile has a working model and provider configured (check config.yaml).
3. Enable kanban toolset for cthugha so it can claim tasks: verify `toolsets` includes `kanban`.
4. Test board access: `hermes --profile cthugha kanban --board i2p-indexer list` should return task list.
5. Verify the dispatcher can spawn a worker with this profile name.

## Definition of Done
- [ ] cthugha profile exists, has model/provider configured, and can reach an LLM backend
- [ ] Kanban toolset is active (profile can use kanban_claim, kanban_complete, etc.)
- [ ] Board visibility confirmed: task list loads for this board
- [ ] At least one test command run successfully as cthugha profile

## Notes
- Use the default profile's config.yaml as a template if starting from scratch
- The i2p-indexer board already exists (created by the orchestrator session)
