# 📥 Outside Challenges

A drop zone for CTFs authored **outside** this repo — boxes handed to me from other
people or tools that I want to solve and track alongside my own lab.

**Authorized targets: only boxes I was explicitly given to solve.** Treat everything
in here as untrusted code — see the safety note below.

## How to load a challenge

Each challenge lives in its own subfolder here, e.g.:

```
ctfs/outside-challenges/
  <challenge-name>/
    README.md            # the mission / how to run it
    docker-compose.yml   # or Dockerfile, or a plain script
    ...                  # whatever the author shipped
```

To add one:

1. Drop the challenge files into a new subfolder: `ctfs/outside-challenges/<name>/`.
   - If I received a single archive (`.zip`/`.tar.gz`), unpack it here:
     ```bash
     mkdir -p ~/security-lab/ctfs/outside-challenges/<name>
     tar -xzf ~/Downloads/<file>.tar.gz  -C ~/security-lab/ctfs/outside-challenges/<name>
     # or:  unzip ~/Downloads/<file>.zip -d ~/security-lab/ctfs/outside-challenges/<name>
     ```
2. Read the challenge's own `README` for how to start it and what the objective is.
3. Run it (most will be Docker):
   ```bash
   cd ~/security-lab/ctfs/outside-challenges/<name>
   docker compose up -d --build      # if it ships a compose file
   docker compose logs -f
   docker compose down               # tear down when finished
   ```
4. **Pick a host port that isn't already taken** by my own boxes (8081–8086 are in
   use). If the challenge's compose file collides, remap the left-hand side of the
   `ports:` mapping to something free (e.g. `8090:...`).

## ⚠️ Safety — this is code from outside my repo

- **Read before you run.** Skim the `Dockerfile`/compose/source so you know what it
  does before starting it. Don't run install scripts blindly.
- **Keep it contained.** Docker is the sandbox — prefer boxes that ship a container.
  Don't run an outside challenge's setup directly on the host if you can avoid it.
- **No secrets on the box.** Don't point a challenge at real credentials, keys, or
  anything from `~/.ssh`, `~/.aws`, etc.
- **Local only.** These are practice targets — bind them to `localhost`, and only
  attack the box you were given.

## Tracking

When I finish one, note it here so I can see my outside-challenge history:

| # | Name | Source type | Focus | Status |
|---|------|-------------|-------|--------|
| — | _(none yet)_ | — | — | — |
